"""Corrélation multi-sources - Jointure des flux CICFlowMeter (déjà classifiés et
enrichis d'anomalies par ml_preprocessing.py) avec les alertes Suricata, puis calcul
d'un niveau de risque final qui fusionne les trois sources en un seul verdict.

Ce module ne contient ni nettoyage ni modèle ML : il combine des résultats déjà
produits ailleurs (classification, détection d'anomalies, alertes Suricata), d'où sa
séparation de ml_preprocessing.py.

Produit deux fichiers à partir du CSV déjà classifié/enrichi d'anomalies
(<nom>_predicted.csv, voir ml_preprocessing.py) :
  - <nom>_unified.csv : <nom>_predicted.csv enrichi des colonnes "suricata_alerte",
    "suricata_signature" et "suricata_severite" (via
    unify_predictions_with_suricata_alerts), à partir d'une jointure par 5-tuple
    réseau (IP source, IP destination, port source, port destination, protocole)
    avec les alertes du fichier eve.json de Suricata. Pas de jointure temporelle.
  - <nom>_final.csv   : <nom>_unified.csv enrichi des colonnes "niveau_risque"
    (CRITIQUE/ELEVE/MOYEN/NORMAL), "raison", et des trois signaux booléens
    ("signal_classifieur", "signal_anomalie", "signal_suricata", valeurs "oui"/"non")
    ayant servi à ce verdict (via compute_risk_levels) — les dashboards les lisent
    directement plutôt que de reproduire cette logique.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Tuple

import numpy as np
import pandas as pd

from logger import setup_logging
from utils import file_exists

logger = setup_logging(__name__)

# Correspondance protocole texte (Suricata, champ "proto") <-> protocole entier
# (CICFlowMeter, colonne "Protocol") : nécessaire pour que la clé de jointure
# 5-tuple soit comparable des deux côtés.
PROTO_NAME_TO_INT = {"TCP": 6, "UDP": 17, "ICMP": 1}
PROTO_INT_TO_NAME = {number: name for name, number in PROTO_NAME_TO_INT.items()}


def _protocol_to_text(protocols: pd.Series) -> pd.Series:
    """Convertit le numéro de protocole (6, 17, 1...) en texte (TCP, UDP, ICMP) pour le
    CSV final. Un numéro hors TCP/UDP/ICMP est écrit "Autre (n)"."""

    def _label(value: Any) -> str:
        if pd.isna(value):
            return ""
        number = int(value)
        return PROTO_INT_TO_NAME.get(number, f"Autre ({number})")

    return protocols.map(_label)


# Seuil de confiance du classifieur en-dessous duquel une classification non-bénigne
# n'est PAS comptée comme signal de risque (prédiction jugée trop peu fiable). Isolé
# en constante pour pouvoir l'ajuster facilement  selon ce qui est
# observé sur des PCAP réels, sans devoir modifier la logique de compute_risk_levels.
RISK_CLASSIFIER_CONFIDENCE_THRESHOLD = 0.5

# Ordre d'affichage/de tri des niveaux de risque, du plus au moins grave.
RISK_LEVEL_ORDER = ["CRITIQUE", "ELEVE", "MOYEN", "NORMAL"]


def _cle_5tuple(ip1: Any, port1: Any, ip2: Any, port2: Any, proto: Any) -> Tuple[Tuple[str, int], Tuple[str, int], int]:
    
    cote_a = (str(ip1), int(port1))
    cote_b = (str(ip2), int(port2))
    return tuple(sorted([cote_a, cote_b])) + (int(proto),)


def _parse_suricata_alerts_by_key(eve_json_path: str) -> Tuple[Dict[Tuple, Dict[str, Any]], int, int]:
    """Lit eve.json en streaming (JSON Lines, une passe) et agrège les alertes par clé
    5-tuple. Ne garde que les événements event_type == "alert". Pour chaque clé,
    conserve la signature de l'alerte la plus grave (severity la plus basse
    numériquement — dans Suricata, severity=1 est la plus grave, 3 la moins grave).

    Returns:
        (alerts_by_key, total_alerts_parsed, alerts_skipped_unknown_proto)
    """
    alerts_by_key: Dict[Tuple, Dict[str, Any]] = {}
    total_alerts_parsed = 0
    alerts_skipped_unknown_proto = 0

    with open(eve_json_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                logger.debug(f"Erreur JSON à la ligne {line_num} de eve.json, ligne ignorée")
                continue

            if event.get("event_type") != "alert":
                continue

            total_alerts_parsed += 1

            proto_raw = event.get("proto", "")
            proto_int = PROTO_NAME_TO_INT.get(str(proto_raw).upper())
            if proto_int is None:
                alerts_skipped_unknown_proto += 1
                logger.debug(f"Protocole Suricata non géré ignoré: {proto_raw!r} (ligne {line_num})")
                continue

            src_ip = event.get("src_ip")
            dest_ip = event.get("dest_ip")
            if not src_ip or not dest_ip:
                continue

            # Certains protocoles (ICMP notamment) n'ont pas de ports dans eve.json :
            # 0 par défaut, pour que la conversion en entier ne lève jamais d'exception.
            src_port = event.get("src_port") or 0
            dest_port = event.get("dest_port") or 0

            alert = event.get("alert", {}) or {}
            signature = alert.get("signature", "Unknown")
            severity = alert.get("severity")

            key = _cle_5tuple(src_ip, src_port, dest_ip, dest_port, proto_int)

            existing = alerts_by_key.get(key)
            if existing is None or (
                severity is not None
                and (existing["severite"] is None or severity < existing["severite"])
            ):
                alerts_by_key[key] = {"signature": signature, "severite": severity}

    logger.info(f"eve.json: {total_alerts_parsed} alertes parsées, {len(alerts_by_key)} clés 5-tuple uniques")
    if alerts_skipped_unknown_proto:
        logger.warning(
            f"{alerts_skipped_unknown_proto} alertes ignorées (protocole non géré: ni TCP, ni UDP, ni ICMP)"
        )

    return alerts_by_key, total_alerts_parsed, alerts_skipped_unknown_proto


def count_eve_event_types(eve_json_path: str) -> Dict[str, int]:
    """Lit eve.json en streaming (une passe) et compte les occurrences de chaque
    event_type, tous types confondus (alert, flow, dns, http, tls, ssh, fileinfo,
    stats, ...) — contrairement à _parse_suricata_alerts_by_key qui ne garde que
    les événements "alert" pour la jointure, cette fonction sert uniquement à donner
    une vue d'ensemble du trafic vu par Suricata dans le dashboard.

    Returns:
        Dictionnaire {event_type: nombre d'occurrences}, vide si le fichier est
        introuvable.
    """
    counts: Dict[str, int] = {}
    if not file_exists(eve_json_path):
        return counts

    with open(eve_json_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            event_type = event.get("event_type")
            if event_type:
                counts[event_type] = counts.get(event_type, 0) + 1

    return counts


def unify_predictions_with_suricata_alerts(
    predicted_csv_path: str,
    eve_json_path: str,
    output_folder: str,
) -> Dict[str, Any]:
    """Enrichit le CSV classifié/anomalies (predicted_csv_path) avec les alertes
    Suricata correspondantes, jointes par clé 5-tuple normalisée (IP source, IP
    destination, port source, port destination, protocole — indépendante du sens du
    flux). Pas de jointure temporelle : seule la correspondance 5-tuple compte.

    Ajoute trois colonnes au CSV, sans modifier ni réordonner les lignes existantes :
      - suricata_alerte     : "oui" / "non"
      - suricata_signature  : signature de l'alerte la plus grave pour ce flux (None si aucune)
      - suricata_severite   : sévérité de cette alerte, 1 = la plus grave (None si aucune)

    Args:
        predicted_csv_path: Chemin du CSV déjà classifié (et/ou enrichi d'anomalies)
        eve_json_path: Chemin du fichier eve.json généré par Suricata
        output_folder: Dossier où écrire le fichier unifié

    Returns:
        Dictionnaire avec statut, chemin du fichier produit, et statistiques de jointure
    """
    try:
        if not file_exists(predicted_csv_path):
            return {
                "status": "error",
                "message": f"[ERREUR] CSV prédit non trouvé: {predicted_csv_path}",
            }

        if not file_exists(eve_json_path):
            return {
                "status": "error",
                "message": f"[ERREUR] Fichier eve.json non trouvé: {eve_json_path}",
            }

        df = pd.read_csv(predicted_csv_path)
        required_cols = {"Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol"}
        missing_cols = required_cols - set(df.columns)
        if missing_cols:
            return {
                "status": "error",
                "message": f"[ERREUR] Colonnes manquantes dans le CSV prédit pour la jointure: {sorted(missing_cols)}",
            }

        alerts_by_key, total_alerts_parsed, alerts_skipped = _parse_suricata_alerts_by_key(eve_json_path)

        # Ports/protocole en entier des deux côtés de la jointure : un port en string
        # ("80") ne correspondrait jamais à un port en int (80), même valeur logique.
        src_ports = df["Src Port"].fillna(0).astype(int)
        dst_ports = df["Dst Port"].fillna(0).astype(int)
        protocols = df["Protocol"].fillna(0).astype(int)

        alerte_flags = []
        signatures = []
        severites = []

        for src_ip, dst_ip, src_port, dst_port, proto in zip(
            df["Src IP"], df["Dst IP"], src_ports, dst_ports, protocols
        ):
            key = _cle_5tuple(src_ip, src_port, dst_ip, dst_port, proto)
            match = alerts_by_key.get(key)
            if match is not None:
                alerte_flags.append("oui")
                signatures.append(match["signature"])
                severites.append(match["severite"])
            else:
                alerte_flags.append("non")
                signatures.append(None)
                severites.append(None)

        df["suricata_alerte"] = alerte_flags
        df["suricata_signature"] = signatures
        df["suricata_severite"] = severites

        Path(output_folder).mkdir(parents=True, exist_ok=True)
        base_name = Path(predicted_csv_path).stem
        if base_name.endswith("_predicted"):
            base_name = base_name[: -len("_predicted")]
        unified_csv_path = os.path.join(output_folder, f"{base_name}_unified.csv")
        df.to_csv(unified_csv_path, index=False)

        total_rows = len(df)
        matched_count = alerte_flags.count("oui")

        logger.info(
            f"Jointure Suricata terminée: {matched_count}/{total_rows} flux enrichis "
            f"({total_alerts_parsed} alertes parsées, {len(alerts_by_key)} clés uniques)"
        )

        if matched_count == 0 and len(alerts_by_key) > 0:
            # Diagnostic : la cause la plus fréquente d'une jointure à 0 résultat alors
            # que des alertes existent est un décalage de type entre les deux côtés de
            # la clé (protocole texte vs entier, port string vs int).
            sample_csv_keys = [
                _cle_5tuple(s, sp, d, dp, p)
                for s, d, sp, dp, p in list(zip(
                    df["Src IP"].head(3), df["Dst IP"].head(3),
                    src_ports.head(3), dst_ports.head(3), protocols.head(3),
                ))
            ]
            sample_alert_keys = list(alerts_by_key.keys())[:3]
            logger.warning(
                "0 flux enrichis alors que des alertes existent — vérifier le format "
                "des clés des deux côtés de la jointure (protocole/ports)."
            )
            logger.warning(f"Exemples de clés côté CSV: {sample_csv_keys}")
            logger.warning(f"Exemples de clés côté Suricata: {sample_alert_keys}")

        logger.info(f"CSV unifié sauvegardé: {unified_csv_path}")

        return {
            "status": "success",
            "message": "[OK] Unification avec les alertes Suricata complétée avec succès !",
            "unified_csv": unified_csv_path,
            "total_rows": total_rows,
            "alerts_parsed": total_alerts_parsed,
            "unique_alert_keys": len(alerts_by_key),
            "alerts_skipped_unknown_proto": alerts_skipped,
            "matched_flows": matched_count,
            "unmatched_flows": total_rows - matched_count,
        }

    except Exception as e:
        logger.error(f"Erreur lors de l'unification avec Suricata: {e}")
        return {
            "status": "error",
            "message": f"[ERREUR] Erreur: {str(e)}",
        }


def compute_risk_levels(unified_csv_path: str, output_folder: str) -> Dict[str, Any]:
    
    try:
        if not file_exists(unified_csv_path):
            return {
                "status": "error",
                "message": f"[ERREUR] CSV unifié non trouvé: {unified_csv_path}",
            }

        df = pd.read_csv(unified_csv_path)
        required_cols = {
            "classification", "score_confiance", "anomalie", "score_anomalie",
            "suricata_alerte", "suricata_severite",
        }
        missing_cols = required_cols - set(df.columns)
        if missing_cols:
            return {
                "status": "error",
                "message": f"[ERREUR] Colonnes manquantes dans le CSV unifié: {sorted(missing_cols)}",
            }

        # Valeurs manquantes traitées comme "pas d'alerte" pour le signal concerné,
        # plutôt que de faire planter la comparaison numérique ou propager un NaN.
        score_confiance = df["score_confiance"].fillna(0.0)
        signal_classifieur = (df["classification"] != "Benign") & (
            score_confiance >= RISK_CLASSIFIER_CONFIDENCE_THRESHOLD
        )
        signal_anomalie = (df["anomalie"] == "anormal") & df["score_anomalie"].notna()
        signal_suricata = df["suricata_alerte"].eq("oui") & df["suricata_severite"].isin([1, 2])
        nb_sources = (
            signal_classifieur.astype(int) + signal_anomalie.astype(int) + signal_suricata.astype(int)
        )
        est_critique = nb_sources >= 2
        est_eleve = (nb_sources == 1) & signal_classifieur
        est_moyen = (nb_sources == 1) & (signal_anomalie | signal_suricata)

        niveau_risque = np.select(
            [est_critique, est_eleve, est_moyen],
            ["CRITIQUE", "ELEVE", "MOYEN"],
            default="NORMAL",
        )

        # Construction de la colonne "raison" : accès ligne par ligne nécessaire pour
        # composer une phrase lisible, mais un passage par zip() reste rapide même sur
        # des CSV de plusieurs centaines de milliers de lignes (cf. jointure Suricata).
        raisons = []
        for sig_suri, severite, sig_clf, sig_ano, signature, classe, conf, score_ano in zip(
            signal_suricata, df["suricata_severite"], signal_classifieur, signal_anomalie,
            df["suricata_signature"], df["classification"], score_confiance, df["score_anomalie"],
        ):
            parts = []
            if sig_suri:
                parts.append(f"Suricata sévérité {int(severite)}: {signature}")
            if sig_clf:
                parts.append(f"Classifieur: {classe} ({conf:.2f})")
            if sig_ano:
                parts.append(f"Anomalie (score {score_ano:.2f})")
            raisons.append(" + ".join(parts) if parts else "Aucun signal détecté")

        df["niveau_risque"] = niveau_risque
        df["raison"] = raisons

        # Signaux sauvegardés en colonnes ("oui"/"non", même convention que suricata_alerte)
        # plutôt que recalculés ailleurs (ex: dashboard) : une seule source de vérité pour
        # la logique de risque, aucun risque de divergence si le seuil est ajusté ici.
        # "signal_suricata" vaut "oui" dès que Suricata a contribué (sévérité 1 ou 2) ;
        # la sévérité elle-même reste disponible dans la colonne "suricata_severite".
        df["signal_classifieur"] = np.where(signal_classifieur, "oui", "non")
        df["signal_anomalie"] = np.where(signal_anomalie, "oui", "non")
        df["signal_suricata"] = np.where(signal_suricata, "oui", "non")

        # Le protocole reste numérique jusqu'ici (la jointure Suricata en a besoin) ; le CSV
        # final l'écrit en texte pour qu'il soit lisible tel quel dans le dashboard.
        if "Protocol" in df.columns:
            df["Protocol"] = _protocol_to_text(df["Protocol"])

        Path(output_folder).mkdir(parents=True, exist_ok=True)
        base_name = Path(unified_csv_path).stem
        if base_name.endswith("_unified"):
            base_name = base_name[: -len("_unified")]
        final_csv_path = os.path.join(output_folder, f"{base_name}_final.csv")
        df.to_csv(final_csv_path, index=False)

        total_rows = len(df)
        counts = df["niveau_risque"].value_counts().to_dict()
        distribution = {level: int(counts.get(level, 0)) for level in RISK_LEVEL_ORDER}

        logger.info(f"Niveau de risque calculé sur {total_rows} flux: {distribution}")
        logger.info(f"CSV final sauvegardé: {final_csv_path}")

        return {
            "status": "success",
            "message": "[OK] Calcul du niveau de risque complété avec succès !",
            "final_csv": final_csv_path,
            "total_rows": total_rows,
            "distribution": distribution,
            "critique_count": distribution["CRITIQUE"],
            "eleve_count": distribution["ELEVE"],
            "moyen_count": distribution["MOYEN"],
            "normal_count": distribution["NORMAL"],
        }

    except Exception as e:
        logger.error(f"Erreur lors du calcul du niveau de risque: {e}")
        return {
            "status": "error",
            "message": f"[ERREUR] Erreur: {str(e)}",
        }


def correlate_with_suricata(
    predicted_csv_path: str,
    eve_json_path: str,
    output_folder: str,
) -> Dict[str, Any]:
    """Phase "Jointure" complète du pipeline : jointure avec les alertes Suricata
    (unify_predictions_with_suricata_alerts) puis, si elle réussit, calcul du niveau
    de risque final (compute_risk_levels) sur son résultat. Les deux sous-étapes sont
    volontairement fusionnées ici car la seconde n'a aucune utilité sans la première.

    Args:
        predicted_csv_path: Chemin du CSV déjà classifié et enrichi d'anomalies
        eve_json_path: Chemin du fichier eve.json généré par Suricata
        output_folder: Dossier où écrire les fichiers unifié et final

    Returns:
        Dictionnaire avec le résultat de chaque sous-étape ("unification_result",
        "risk_result") et un statut global ("success" seulement si les deux réussissent)
    """
    unification_result = unify_predictions_with_suricata_alerts(predicted_csv_path, eve_json_path, output_folder)
    if unification_result.get("status") != "success":
        return {
            "status": "error",
            "message": unification_result.get("message", "[ERREUR] Échec de la jointure avec les alertes Suricata."),
            "unification_result": unification_result,
            "risk_result": None,
        }

    risk_result = compute_risk_levels(unification_result["unified_csv"], output_folder)
    if risk_result.get("status") != "success":
        return {
            "status": "error",
            "message": risk_result.get("message", "[ERREUR] Échec du calcul du niveau de risque."),
            "unification_result": unification_result,
            "risk_result": risk_result,
        }

    return {
        "status": "success",
        "message": "[OK] Jointure Suricata et calcul du niveau de risque complétés avec succès !",
        "unification_result": unification_result,
        "risk_result": risk_result,
        "unified_csv": unification_result["unified_csv"],
        "final_csv": risk_result["final_csv"],
    }


# Colonnes lues depuis le CSV final pour le dashboard de corrélation (voir
# dashboards.py) : usecols pour éviter de charger les 70+ colonnes de features
# d'un fichier qui peut faire plusieurs centaines de milliers de lignes.
CORRELATION_DASHBOARD_COLUMNS = [
    "Timestamp", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol",
    "classification", "score_confiance", "anomalie", "score_anomalie",
    "suricata_alerte", "suricata_signature", "suricata_severite",
    "niveau_risque", "raison",
    "signal_classifieur", "signal_anomalie", "signal_suricata",
]


def load_correlation_dataframe(final_csv_path: str) -> pd.DataFrame:
    """Charge le CSV final (produit par correlate_with_suricata) pour le dashboard de
    corrélation, en ne lisant que les colonnes nécessaires à l'analyse multi-sources
    (pas les 70+ colonnes de features CICFlowMeter).

    Args:
        final_csv_path: Chemin du CSV produit par compute_risk_levels

    Returns:
        DataFrame limité aux colonnes de CORRELATION_DASHBOARD_COLUMNS présentes
    """
    available_cols = pd.read_csv(final_csv_path, nrows=0).columns
    usecols = [c for c in CORRELATION_DASHBOARD_COLUMNS if c in available_cols]
    return pd.read_csv(final_csv_path, usecols=usecols)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 4:
        print("Usage: python risk_correlation.py <csv_predicted> <dossier_sortie> <eve_json> [--unify-only|--risk-only]")
        sys.exit(1)

    predicted_csv_arg, output_folder_arg, eve_json_arg = sys.argv[1], sys.argv[2], sys.argv[3]

    if "--unify-only" in sys.argv:
        result = unify_predictions_with_suricata_alerts(predicted_csv_arg, eve_json_arg, output_folder_arg)
    elif "--risk-only" in sys.argv:
        # Ici, <csv_predicted> doit en réalité être le chemin d'un CSV déjà unifié.
        result = compute_risk_levels(predicted_csv_arg, output_folder_arg)
    else:
        result = correlate_with_suricata(predicted_csv_arg, eve_json_arg, output_folder_arg)
    print(result)
