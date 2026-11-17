"""Prétraitement ML - Nettoyage du CSV CICFlowMeter, préparation d'une copie prête
pour l'inférence, classification avec le modèle entraîné, et détection d'anomalies
avec un modèle non-supervisé (Isolation Forest).

La jointure avec les alertes Suricata et le calcul du niveau de risque final vivent
dans risk_correlation.py (corrélation multi-sources, pas du prétraitement ML).

Produit jusqu'à trois fichiers à partir d'un seul CSV CICFlowMeter :
  - <nom>_clean.csv     : mêmes colonnes que la sortie CICFlowMeter (IP, ports,
    timestamp, toutes les features), débarrassé des lignes NaN/inf, index remis
    à plat.
  - <nom>_ml_ready.csv  : copie de <nom>_clean.csv, colonnes renommées selon la
    convention d'entraînement (RENAME_MAP), colonnes non-features supprimées,
    tout en float32. C'est ce fichier qui est donné aux modèles pour l'inférence.
  - <nom>_predicted.csv : <nom>_clean.csv enrichi des colonnes "classification" et
    "score_confiance" (classifieur, via classify_cicflowmeter_csv), puis, une fois
    ce fichier disponible, enrichi à nouveau des colonnes "anomalie" et
    "score_anomalie" (détecteur d'anomalies, via detect_anomalies_cicflowmeter_csv).
    Le fichier final contient donc les résultats des deux modèles ensemble.

Ces trois fonctions nettoient toutes le même CSV CICFlowMeter (via _clean_and_prepare) :
ce nettoyage n'est donc effectué qu'une seule fois par fichier, son résultat étant mis
en cache pour les appels suivants (voir _clean_and_prepare) plutôt que d'être relu et
recalculé à chaque étape.
"""

import os
from pathlib import Path
from typing import Any, Dict, Tuple

import joblib
import numpy as np
import pandas as pd

from config import ANOMALY_MODEL_PATH, CLASSIFIER_MODEL_PATH
from logger import setup_logging
from utils import file_exists

logger = setup_logging(__name__)

# Cache du dernier nettoyage effectué par _clean_and_prepare, pour éviter de relire et
# renettoyer le même CSV CICFlowMeter à chaque étape du pipeline (prétraitement,
# classification, détection d'anomalies appellent toutes les trois cette fonction sur
# le même fichier). Une seule entrée : le pipeline ne traite qu'un PCAP à la fois, et
# ne revient jamais sur un fichier précédent une fois passé à l'étape suivante.
_last_clean_and_prepare_cache: Dict[str, Tuple[pd.DataFrame, pd.DataFrame, int, int]] = {}

# Colonnes texte/identifiants à préserver telles quelles pendant le nettoyage NaN/inf :
# elles ne doivent jamais passer par pd.to_numeric ni participer au masque de filtrage.
TEXT_COLUMNS = {"Flow ID", "Src IP", "Dst IP", "Timestamp", "Label"}

# CICFlowMeter (nommage "verbeux") -> nommage abrégé attendu par les modèles (convention du
# jeu d'entraînement CICIDS2018, ex: "Tot Fwd Pkts")
RENAME_MAP = {
    "Total Fwd Packet": "Tot Fwd Pkts",
    "Total Bwd packets": "Tot Bwd Pkts",
    "Total Length of Fwd Packet": "TotLen Fwd Pkts",
    "Total Length of Bwd Packet": "TotLen Bwd Pkts",
    "Fwd Packet Length Max": "Fwd Pkt Len Max",
    "Fwd Packet Length Min": "Fwd Pkt Len Min",
    "Fwd Packet Length Mean": "Fwd Pkt Len Mean",
    "Fwd Packet Length Std": "Fwd Pkt Len Std",
    "Bwd Packet Length Max": "Bwd Pkt Len Max",
    "Bwd Packet Length Min": "Bwd Pkt Len Min",
    "Bwd Packet Length Mean": "Bwd Pkt Len Mean",
    "Bwd Packet Length Std": "Bwd Pkt Len Std",
    "Flow Bytes/s": "Flow Byts/s",
    "Flow Packets/s": "Flow Pkts/s",
    "Fwd IAT Total": "Fwd IAT Tot",
    "Bwd IAT Total": "Bwd IAT Tot",
    "Fwd Header Length": "Fwd Header Len",
    "Bwd Header Length": "Bwd Header Len",
    "Packet Length Min": "Pkt Len Min",
    "Packet Length Max": "Pkt Len Max",
    "Packet Length Mean": "Pkt Len Mean",
    "Packet Length Std": "Pkt Len Std",
    "Packet Length Variance": "Pkt Len Var",
    "FIN Flag Count": "FIN Flag Cnt",
    "SYN Flag Count": "SYN Flag Cnt",
    "RST Flag Count": "RST Flag Cnt",
    "PSH Flag Count": "PSH Flag Cnt",
    "ACK Flag Count": "ACK Flag Cnt",
    "URG Flag Count": "URG Flag Cnt",
    "CWR Flag Count": "CWE Flag Count",
    "ECE Flag Count": "ECE Flag Cnt",
    "Average Packet Size": "Pkt Size Avg",
    "Fwd Segment Size Avg": "Fwd Seg Size Avg",
    "Bwd Segment Size Avg": "Bwd Seg Size Avg",
    "Fwd Bytes/Bulk Avg": "Fwd Byts/b Avg",
    "Fwd Packet/Bulk Avg": "Fwd Pkts/b Avg",
    "Fwd Bulk Rate Avg": "Fwd Blk Rate Avg",
    "Bwd Bytes/Bulk Avg": "Bwd Byts/b Avg",
    "Bwd Packet/Bulk Avg": "Bwd Pkts/b Avg",
    "Bwd Bulk Rate Avg": "Bwd Blk Rate Avg",
    "Subflow Fwd Packets": "Subflow Fwd Pkts",
    "Subflow Fwd Bytes": "Subflow Fwd Byts",
    "Subflow Bwd Packets": "Subflow Bwd Pkts",
    "Subflow Bwd Bytes": "Subflow Bwd Byts",
    "FWD Init Win Bytes": "Init Fwd Win Byts",
    "Bwd Init Win Bytes": "Init Bwd Win Byts",
    "Fwd Packets/s": "Fwd Pkts/s",
    "Bwd Packets/s": "Bwd Pkts/s",
}

# Colonnes non-features retirées de la copie ML (identifiants/métadonnées, et colonnes
# bulk/rate non utilisées à l'entraînement) - noms donnés APRÈS application de RENAME_MAP
DROP_COLUMNS = [
    "Dst IP", "Flow ID", "Src IP", "Src Port", "Timestamp", "Label",
    "Bwd Blk Rate Avg", "Bwd Byts/b Avg", "Bwd PSH Flags", "Bwd Pkts/b Avg", "Bwd URG Flags",
    "Fwd Blk Rate Avg", "Fwd Byts/b Avg", "Fwd Pkts/b Avg",
]


def _clean_and_prepare(csv_path: str) -> Tuple[pd.DataFrame, pd.DataFrame, int, int]:
    
    cached = _last_clean_and_prepare_cache.get(csv_path)
    if cached is not None:
        cached_df_clean, cached_df_copie, rows_before, rows_after = cached
        return cached_df_clean.copy(), cached_df_copie.copy(), rows_before, rows_after

    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
    rows_before = len(df)

    text_cols_present = [c for c in TEXT_COLUMNS if c in df.columns]
    numeric_cols = [c for c in df.columns if c not in text_cols_present]

    numeric_view = df[numeric_cols].apply(pd.to_numeric, errors="coerce")
    numeric_view = numeric_view.replace([np.inf, -np.inf], np.nan)
    valid_rows_mask = ~numeric_view.isna().any(axis=1)

    df_clean = df[valid_rows_mask].reset_index(drop=True)
    rows_after = len(df_clean)

    df_copie = df_clean.copy()
    df_copie = df_copie.rename(columns=RENAME_MAP)
    df_copie = df_copie.drop(columns=DROP_COLUMNS, errors="ignore")
    df_copie = df_copie.astype("float32")

    _last_clean_and_prepare_cache.clear()
    _last_clean_and_prepare_cache[csv_path] = (df_clean, df_copie, rows_before, rows_after)

    return df_clean.copy(), df_copie.copy(), rows_before, rows_after


def preprocess_cicflowmeter_csv(csv_path: str, output_folder: str) -> Dict[str, Any]:
    """Nettoie un CSV CICFlowMeter et produit une copie prétraitée pour l'inférence ML.

    Args:
        csv_path: Chemin du CSV généré par CICFlowMeter (ex: xxx.pcap_Flow.csv)
        output_folder: Dossier où écrire les fichiers de sortie (le dossier d'analyse,
            pour rester regroupé avec les autres fichiers de sortie)

    Returns:
        Dictionnaire avec statut, chemins des fichiers produits, et statistiques
    """
    try:
        if not file_exists(csv_path):
            return {
                "status": "error",
                "message": f"[ERREUR] CSV CICFlowMeter non trouvé: {csv_path}",
            }

        df_clean, df_copie, rows_before, rows_after = _clean_and_prepare(csv_path)

        Path(output_folder).mkdir(parents=True, exist_ok=True)
        base_name = Path(csv_path).stem
        clean_csv_path = os.path.join(output_folder, f"{base_name}_clean.csv")
        ml_ready_csv_path = os.path.join(output_folder, f"{base_name}_ml_ready.csv")

        df_clean.to_csv(clean_csv_path, index=False)
        df_copie.to_csv(ml_ready_csv_path, index=False)

        nan_remaining = int(df_copie.isnull().sum().sum())
        final_columns = df_copie.shape[1]

        logger.info(
            f"Prétraitement terminé: {rows_before} -> {rows_after} lignes "
            f"({final_columns} colonnes, {nan_remaining} NaN restants)"
        )
        logger.info(f"Fichiers sauvegardés: {clean_csv_path}, {ml_ready_csv_path}")

        return {
            "status": "success",
            "message": "[OK] Prétraitement complété avec succès !",
            "clean_csv": clean_csv_path,
            "ml_ready_csv": ml_ready_csv_path,
            "rows_before": rows_before,
            "rows_after": rows_after,
            "final_columns": final_columns,
            "nan_remaining": nan_remaining,
        }

    except Exception as e:
        logger.error(f"Erreur lors du prétraitement: {e}")
        return {
            "status": "error",
            "message": f"[ERREUR] Erreur: {str(e)}",
        }


def classify_cicflowmeter_csv(
    csv_path: str,
    output_folder: str,
    model_path: str = CLASSIFIER_MODEL_PATH,
) -> Dict[str, Any]:
    """Nettoie un CSV CICFlowMeter, classifie avec le modèle entraîné, et enregistre
    l'original nettoyé enrichi des colonnes "classification" et "score_confiance".

    Args:
        csv_path: Chemin du CSV généré par CICFlowMeter (ex: xxx.pcap_Flow.csv)
        output_folder: Dossier où écrire les fichiers de sortie
        model_path: Chemin du modèle joblib ({"model": ..., "features": [...]}, plus
            "label_encoder" pour les modèles entraînés sur des classes encodées en entiers)

    Returns:
        Dictionnaire avec statut, chemins des fichiers produits, et statistiques
    """
    try:
        if not file_exists(csv_path):
            return {
                "status": "error",
                "message": f"[ERREUR] CSV CICFlowMeter non trouvé: {csv_path}",
            }

        if not file_exists(model_path):
            return {
                "status": "error",
                "message": f"[ERREUR] Modèle non trouvé: {model_path}",
            }

        df_clean, df_copie, rows_before, rows_after = _clean_and_prepare(csv_path)

        artefacts = joblib.load(model_path)
        model = artefacts["model"]
        features = artefacts["features"]
        label_encoder = artefacts.get("label_encoder")

        # Le modèle attend les colonnes dans l'ordre exact de `features` : on vérifie
        # d'abord qu'aucune n'est manquante (fatal), puis on signale les colonnes en
        # trop (non fatal, elles sont simplement ignorées par le X = copie[features]).
        manquantes = [f for f in features if f not in df_copie.columns]
        if manquantes:
            raise ValueError(f"Features manquantes dans la copie prétraitée: {manquantes}")

        en_trop = [c for c in df_copie.columns if c not in features]
        if en_trop:
            logger.warning(f"Colonnes en trop dans la copie prétraitée (ignorées par le modèle): {en_trop}")

        X = df_copie[features]

        y_classification = model.predict(X.values)
        # Random Forest (modèle par défaut) a été entraîné directement sur les noms de
        # classe en texte : predict() renvoie déjà des chaînes, pas de label_encoder dans
        # ses artefacts. LightGBM/XGBoost (models/classifieur_lightgbm.joblib,
        # models/classifieur_xgboost_v2.joblib) ont été entraînés sur des classes encodées en
        # entiers : leurs artefacts contiennent un LabelEncoder déjà ajusté pour retrouver
        # le nom de classe d'origine à partir de l'entier prédit.
        if label_encoder is not None:
            y_classification = label_encoder.inverse_transform(y_classification)
        y_proba = model.predict_proba(X.values)
        confiance = y_proba.max(axis=1)

        # df_clean et df_copie/X sont restés alignés ligne à ligne depuis _clean_and_prepare
        # (même ordre, aucun tri/filtrage supplémentaire) : la ligne i de y_classification
        # correspond donc bien à la ligne i de df_clean.
        df_clean["classification"] = y_classification
        df_clean["score_confiance"] = confiance.round(4)

        # Label (toujours "NeedManualLabel", placeholder CICFlowMeter jamais rempli) n'apporte
        # plus rien une fois qu'on a une vraie classification + un score de confiance.
        df_clean = df_clean.drop(columns=["Label"], errors="ignore")

        Path(output_folder).mkdir(parents=True, exist_ok=True)
        base_name = Path(csv_path).stem
        predicted_csv_path = os.path.join(output_folder, f"{base_name}_predicted.csv")
        df_clean.to_csv(predicted_csv_path, index=False)

        rows_final = len(df_clean)
        distribution = df_clean["classification"].value_counts().to_dict()

        logger.info(f"Classification terminée: {rows_final} flux, distribution: {distribution}")
        logger.info(f"CSV classifié sauvegardé: {predicted_csv_path}")

        return {
            "status": "success",
            "message": "[OK] Classification complétée avec succès !",
            "predicted_csv": predicted_csv_path,
            "rows_before": rows_before,
            "rows_after": rows_after,
            "rows_final": rows_final,
            "classification_distribution": distribution,
        }

    except Exception as e:
        logger.error(f"Erreur lors de la classification: {e}")
        return {
            "status": "error",
            "message": f"[ERREUR] Erreur: {str(e)}",
        }


def detect_anomalies_cicflowmeter_csv(
    csv_path: str,
    output_folder: str,
    model_path: str = ANOMALY_MODEL_PATH,
) -> Dict[str, Any]:
    """Détecte les anomalies (modèle non-supervisé Isolation Forest) et enrichit le
    CSV déjà classifié (classify_cicflowmeter_csv) avec deux colonnes supplémentaires :
    "anomalie" et "score_anomalie". Étape suivante du pipeline, après la classification
    — le fichier <nom>_predicted.csv doit donc déjà exister.

    Args:
        csv_path: Chemin du CSV généré par CICFlowMeter (ex: xxx.pcap_Flow.csv)
        output_folder: Dossier où se trouve (et sera réécrit) <nom>_predicted.csv
        model_path: Chemin du modèle joblib ({"model", "features", "seuil", "fpr"})

    Returns:
        Dictionnaire avec statut, chemin du fichier enrichi, et statistiques
    """
    try:
        if not file_exists(csv_path):
            return {
                "status": "error",
                "message": f"[ERREUR] CSV CICFlowMeter non trouvé: {csv_path}",
            }

        if not file_exists(model_path):
            return {
                "status": "error",
                "message": f"[ERREUR] Modèle de détection d'anomalies non trouvé: {model_path}",
            }

        base_name = Path(csv_path).stem
        predicted_csv_path = os.path.join(output_folder, f"{base_name}_predicted.csv")
        if not file_exists(predicted_csv_path):
            return {
                "status": "error",
                "message": (
                    f"[ERREUR] {os.path.basename(predicted_csv_path)} introuvable "
                    "— la classification (classify_cicflowmeter_csv) doit être exécutée "
                    "avant la détection d'anomalies."
                ),
            }

        # Le CSV déjà classifié (classification + score_confiance) est la
        # base qu'on enrichit ; la copie ML-ready est récupérée du cache posé par
        # l'appel précédent (prétraitement ou classification), pas recalculée : elle
        # contient donc bien les mêmes lignes, dans le même ordre, que celles
        # utilisées pour produire predicted_csv_path.
        df_final = pd.read_csv(predicted_csv_path)
        _, df_copie, _, _ = _clean_and_prepare(csv_path)

        if len(df_final) != len(df_copie):
            raise ValueError(
                f"Désalignement détecté entre {os.path.basename(predicted_csv_path)} "
                f"({len(df_final)} lignes) et la copie ML-ready recalculée "
                f"({len(df_copie)} lignes) — le fichier prédit ne correspond peut-être "
                "pas au même CSV CICFlowMeter."
            )

        artefacts = joblib.load(model_path)
        model = artefacts["model"]
        features = artefacts["features"]
        seuil = artefacts["seuil"]

        # Alignement sur les features PROPRES au modèle d'anomalie (indépendant de
        # celles du classifieur, même si elles se recoupent en pratique aujourd'hui).
        manquantes = [f for f in features if f not in df_copie.columns]
        if manquantes:
            raise ValueError(f"Features manquantes dans la copie prétraitée: {manquantes}")

        en_trop = [c for c in df_copie.columns if c not in features]
        if en_trop:
            logger.warning(f"Colonnes en trop dans la copie prétraitée (ignorées par le modèle): {en_trop}")

        X = df_copie[features]

        # IMPORTANT : score_samples() de scikit-learn renvoie un score où haut = normal.
        # Le seuil sauvegardé a été calibré sur des scores INVERSÉS (haut = anormal) : le
        # signe moins ci-dessous est donc indispensable, sans lui la comparaison au seuil
        # serait faite dans le mauvais sens et tous les flux seraient mal classés.
        scores = -model.score_samples(X.values)
        anomalie = np.where(scores >= seuil, "anormal", "normal")

        df_final["score_anomalie"] = scores.round(4)
        df_final["anomalie"] = anomalie

        df_final.to_csv(predicted_csv_path, index=False)

        anomaly_count = int((anomalie == "anormal").sum())
        normal_count = int((anomalie == "normal").sum())

        logger.info(f"Seuil utilisé: {seuil}")
        logger.info(f"Flux anormaux détectés: {anomaly_count} / {len(df_final)}")
        logger.info(f"CSV enrichi (anomalies) sauvegardé: {predicted_csv_path}")

        return {
            "status": "success",
            "message": "[OK] Détection d'anomalies complétée avec succès !",
            "predicted_csv": predicted_csv_path,
            "seuil": seuil,
            "anomaly_count": anomaly_count,
            "normal_count": normal_count,
            "total_rows": len(df_final),
        }

    except Exception as e:
        logger.error(f"Erreur lors de la détection d'anomalies: {e}")
        return {
            "status": "error",
            "message": f"[ERREUR] Erreur: {str(e)}",
        }


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python ml_preprocessing.py <csv_cicflowmeter> <dossier_sortie> [--classify|--anomalies]")
        sys.exit(1)

    if "--anomalies" in sys.argv:
        result = detect_anomalies_cicflowmeter_csv(sys.argv[1], sys.argv[2])
    elif "--classify" in sys.argv:
        result = classify_cicflowmeter_csv(sys.argv[1], sys.argv[2])
    else:
        result = preprocess_cicflowmeter_csv(sys.argv[1], sys.argv[2])
    print(result)
