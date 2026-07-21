"""Gestion de l'historique des analyses PCAP (persistance + affichage Streamlit)."""

import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import streamlit as st

from config import HISTORY_FILE
from dashboards import _render_metric_cards
from logger import setup_logging
from utils import get_file_size_kb, load_json_file, save_json_file

_RISK_CARD_COLORS = {
    "CRITIQUE": "#c0392b",
    "ELEVE": "#e67e22",
    "MOYEN": "#d4ac0d",
    "NORMAL": "#16a085",
}

logger = setup_logging(__name__)


def load_history() -> List[Dict[str, Any]]:
    """Charge l'historique des analyses depuis le disque.

    Returns:
        Liste des analyses historiques
    """
    history = load_json_file(str(HISTORY_FILE))
    return history if isinstance(history, list) else []


def save_history(history: List[Dict[str, Any]]) -> None:
    """Sauvegarde l'historique sur le disque.

    Args:
        history: Liste des analyses à sauvegarder
    """
    if save_json_file(str(HISTORY_FILE), history):
        logger.info("Historique sauvegardé avec succès")
    else:
        logger.error("Erreur lors de la sauvegarde de l'historique")


def _next_history_id(history: List[Dict[str, Any]]) -> int:
    """Calcule le prochain ID d'entrée d'historique.

    Utilise max(id existants) + 1 plutôt que len(history) : reste unique même
    si une entrée a été retirée manuellement du fichier JSON.
    """
    existing_ids = [entry.get("id", -1) for entry in history if isinstance(entry, dict)]
    return (max(existing_ids) + 1) if existing_ids else 0


def save_analysis_to_history(
    pcap_path: str,
    analysis_result: Dict[str, Any],
    file_size_gb: float,
    cicflowmeter_result: Optional[Dict[str, Any]] = None,
    preprocessing_result: Optional[Dict[str, Any]] = None,
    classification_result: Optional[Dict[str, Any]] = None,
    anomaly_result: Optional[Dict[str, Any]] = None,
    jointure_result: Optional[Dict[str, Any]] = None,
) -> None:
    """Sauvegarde les détails d'une analyse dans l'historique.

    Appelée depuis le thread d'analyse en arrière-plan (voir app.py) : ne doit
    donc jamais appeler d'API Streamlit (st.*), qui exige un contexte de script
    actif. Les erreurs sont uniquement journalisées.

    Args:
        pcap_path: Chemin du fichier PCAP
        analysis_result: Résultats de l'analyse Suricata
        file_size_gb: Taille du fichier en GB
        cicflowmeter_result: Résultats de l'extraction CICFlowMeter (optionnel)
        preprocessing_result: Résultats du prétraitement ML (optionnel)
        classification_result: Résultats de la classification ML (optionnel)
        anomaly_result: Résultats de la détection d'anomalies (optionnel)
        jointure_result: Résultat de la phase "Jointure" (jointure Suricata + niveau de
            risque, voir risk_correlation.correlate_with_suricata) ; contient les clés
            imbriquées "unification_result" et "risk_result" (optionnel)
    """
    unification_result = (jointure_result or {}).get("unification_result")
    risk_result = (jointure_result or {}).get("risk_result")
    try:
        history = load_history()

        analysis_entry = {
            "id": _next_history_id(history),
            "filename": os.path.basename(pcap_path),
            "file_path": pcap_path,
            "file_size_gb": round(file_size_gb, 2),
            "selection_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "analysis_folder": analysis_result.get("analysis_folder", ""),
            "pcap_name": analysis_result.get("pcap_name", ""),
            "timestamp": analysis_result.get("timestamp", ""),
            "home_net_used": analysis_result.get("home_net_used", "Défaut (suricata.yaml)"),
        }

        # Ajouter les fichiers générés (Suricata + CICFlowMeter)
        analysis_folder = analysis_result.get("analysis_folder")
        if analysis_folder and os.path.exists(analysis_folder):
            files_info = {}
            for filename in ["eve.json", "suricata.log", "stats.log", "fast.log"]:
                filepath = os.path.join(analysis_folder, filename)
                if os.path.exists(filepath):
                    files_info[filename] = {
                        "size_kb": get_file_size_kb(filepath),
                        "found": True,
                    }

            csv_file = (cicflowmeter_result or {}).get("csv_file")
            if csv_file and os.path.exists(csv_file):
                files_info[os.path.basename(csv_file)] = {
                    "size_kb": get_file_size_kb(csv_file),
                    "found": True,
                }

            for ml_file_key in ("clean_csv", "ml_ready_csv"):
                ml_file = (preprocessing_result or {}).get(ml_file_key)
                if ml_file and os.path.exists(ml_file):
                    files_info[os.path.basename(ml_file)] = {
                        "size_kb": get_file_size_kb(ml_file),
                        "found": True,
                    }

            predicted_file = (classification_result or {}).get("predicted_csv")
            if predicted_file and os.path.exists(predicted_file):
                files_info[os.path.basename(predicted_file)] = {
                    "size_kb": get_file_size_kb(predicted_file),
                    "found": True,
                }

            unified_file = (unification_result or {}).get("unified_csv")
            if unified_file and os.path.exists(unified_file):
                files_info[os.path.basename(unified_file)] = {
                    "size_kb": get_file_size_kb(unified_file),
                    "found": True,
                }

            final_file = (risk_result or {}).get("final_csv")
            if final_file and os.path.exists(final_file):
                files_info[os.path.basename(final_file)] = {
                    "size_kb": get_file_size_kb(final_file),
                    "found": True,
                }

            analysis_entry["output_files"] = files_info

        analysis_entry["cicflowmeter_status"] = (cicflowmeter_result or {}).get("status", "non exécuté")
        analysis_entry["preprocessing_status"] = (preprocessing_result or {}).get("status", "non exécuté")
        analysis_entry["classification_status"] = (classification_result or {}).get("status", "non exécuté")
        if classification_result and classification_result.get("status") == "success":
            analysis_entry["classification_distribution"] = classification_result.get("classification_distribution", {})

        analysis_entry["anomaly_status"] = (anomaly_result or {}).get("status", "non exécuté")
        if anomaly_result and anomaly_result.get("status") == "success":
            analysis_entry["anomaly_count"] = anomaly_result.get("anomaly_count", 0)
            analysis_entry["normal_count"] = anomaly_result.get("normal_count", 0)

        analysis_entry["unification_status"] = (unification_result or {}).get("status", "non exécuté")
        if unification_result and unification_result.get("status") == "success":
            analysis_entry["matched_flows"] = unification_result.get("matched_flows", 0)
            analysis_entry["unmatched_flows"] = unification_result.get("unmatched_flows", 0)

        analysis_entry["risk_status"] = (risk_result or {}).get("status", "non exécuté")
        if risk_result and risk_result.get("status") == "success":
            analysis_entry["risk_distribution"] = risk_result.get("distribution", {})
            analysis_entry["total_rows"] = risk_result.get("total_rows", 0)

        history.append(analysis_entry)
        save_history(history)
        logger.info(f"Analyse ajoutée à l'historique: {os.path.basename(pcap_path)}")

    except Exception as e:
        logger.error(f"Erreur lors de la sauvegarde de l'analyse dans l'historique: {e}")


def _display_history_statistics(history: List[Dict[str, Any]]) -> None:
    """Affiche les statistiques générales de l'historique.

    Args:
        history: Liste des analyses historiques
    """
    col1, col2 = st.columns(2)

    with col1:
        st.metric("Total d'analyses", len(history))

    with col2:
        if history:
            st.metric("Dernière analyse", history[-1].get("selection_date", "N/A")[:10])


def _display_analysis_card(analysis: Dict[str, Any]) -> None:
    """Affiche une carte d'analyse.

    Args:
        analysis: Données de l'analyse
    """
    with st.container():
        col1, col2, col3, col4 = st.columns([2, 2, 2, 1])

        with col1:
            st.markdown(f"### {analysis.get('filename', 'Unknown')}")
        with col2:
            st.markdown(f"**Taille:** `{analysis.get('file_size_gb', 0):.2f} GB`")
        with col3:
            st.markdown(f"**Date:** `{analysis.get('selection_date', 'N/A')}`")
        with col4:
            if analysis.get('output_files'):
                st.success("Complète")
            else:
                st.warning("En cours")

        risk_distribution = analysis.get('risk_distribution')
        if risk_distribution:
            # total_rows n'existe pas sur les analyses faites avant son ajout à
            # l'historique : la somme des niveaux reste un total correct dans ce cas.
            total_rows = analysis.get('total_rows') or sum(risk_distribution.values())
            cards = [("Flux analysés", total_rows, "#34495e", None)]
            for level, color in _RISK_CARD_COLORS.items():
                cards.append((level, risk_distribution.get(level, 0), color, None))
            _render_metric_cards(cards)

        with st.expander("Voir les détails", expanded=False):
            st.write("**Informations générales :**")
            st.write(f"ID: {analysis.get('id', 'N/A')}")
            st.write(f"HOME_NET utilisé: `{analysis.get('home_net_used', 'N/A')}`")

            st.write("**Fichiers de sortie :**")
            output_files = analysis.get('output_files', {})
            if output_files:
                for file_name, file_info in output_files.items():
                    size_kb = file_info.get('size_kb', 0)
                    st.write(f"- {file_name}: {size_kb:.2f} KB")
            else:
                st.write("Aucun fichier de sortie")

        st.divider()
