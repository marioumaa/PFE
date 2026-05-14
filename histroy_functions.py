# ===== History Management =====
from datetime import datetime
import os
import streamlit as st

from logger import setup_logging
logger = setup_logging(__name__)

from config import HISTORY_FILE
from typing import Optional, List, Dict, Any

from utils import get_file_size_kb, load_json_file, save_json_file


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


def save_analysis_to_history(pcap_path: str, analysis_result: Dict[str, Any], file_size_gb: float) -> None:
    """Sauvegarde les détails d'une analyse dans l'historique.
    
    Args:
        pcap_path: Chemin du fichier PCAP
        analysis_result: Résultats de l'analyse
        file_size_gb: Taille du fichier en GB
    """
    try:
        # Charger l'historique existant
        history = load_history()
        
        # Créer une entrée d'analyse détaillée
        analysis_entry = {
            "id": len(history),
            "filename": os.path.basename(pcap_path),
            "file_path": pcap_path,
            "file_size_gb": round(file_size_gb, 2),
            "selection_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "analysis_folder": analysis_result.get("analysis_folder", ""),
            "pcap_name": analysis_result.get("pcap_name", ""),
            "timestamp": analysis_result.get("timestamp", "")
        }
        
        # Ajouter les fichiers générés
        analysis_folder = analysis_result.get("analysis_folder")
        if analysis_folder and os.path.exists(analysis_folder):
            files_info = {}
            for filename in ["eve.json", "suricata.log", "stats.log", "fast.log"]:
                filepath = os.path.join(analysis_folder, filename)
                if os.path.exists(filepath):
                    files_info[filename] = {
                        "size_kb": get_file_size_kb(filepath),
                        "found": True
                    }
            analysis_entry["output_files"] = files_info
        
        # Ajouter à l'historique
        history.append(analysis_entry)
        save_history(history)
        logger.info(f"Analyse ajoutée à l'historique: {os.path.basename(pcap_path)}")
            
    except Exception as e:
        logger.error(f"Erreur lors de la sauvegarde de l'analyse: {e}")
        st.warning(f"Historique non sauvegardé: {str(e)}")



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
        # En-tête de la carte
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
        
        # Détails
        with st.expander("Voir les détails", expanded=False):
            st.write("**Informations générales :**")
            st.write(f"ID: {analysis.get('id', 'N/A')}")
            
            
            st.write("**Fichiers de sortie :**")
            output_files = analysis.get('output_files', {})
            if output_files:
                for file_name, file_info in output_files.items():
                    size_kb = file_info.get('size_kb', 0)
                    st.write(f"- {file_name}: {size_kb:.2f} KB")
            else:
                st.write("Aucun fichier de sortie")
        
        st.divider()









