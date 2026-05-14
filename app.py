
import os
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from datetime import datetime
from typing import Optional, List, Dict, Any
import tkinter as tk
from tkinter import filedialog
from histroy_functions import _display_analysis_card, _display_history_statistics, load_history, save_analysis_to_history
from suricata_analyzer import run_suricata_analysis, parse_eve_alerts
from cicflowmeter_analyzer import run_cicflowmeter_analysis
from config import HISTORY_FILE
from logger import setup_logging
from utils import load_json_file, save_json_file, get_file_size_gb, get_file_size_kb
from dashboards import _display_alerts_statistics, _display_alerts_charts

logger = setup_logging(__name__)

def select_pcap_file():
    root = tk.Tk()
    root.withdraw()  # cacher la fenêtre principale
    root.attributes('-topmost', True)  # mettre devant

    file_path = filedialog.askopenfilename(
        title="Sélectionner un fichier PCAP",
        filetypes=[("PCAP files", "*.pcap")]
    )

    root.destroy()
    return file_path

# ===== Session State Initialization =====
def _initialize_session_state() -> None:
    """Initialise les variables de session."""
    if 'history' not in st.session_state:
        st.session_state['history'] = load_history()
    
    if 'selected_pcap' not in st.session_state:
        st.session_state['selected_pcap'] = None
    
    if 'selected_pcap_name' not in st.session_state:
        st.session_state['selected_pcap_name'] = None
    
    if 'analysis_result' not in st.session_state:
        st.session_state['analysis_result'] = None
    
    if 'analysis_folder' not in st.session_state:
        st.session_state['analysis_folder'] = None
    
    if 'pipeline_started' not in st.session_state:
        st.session_state['pipeline_started'] = False
    
    if 'pipeline_done' not in st.session_state:
        st.session_state['pipeline_done'] = False
    
    if 'pipeline_status' not in st.session_state:
        st.session_state['pipeline_status'] = None
    
    if 'ml_results' not in st.session_state:
        st.session_state['ml_results'] = None
    
    if 'flows_csv' not in st.session_state:
        st.session_state['flows_csv'] = None






# Initialiser la session au démarrage
_initialize_session_state()

# ===== Page: Home =====
def home_page() -> None:
    """Page d'accueil professionnelle."""
    st.set_page_config(page_title="PCAP Analyzer", layout="wide")
    
    st.markdown("## Analyseur PCAP - Détection d'anomalies réseau")
    
    
    st.markdown("""
    Plateforme d'analyse de trafic réseau avec Suricata et Machine Learning.
    
    Identification automatique des menaces et anomalies à partir de fichiers PCAP
    """)
    

    st.markdown("---")
    st.markdown("### Guide d'utilisation")
    
   
    
    st.markdown("---")
    st.markdown("### Fonctionnalités principales")
    

    
    st.markdown("---")
    st.success("Prêt à commencer ? Allez à Sélection PCAP dans la barre latérale.")


# ===== Page: Upload and Analysis =====
def upload_page() -> None:
    """Page de sélection et analyse des fichiers PCAP."""
    st.title("Sélection PCAP")
    st.write("Sélectionnez un fichier PCAP local pour analyse du trafic réseau")

    # Vérifier si un fichier est déjà sélectionné en session
    if st.session_state.get('selected_pcap'):
        file_path = st.session_state['selected_pcap']
        file_size_gb = get_file_size_gb(file_path)
        _display_selected_pcap()
        if not st.session_state.get('pipeline_started'):
            _run_analysis_pipeline(file_path, file_size_gb)
    else:
        _display_file_selection()




# ===== Page: History =====
def history_page() -> None:
    """Page d'historique des analyses PCAP."""
    st.title("Historique des analyses PCAP")
    st.markdown("---")
    
    # Charger l'historique
    history = load_history()
    
    if not history:
        st.info("Aucune analyse n'a encore été effectuée.")
        return
    
    # Filtrer les éléments invalides
    valid_history = [item for item in history if isinstance(item, dict)]
    
    if not valid_history:
        st.warning("Les données d'historique ne sont pas au bon format. Veuillez réexécuter les analyses.")
        return
    
    # Afficher les statistiques générales
    _display_history_statistics(valid_history)
    st.markdown("---")
    
    # Afficher chaque analyse en carte professionnelle
    for idx, analysis in enumerate(reversed(valid_history), 1):
        if not isinstance(analysis, dict):
            continue
        
        _display_analysis_card(analysis)



def _display_selected_pcap() -> None:
    """Affiche le fichier PCAP sélectionné et le statut du pipeline d'analyse."""
    file_path = st.session_state['selected_pcap']
    filename = st.session_state.get('selected_pcap_name', os.path.basename(file_path))
    
    st.success("Fichier PCAP sélectionné avec succès !")
    
    file_size = os.path.getsize(file_path)
    file_size_gb = get_file_size_gb(file_path)
    
    col1, col2 = st.columns(2)
    with col1:
        st.info(f"Fichier: {filename}")
    with col2:
        st.info(f"Taille: {file_size_gb:.2f} GB")
    
    st.divider()
    st.subheader("Pipeline d'analyse automatique")
    
    if st.session_state.get('pipeline_done'):
        st.success("Pipeline terminé")
    elif st.session_state.get('pipeline_started'):
        status_message = st.session_state.get('pipeline_status', "Analyse en cours...")
        st.info(status_message)
    else:
        st.info("Préparation du pipeline d'analyse...")
    
    # Afficher les résultats ML s'ils existent dans session_state
    if st.session_state.get('ml_results') is not None:
        ml_results = st.session_state['ml_results']
        if ml_results and ml_results.get("status") == "success":
            st.divider()
            st.subheader("Résultats de l'Analyse ML - Classification des Flows")
            
            st.write("**Résumé des prédictions:**")
            pred_summary = ml_results.get("prediction_summary", {})
            if pred_summary:
                for pred, count in pred_summary.items():
                    st.write(f"- **{pred}**: {count} occurrences")
            else:
                st.info("Aucune prédiction disponible")
        elif ml_results and ml_results.get("status") == "error":
            st.error(f"Erreur ML: {ml_results.get('message', 'Erreur inconnue')}")
    
    # Afficher les résultats Suricata s'ils existent
    if st.session_state.get('analysis_result') is not None:
        if st.session_state['analysis_result'].get('status') == 'success':
            # Parser et afficher les alertes
            alerts_data = parse_eve_alerts(st.session_state['analysis_folder'])
    
            if alerts_data["status"] == "success":
                _display_alerts_statistics(alerts_data)
                _display_alerts_charts(alerts_data)
             

            


def _display_file_selection() -> None:
    st.markdown("### Sélectionnez un fichier PCAP depuis votre ordinateur")
    
    if st.button("Choisir un fichier PCAP"):
        file_path = select_pcap_file()

        if file_path:
            if not os.path.exists(file_path):
                st.error("Fichier introuvable.")
                return

            if not file_path.lower().endswith(".pcap"):
                st.error("Veuillez sélectionner un fichier .pcap")
                return

            st.session_state['selected_pcap'] = file_path
            st.session_state['selected_pcap_name'] = os.path.basename(file_path)
            st.session_state['pipeline_started'] = False
            st.session_state['pipeline_done'] = False
            st.session_state['pipeline_status'] = None
            st.session_state['analysis_result'] = None
            st.session_state['analysis_folder'] = None
            st.session_state['ml_results'] = None
            st.session_state['flows_csv'] = None

            st.success("Fichier sélectionné avec succès !")
            st.rerun()
    
     


def _run_suricata_analysis(file_path: str, file_size_gb: float) -> None:
    """Exécute l'analyse Suricata.
    
    Args:
        file_path: Chemin du fichier PCAP
        file_size_gb: Taille du fichier en GB
    """
    with st.spinner("Suricata analyse le fichier en cours... Cela peut prendre plusieurs minutes..."):
        logger.info(f"Demarrage de l'analyse: {file_path}")
        analysis_result = run_suricata_analysis(file_path)
        
        if analysis_result["status"] == "success":
            st.session_state['analysis_result'] = analysis_result
            st.session_state['analysis_folder'] = analysis_result['analysis_folder']
            
            # Sauvegarder l'analyse dans l'historique
            save_analysis_to_history(file_path, analysis_result, file_size_gb)
            
            st.success(analysis_result["message"])
            st.rerun()
        else:
            st.error(analysis_result["message"])


def _run_flow_extraction(file_path: str, file_size_gb: float) -> None:
    """Exécute l'extraction de flows avec CICFlowMeter.
    
    Args:
        file_path: Chemin du fichier PCAP
        file_size_gb: Taille du fichier en GB
    """
    # Verifier que Suricata a d'abord été exécuté pour créer le dossier d'analyse
    if not st.session_state.get('analysis_folder'):
        st.error("Veuillez d'abord executer l'analyse Suricata pour creer le dossier d'analyse.")
        return
    
    analysis_folder = st.session_state['analysis_folder']
    
    with st.spinner("Extraction des flows avec CICFlowMeter en cours... Cela peut prendre quelques minutes..."):
        logger.info(f"Demarrage de l'extraction des flows: {file_path} -> {analysis_folder}")
        
        extraction_result = run_cicflowmeter_analysis(file_path, analysis_folder)
        logger.info(f"Resultat de l'extraction CICFlowMeter: {extraction_result.get('status', 'unknown')}")
        
        if extraction_result["status"] == "success":
            logger.info("Extraction CICFlowMeter réussie - traitement des résultats...")
            flows_csv_path = extraction_result.get("output_csv")
            
            # Sauvegarder le fichier dans l'historique
            if flows_csv_path and os.path.exists(flows_csv_path):
                file_size_kb = get_file_size_kb(flows_csv_path)
                
                # Stocker dans la session
                st.session_state['flows_csv'] = flows_csv_path
                
                # Stocker les résultats ML dans session_state AVANT de quitter le spinner
                ml_results = extraction_result.get("ml_results")
                st.session_state['ml_results'] = ml_results
            else:
                st.error("Impossible de localiser le fichier flows.csv genere.")
                return
        else:
            st.error(f"Erreur lors de l'extraction: {extraction_result['message']}")
            return
    
    # AFFICHAGE EN DEHORS DU SPINNER - MESSAGES PERSISTANTS
    st.success(extraction_result["message"])
    st.info(f"Fichier flows.csv genere avec succes ({file_size_kb:.2f} KB) dans {analysis_folder}")
    
    # Rerun pour mettre à jour l'affichage avec les résultats ML
    st.rerun()


def _run_analysis_pipeline(file_path: str, file_size_gb: float) -> None:
    """Exécute le pipeline complet Suricata -> CICFlowMeter -> ML."""
    st.session_state['pipeline_started'] = True
    st.session_state['pipeline_status'] = "Analyse Suricata en cours..."

    with st.spinner(st.session_state['pipeline_status']):
        logger.info(f"Demarrage de l'analyse Suricata: {file_path}")
        analysis_result = run_suricata_analysis(file_path)

        if analysis_result["status"] != "success":
            st.session_state['analysis_result'] = analysis_result
            st.session_state['pipeline_done'] = True
            st.session_state['pipeline_status'] = "Échec de l'analyse Suricata"
            st.error(analysis_result.get("message", "Erreur lors de l'analyse Suricata"))
            return

        st.session_state['analysis_result'] = analysis_result
        st.session_state['analysis_folder'] = analysis_result['analysis_folder']
        save_analysis_to_history(file_path, analysis_result, file_size_gb)

    st.session_state['pipeline_status'] = "Extraction des flows avec CICFlowMeter en cours..."
    analysis_folder = st.session_state['analysis_folder']

    with st.spinner(st.session_state['pipeline_status']):
        logger.info(f"Demarrage de l'extraction des flows: {file_path} -> {analysis_folder}")
        extraction_result = run_cicflowmeter_analysis(file_path, analysis_folder)

        if extraction_result["status"] != "success":
            st.session_state['pipeline_done'] = True
            st.session_state['pipeline_status'] = "Échec de l'extraction des flows"
            st.error(extraction_result.get("message", "Erreur lors de l'extraction des flows"))
            return

        flows_csv_path = extraction_result.get("output_csv")
        if flows_csv_path and os.path.exists(flows_csv_path):
            file_size_kb = get_file_size_kb(flows_csv_path)
            st.session_state['flows_csv'] = flows_csv_path
            st.session_state['ml_results'] = extraction_result.get("ml_results")
            st.session_state['pipeline_status'] = "Pipeline terminé"
            st.session_state['pipeline_done'] = True
            st.success(extraction_result["message"])
            st.info(f"Fichier flows.csv genere avec succes ({file_size_kb:.2f} KB) dans {analysis_folder}")
        else:
            st.session_state['pipeline_done'] = True
            st.session_state['pipeline_status'] = "Échec de l'extraction des flows"
            st.error("Impossible de localiser le fichier flows.csv genere.")
            return

    st.rerun()



    
    
    
    


# ===== Main App Configuration =====
def main() -> None:
    """Fonction principale de l'application."""
    st.set_page_config(
        page_title="PCAP Analyzer",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Navigation avec selectbox
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox(
        "Aller à",
        ["Accueil", "Sélection PCAP", "Historique"]
    )
    
    if page == "Accueil":
        home_page()
    elif page == "Sélection PCAP":
        upload_page()
    elif page == "Historique":
        history_page()


if __name__ == "__main__":
    main()