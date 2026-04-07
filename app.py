
import os
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from datetime import datetime
from typing import Optional, List, Dict, Any
import tkinter as tk
from tkinter import filedialog
from suricata_analyzer import run_suricata_analysis, parse_eve_alerts, get_analysis_summary
from config import HISTORY_FILE
from logger import setup_logging
from utils import load_json_file, save_json_file, get_file_size_gb, get_file_size_kb

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
    
    if 'analysis_result' not in st.session_state:
        st.session_state['analysis_result'] = None
    
    if 'analysis_folder' not in st.session_state:
        st.session_state['analysis_folder'] = None


# ===== History Management =====
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


# Initialiser la session au démarrage
_initialize_session_state()

# ===== Page: Home =====
def home_page() -> None:
    """Page d'accueil professionnelle."""
    st.set_page_config(page_title="PCAP Analyzer", layout="wide")
    
    st.markdown("## Analyseur PCAP - Détection d'anomalies réseau")
    st.markdown("---")
    
    st.markdown("""
    Plateforme d'analyse de trafic réseau avec Suricata et Machine Learning.
    
    Identification automatique des menaces et anomalies à partir de fichiers PCAP
    """)
    
    # Caractéristiques principales
    col1, col2 = st.columns(2)
    

    
    with col1:
        st.markdown("""
        **Analytique avancée**
        - Visualisations interactives
        - Graphiques détaillés
        - Statistiques complètes
        """)
    
    with col2:
        st.markdown("""
        **Gestion des données**
        - Historique complet
        - Traçabilité totale
        - Résultats structurés
        """)
    
    st.markdown("---")
    st.markdown("### Guide d'utilisation")
    
    # Processus d'analyse
    step_cols = st.columns(5)
    steps = [
        ("1", "Sélectionner", "Choisissez votre fichier PCAP"),
        ("2", "Analyser", "Lancez Suricata"),
        ("3", "Analyser", "Classification avec ML"),
        ("4", "Résultats", "Visualisez les alertes"),
        ("5", "Historique", "Consultez vos analyses")
    ]
    
    for col, (num, title, desc) in zip(step_cols, steps):
        with col:
            st.markdown(f"**Étape {num}: {title}**\n\n{desc}")
    
    st.markdown("---")
    st.markdown("### Fonctionnalités principales")
    
    features = {
        "Détection de menaces": "Identifier les anomalies et les menaces",
        "Statistiques détaillées": "Analyse complète par catégorie et sévérité",
        "Visualisations interactives": "Graphiques pie charts et bar charts détaillés",
        "Rapports d'analyse": "Export complet des résultats d'analyse"
    }
    
    feature_cols = st.columns(2)
    for idx, (feature, desc) in enumerate(features.items()):
        with feature_cols[idx % 2]:
            st.info(f"**{feature}**\n{desc}")
    
    st.markdown("---")
    st.success("Prêt à commencer ? Allez à Sélection PCAP dans la barre latérale.")


# ===== Page: Upload and Analysis =====
def upload_page() -> None:
    """Page de sélection et analyse des fichiers PCAP."""
    st.title("Sélection PCAP")
    st.write("Sélectionnez un fichier PCAP local pour analyse du trafic réseau")

    # Vérifier si un fichier est déjà sélectionné en session
    if st.session_state.get('selected_pcap'):
        _display_selected_pcap()
    else:
        _display_file_selection()


def _display_selected_pcap() -> None:
    """Affiche le fichier PCAP sélectionné et les options d'analyse."""
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
    st.subheader("Analyse Suricata")
    
    if st.button("Analyser avec Suricata", key="analyze_button"):
        _run_analysis(file_path, file_size_gb)
    
    # Afficher les résultats s'ils existent
    if st.session_state.get('analysis_result') is not None:
        if st.session_state['analysis_result'].get('status') == 'success':
            display_analysis_results(st.session_state['analysis_folder'])


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

            st.success("Fichier sélectionné avec succès !")
            st.rerun()
    
     


def _run_analysis(file_path: str, file_size_gb: float) -> None:
    """Exécute l'analyse Suricata.
    
    Args:
        file_path: Chemin du fichier PCAP
        file_size_gb: Taille du fichier en GB
    """
    with st.spinner("Suricata analyse le fichier en cours... Cela peut prendre plusieurs minutes..."):
        logger.info(f"Démarrage de l'analyse: {file_path}")
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

def display_analysis_results(analysis_folder: str) -> None:
    """Affiche les résultats de l'analyse Suricata.
    
    Args:
        analysis_folder: Dossier contenant les résultats d'analyse
    """
    if not analysis_folder or not os.path.exists(analysis_folder):
        st.error("Dossier d'analyse introuvable. Veuillez relancer l'analyse.")
        return
    
    st.divider()
    st.subheader("Résultats de l'Analyse")
    
    # Obtenir les infos sur les fichiers générés
    files_summary = get_analysis_summary(analysis_folder)
    
    if files_summary and files_summary.get("status") == "success":
        _display_generated_files(files_summary)
    
    # Parser et afficher les alertes
    alerts_data = parse_eve_alerts(analysis_folder)
    
    if alerts_data["status"] == "success":
        _display_alerts_statistics(alerts_data)
        _display_alerts_charts(alerts_data)


def _display_generated_files(files_summary: Dict[str, Any]) -> None:
    """Affiche les fichiers générés par Suricata.
    
    Args:
        files_summary: Résumé des fichiers générés
    """
    st.write("**Fichiers générés par Suricata :**")
    col1, col2 = st.columns(2)
    
    for filename, info in files_summary["files"].items():
        col = col1 if list(files_summary["files"].keys()).index(filename) % 2 == 0 else col2
        with col:
            if info["found"]:
                st.success(f"OK - {filename}")
                st.caption(f"{info['description']} - {info['size_kb']:.2f} KB")
            else:
                st.warning(f"Non trouvé - {filename}")


def _display_alerts_statistics(alerts_data: Dict[str, Any]) -> None:
    """Affiche les statistiques des alertes.
    
    Args:
        alerts_data: Données des alertes parsées
    """
    st.divider()
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Nombre d'alertes", alerts_data["alert_count"])
    with col2:
        st.metric("Total d'événements", alerts_data["total_events"])
    with col3:
        st.metric("Types d'événements", len(alerts_data["event_types"]))
    
    # Détails des types d'événements
    st.write("**Distribution des événements :**")
    event_dist = alerts_data["event_types"]
    if event_dist:
        st.bar_chart(event_dist)


def _display_alerts_charts(alerts_data: Dict[str, Any]) -> None:
    """Affiche les graphiques d'analyse des alertes.
    
    Args:
        alerts_data: Données des alertes parsées
    """
    st.divider()
    if alerts_data.get("alert_categories"):
        st.subheader("Distribution des catégories d'alertes")
        
        categories_data = alerts_data["alert_categories"]
        
        # Créer un dataframe pour le pie chart
        cat_df = pd.DataFrame({
            "Catégorie": list(categories_data.keys()),
            "Nombre d'alertes": list(categories_data.values())
        }).sort_values('Nombre d\'alertes', ascending=False)
        
        # Afficher le pie chart
        fig = go.Figure(data=[go.Pie(
            labels=cat_df['Catégorie'],
            values=cat_df['Nombre d\'alertes'],
            textposition='auto',
            textinfo='label+percent',
            hovertemplate='<b>%{label}</b><br>Alertes: %{value}<br>Pourcentage: %{percent}<extra></extra>',
            marker=dict(line=dict(color='white', width=2))
        )])
        
        fig.update_layout(
            height=600,
            showlegend=True,
            font=dict(size=12),
            title={
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 18}
            },
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)'
        )
        
        st.plotly_chart(fig, use_container_width='stretch')
        






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
            st.write(f"Fichier: {analysis.get('filename', 'N/A')}")
            st.write(f"Taille: {analysis.get('file_size_gb', 0):.2f} GB")
            
            st.write("**Fichiers de sortie :**")
            output_files = analysis.get('output_files', {})
            if output_files:
                for file_name, file_info in output_files.items():
                    size_kb = file_info.get('size_kb', 0)
                    st.write(f"- {file_name}: {size_kb:.2f} KB")
            else:
                st.write("Aucun fichier de sortie")
        
        st.divider()


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