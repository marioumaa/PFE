"""Application Streamlit : sélection d'un PCAP et lancement du pipeline d'analyse."""

import ipaddress
import os
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st

from cicflowmeter_analyzer import run_cicflowmeter_analysis
from dashboards import (
    display_correlation_dashboard,
    _render_metric_cards,
    _COLOR_CRITIQUE,
    _COLOR_ELEVE,
    _COLOR_MOYEN,
    _COLOR_NORMAL,
)
from history_functions import (
    _display_analysis_card,
    _display_history_statistics,
    load_history,
    save_analysis_to_history,
)
from logger import setup_logging
from ml_preprocessing import (
    preprocess_cicflowmeter_csv,
    classify_cicflowmeter_csv,
    detect_anomalies_cicflowmeter_csv,
)
from risk_correlation import (
    correlate_with_suricata,
    count_eve_event_types,
    load_correlation_dataframe,
)
from suricata_analyzer import run_suricata_analysis
from utils import get_file_size_gb

logger = setup_logging(__name__)


@st.cache_data(show_spinner=False, max_entries=10)
def _load_correlation_data_cached(final_csv: str) -> pd.DataFrame:
    """Version mise en cache de load_correlation_dataframe.

    Sans ce cache, le CSV final (potentiellement plusieurs centaines de milliers de
    lignes) est rechargé en entier à chaque rerun complet du script Streamlit — y
    compris en changeant simplement de page puis en revenant sur "Sélection PCAP" —
    ce qui se manifeste comme un blocage temporaire de l'appli.
    """
    return load_correlation_dataframe(final_csv)


@st.cache_data(show_spinner=False, max_entries=10)
def _load_event_type_counts_cached(eve_json_path: str) -> Dict[str, int]:
    """Version mise en cache de count_eve_event_types (même motivation que
    _load_correlation_data_cached : eve.json peut être volumineux et ne doit pas
    être reparcouru à chaque rerun Streamlit).
    """
    return count_eve_event_types(eve_json_path)


def _validate_home_net(value: str) -> Optional[str]:
    """Valide la saisie du champ HOME_NET.

    Args:
        value: Texte saisi par l'utilisateur (peut être vide)

    Returns:
        None si valide, sinon un message d'erreur à afficher
    """
    value = value.strip()
    if not value or value.lower() == "any":
        return None

    for entry in value.split(","):
        entry = entry.strip()
        if not entry:
            return "Entrée vide entre deux virgules."
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return f"'{entry}' n'est pas une adresse IP ou une plage CIDR valide (ex: 192.168.1.0/24)."
    return None


def select_pcap_file() -> str:
    
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)

        file_path = filedialog.askopenfilename(
            title="Sélectionner un fichier PCAP",
            filetypes=[("PCAP files", "*.pcap")]
        )

        root.destroy()
    except Exception as e:
        logger.error(f"Erreur lors de l'ouverture du sélecteur de fichier: {e}")
        return ""

    if file_path:
        logger.info(f"Fichier PCAP choisi par l'utilisateur: {file_path}")
    else:
        logger.info("Sélection de fichier annulée par l'utilisateur")

    return file_path


# ===== Session State Initialization =====
# Valeurs par défaut de la session ; 'history' est traité à part car sa valeur
# initiale nécessite un appel de fonction (load_history()) plutôt qu'une constante.
_SESSION_STATE_DEFAULTS: Dict[str, Any] = {
    'selected_pcap': None,
    'selected_pcap_name': None,
    'selected_pcap_time': None,
    'analysis_result': None,
    'analysis_folder': None,
    'cicflowmeter_result': None,
    'preprocessing_result': None,
    'classification_result': None,
    'anomaly_result': None,
    'jointure_result': None,
    'pipeline_started': False,
    'pipeline_done': False,
    'pipeline_status': None,
    'pipeline_result_holder': None,
    'home_net_input': '',
    'home_net': None,
}

# Étapes du pipeline affichées dans le stepper de progression. "Jointure" fait à la
# fois la jointure avec les alertes Suricata et le calcul du niveau de risque final
# (voir risk_correlation.correlate_with_suricata) : la seconde n'a aucune utilité
# sans la première, elles sont donc montrées comme une seule étape. "Dashboards" n'a
# pas de traitement asynchrone propre (le rendu est synchrone, dans la page elle-même,
# dès que la jointure a réussi) : son état est donc simplement le miroir de celui de
# la jointure, ajouté comme étape distincte pour que le stepper raconte l'histoire
# complète jusqu'à l'affichage des résultats.
_PIPELINE_STAGE_LABELS: List[str] = [
    "Sélection PCAP", "Analyse Suricata", "Extraction CICFlowMeter",
    "Prétraitement ML", "Classification", "Détection Anomalies", "Jointure", "Dashboards",
]
_STAGE_COLORS = {
    "done": "#16a085",
    "active": "#1E40AF",
    "pending": "#cbd5e1",
    "error": "#c0392b",
}
_STAGE_ICONS = {
    "done": "✓",
    "active": "●",
    "pending": "",
    "error": "✕",
}


def _initialize_session_state() -> None:
    """Initialise les variables de session avec leurs valeurs par défaut."""
    if 'history' not in st.session_state:
        st.session_state['history'] = load_history()

    for key, default_value in _SESSION_STATE_DEFAULTS.items():
        if key not in st.session_state:
            st.session_state[key] = default_value


# Initialiser la session au démarrage
_initialize_session_state()


def _render_step_cards(steps: List[Tuple[str, str, str, str]]) -> None:
    """Affiche les cartes "Comment ça marche" de la page d'accueil : bordure et
    pastille numérotée colorées (une couleur distincte par étape), texte en couleur
    par défaut du thème (pas de texte coloré, pour rester lisible en clair/sombre).

    Args:
        steps: liste de (numéro, titre, description, couleur_hex)
    """
    # Même contrainte que _render_metric_cards (dashboards.py) : HTML construit sur
    # une seule ligne, sans indentation, pour éviter que Streamlit ne l'affiche
    # comme du texte brut (règle Markdown des blocs de code indentés).
    tiles = []
    for num, title, desc, color in steps:
        tiles.append(
            f'<div style="flex:1 1 220px;min-width:220px;background:{color}12;'
            f'border:1.5px solid {color};border-radius:10px;padding:16px 14px;">'
            f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">'
            f'<div style="width:26px;height:26px;border-radius:50%;background:{color};'
            f'color:white;display:flex;align-items:center;justify-content:center;'
            f'font-size:13px;font-weight:700;flex:0 0 auto;">{num}</div>'
            f'<div style="font-weight:700;font-size:14.5px;">{title}</div>'
            f'</div>'
            f'<div style="font-size:12.5px;opacity:0.85;">{desc}</div>'
            f'</div>'
        )
    st.markdown(
        f'<div style="display:flex;gap:12px;flex-wrap:wrap;margin:6px 0 12px 0;">{"".join(tiles)}</div>',
        unsafe_allow_html=True,
    )


# ===== Page: Home =====
def home_page() -> None:
    """Page d'accueil : présentation courte et guide visuel rapide."""
    st.markdown("## Analyseur PCAP — Détection de menaces réseau")
    st.caption("Suricata (IDS) + Machine Learning")

    st.markdown("#### Comment ça marche")
    _render_step_cards([
        ("1", "Sélectionnez", "Un fichier `.pcap` et le réseau du client (HOME_NET).", "#2563eb"),
        ("2", "Analyse automatique", "Suricata, CICFlowMeter, classification, anomalies, fusion — en arrière-plan.", "#8e44ad"),
        ("3", "Dashboards", "Résultats corrélés entre les 3 sources, prêts à l'emploi.", "#16a085"),
    ])

    st.markdown("#### Niveaux de risque")
    _render_metric_cards([
        ("Au moins 2 sources concordent (classifieur, détecteur d'anomalies, alerte Suricata de sévérité 1 ou 2) — à traiter en priorité.", "CRITIQUE", _COLOR_CRITIQUE, None),
        ("Le classifieur ML seul a détecté une menace, avec une confiance suffisante.", "ELEVE", _COLOR_ELEVE, None),
        ("Une seule source isolée : détecteur d'anomalies seul, ou alerte Suricata seule (sévérité 1 ou 2).", "MOYEN", _COLOR_MOYEN, None),
        ("Aucun signal significatif détecté.", "NORMAL", _COLOR_NORMAL, None),
    ])

    st.markdown("---")
    st.info("Prêt ? Direction **Sélection PCAP** dans la barre latérale.")


# ===== Page: Upload and Analysis =====
def upload_page() -> None:
    """Page de sélection et analyse des fichiers PCAP."""
    st.title("Sélection PCAP")

    # Vérifier si un fichier est déjà sélectionné en session
    if st.session_state.get('selected_pcap'):
        file_path = st.session_state['selected_pcap']
        file_size_gb = get_file_size_gb(file_path)

        if not st.session_state.get('pipeline_started') and not st.session_state.get('pipeline_done'):
            _start_pipeline_thread(file_path, file_size_gb)

        _display_selected_pcap()

        # La zone de statut se rafraîchit seule (sans regriser toute la page)
        # tant que l'analyse en arrière-plan n'est pas terminée.
        if not st.session_state.get('pipeline_done'):
            _pipeline_status_fragment()
    else:
        _display_file_selection()


# ===== Page: History =====
def history_page() -> None:
    """Page d'historique des analyses PCAP."""
    st.title("Historique des analyses PCAP")
    st.markdown("---")

    history = load_history()

    if not history:
        st.info("Aucune analyse n'a encore été effectuée.")
        return

    # Filtrer les éléments invalides
    valid_history = [item for item in history if isinstance(item, dict)]

    if not valid_history:
        st.warning("Les données d'historique ne sont pas au bon format. Veuillez réexécuter les analyses.")
        return

    _display_history_statistics(valid_history)
    st.markdown("---")

    # Afficher chaque analyse en carte professionnelle, la plus récente en premier
    for analysis in reversed(valid_history):
        _display_analysis_card(analysis)


def _reset_analysis() -> None:
    """Réinitialise la session pour repartir sur une nouvelle sélection/analyse."""
    for key, default_value in _SESSION_STATE_DEFAULTS.items():
        st.session_state[key] = default_value


def _pipeline_stage_states(result_holder: Optional[Dict[str, Any]]) -> List[str]:
    """Détermine l'état (done/active/pending/error) de chacune des 8 étapes du pipeline.

    Args:
        result_holder: État partagé du thread d'arrière-plan (voir _start_pipeline_thread)

    Returns:
        Liste de 8 états, un par étape (Sélection, Suricata, CICFlowMeter,
        Prétraitement ML, Classification, Détection Anomalies, Jointure, Dashboards)
    """
    if not result_holder or not result_holder.get("suricata_done"):
        return ["done", "active", "pending", "pending", "pending", "pending", "pending", "pending"]

    suricata_ok = result_holder["suricata_result"].get("status") == "success"
    if not suricata_ok:
        return ["done", "error", "pending", "pending", "pending", "pending", "pending", "pending"]

    if not result_holder.get("cicflowmeter_done"):
        return ["done", "done", "active", "pending", "pending", "pending", "pending", "pending"]

    cicflowmeter_result = result_holder.get("cicflowmeter_result")
    cicflowmeter_ok = bool(cicflowmeter_result and cicflowmeter_result.get("status") == "success")
    if not cicflowmeter_ok:
        return ["done", "done", "error", "pending", "pending", "pending", "pending", "pending"]

    if not result_holder.get("preprocessing_done"):
        return ["done", "done", "done", "active", "pending", "pending", "pending", "pending"]

    preprocessing_result = result_holder.get("preprocessing_result")
    preprocessing_ok = bool(preprocessing_result and preprocessing_result.get("status") == "success")
    if not preprocessing_ok:
        return ["done", "done", "done", "error", "pending", "pending", "pending", "pending"]

    if not result_holder.get("classification_done"):
        return ["done", "done", "done", "done", "active", "pending", "pending", "pending"]

    classification_result = result_holder.get("classification_result")
    classification_ok = bool(classification_result and classification_result.get("status") == "success")
    if not classification_ok:
        return ["done", "done", "done", "done", "error", "pending", "pending", "pending"]

    if not result_holder.get("anomaly_done"):
        return ["done", "done", "done", "done", "done", "active", "pending", "pending"]

    anomaly_result = result_holder.get("anomaly_result")
    anomaly_ok = bool(anomaly_result and anomaly_result.get("status") == "success")
    if not anomaly_ok:
        return ["done", "done", "done", "done", "done", "error", "pending", "pending"]

    if not result_holder.get("jointure_done"):
        return ["done", "done", "done", "done", "done", "done", "active", "pending"]

    jointure_result = result_holder.get("jointure_result")
    jointure_ok = bool(jointure_result and jointure_result.get("status") == "success")
    if not jointure_ok:
        return ["done", "done", "done", "done", "done", "done", "error", "pending"]

    # Le rendu des dashboards est synchrone (dans _display_selected_pcap), pas suivi
    # par le thread d'arrière-plan : son état est simplement le miroir de celui de la jointure.
    return ["done", "done", "done", "done", "done", "done", "done", "done"]


def _render_pipeline_progress(stage_states: List[str]) -> None:
    """Affiche un stepper horizontal (cercles + ligne de connexion) montrant la
    progression du pipeline à travers ses 8 étapes.

    Args:
        stage_states: États des 8 étapes, dans l'ordre (voir _pipeline_stage_states)
    """
    circles = []
    for label, state in zip(_PIPELINE_STAGE_LABELS, stage_states):
        color = _STAGE_COLORS[state]
        icon = _STAGE_ICONS[state]
        pulse = "animation: cfm-pulse 1.4s ease-in-out infinite;" if state == "active" else ""
        circles.append(f"""
        <div style="display:flex;flex-direction:column;align-items:center;flex:0 0 auto;">
            <div style="width:32px;height:32px;border-radius:50%;background:{color};color:white;
                        display:flex;align-items:center;justify-content:center;font-size:15px;
                        font-weight:bold;{pulse}">{icon}</div>
            <div style="margin-top:6px;font-size:12px;text-align:center;white-space:nowrap;">{label}</div>
        </div>
        """)

    parts = [circles[0]]
    for i, state in enumerate(stage_states[:-1]):
        line_color = _STAGE_COLORS["done"] if state == "done" else _STAGE_COLORS["pending"]
        parts.append(
            f'<div style="flex:1 1 auto;height:3px;background:{line_color};'
            f'margin:15px 8px 0 8px;"></div>'
        )
        parts.append(circles[i + 1])

    st.markdown(
        f"""
        <style>
        @keyframes cfm-pulse {{
            0% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
            100% {{ opacity: 1; }}
        }}
        </style>
        <div style="display:flex;align-items:flex-start;justify-content:space-between;padding:8px 0 18px 0;">
            {''.join(parts)}
        </div>
        """,
        unsafe_allow_html=True,
    )


def _display_selected_pcap() -> None:
    """Affiche la carte de confirmation du fichier PCAP sélectionné, puis les résultats."""
    file_path = st.session_state['selected_pcap']
    filename = st.session_state.get('selected_pcap_name', os.path.basename(file_path))

    st.success("Fichier PCAP sélectionné avec succès !")

    file_size_gb = get_file_size_gb(file_path)
    selected_time = st.session_state.get('selected_pcap_time') or "-"

    with st.container(border=True):
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown("**Fichier**")
            st.write(filename)
        with col2:
            st.markdown("**Taille**")
            st.write(f"{file_size_gb:.2f} GB")
        with col3:
            st.markdown("**Sélectionné le**")
            st.write(selected_time)

    st.divider()
    st.subheader("Pipeline d'analyse automatique")

    if st.session_state.get('pipeline_done'):
        # Le fragment (voir _pipeline_status_fragment) ne tourne plus une fois le
        # pipeline terminé : le stepper final est donc reconstruit ici, une seule
        # fois, à partir de l'état persisté dans pipeline_result_holder.
        _render_pipeline_progress(_pipeline_stage_states(st.session_state.get('pipeline_result_holder')))

        if st.session_state.get('analysis_result', {}).get('status') == 'success':
            st.success("Pipeline terminé")
        else:
            st.error(
                st.session_state.get('analysis_result', {}).get(
                    'message', "Échec de l'analyse Suricata."
                )
            )

        cicflowmeter_result = st.session_state.get('cicflowmeter_result')
        if cicflowmeter_result is not None and cicflowmeter_result.get('status') != 'success':
            st.warning(
                "Extraction CICFlowMeter : " +
                cicflowmeter_result.get('message', "échec de l'extraction des features de flux.")
            )

        preprocessing_result = st.session_state.get('preprocessing_result')
        if preprocessing_result is not None and preprocessing_result.get('status') != 'success':
            st.warning(
                "Prétraitement ML : " +
                preprocessing_result.get('message', "échec du prétraitement des features.")
            )

        classification_result = st.session_state.get('classification_result')
        if classification_result is not None and classification_result.get('status') != 'success':
            st.warning(
                "Classification : " +
                classification_result.get('message', "échec de la classification.")
            )

        anomaly_result = st.session_state.get('anomaly_result')
        if anomaly_result is not None and anomaly_result.get('status') != 'success':
            st.warning(
                "Détection d'anomalies : " +
                anomaly_result.get('message', "échec de la détection d'anomalies.")
            )

        jointure_result = st.session_state.get('jointure_result')
        if jointure_result is not None and jointure_result.get('status') != 'success':
            st.warning(
                "Jointure : " +
                jointure_result.get(
                    'message', "échec de la jointure avec les alertes Suricata ou du calcul du niveau de risque."
                )
            )

    # Afficher le dashboard de corrélation multi-sources si la jointure a réussi
    # (le CSV final contient déjà tout : classification, anomalie, alertes Suricata,
    # niveau de risque — un seul dashboard, pas un par couche)
    jointure_result = st.session_state.get('jointure_result')
    if jointure_result is not None and jointure_result.get('status') == 'success':
        correlation_df = _load_correlation_data_cached(jointure_result['final_csv'])
        analysis_folder = st.session_state.get('analysis_folder')
        event_type_counts = {}
        if analysis_folder:
            eve_json_path = os.path.join(analysis_folder, "eve.json")
            event_type_counts = _load_event_type_counts_cached(eve_json_path)
        display_correlation_dashboard(correlation_df, event_type_counts)

    if st.session_state.get('pipeline_done'):
        st.button("Analyser de nouveau", on_click=_reset_analysis)


def _display_file_selection() -> None:
    """Affiche le formulaire HOME_NET et le bouton de sélection du fichier PCAP."""
    st.markdown("### Réseau du client")
    st.session_state['home_net_input'] = st.text_input(
        "HOME_NET (réseau interne du client)",
        value=st.session_state['home_net_input'],
        placeholder="ex: 10.0.0.0/8  ou  192.168.1.0/24,172.16.5.0/24  ou  any",
        help="Plage(s) réseau interne du client audité, séparées par des virgules. "
             "Si le réseau du client est inconnu, tapez 'any' (plus sûr qu'une plage devinée). "
             "Laissez vide pour utiliser la valeur par défaut de suricata.yaml."
    )

    home_net_error = _validate_home_net(st.session_state['home_net_input'])
    if home_net_error:
        st.error(f"HOME_NET invalide : {home_net_error}")

    st.markdown("### Sélectionnez un fichier PCAP depuis votre ordinateur")

    if st.button("Choisir un fichier PCAP", disabled=bool(home_net_error)):
        file_path = select_pcap_file()

        if not file_path:
            return

        if not os.path.exists(file_path):
            st.error("Fichier introuvable.")
            logger.warning(f"Fichier sélectionné introuvable: {file_path}")
            return

        if not file_path.lower().endswith(".pcap"):
            st.error("Veuillez sélectionner un fichier .pcap")
            return

        home_net_value = st.session_state['home_net_input'].strip() or None
        for key, default_value in _SESSION_STATE_DEFAULTS.items():
            st.session_state[key] = default_value
        st.session_state['selected_pcap'] = file_path
        st.session_state['selected_pcap_name'] = os.path.basename(file_path)
        st.session_state['selected_pcap_time'] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        st.session_state['home_net'] = home_net_value

        st.success("Fichier sélectionné avec succès !")
        st.rerun()


def _cleanup_intermediate_outputs(
    cicflowmeter_result: Optional[Dict[str, Any]],
    preprocessing_result: Optional[Dict[str, Any]],
    classification_result: Optional[Dict[str, Any]],
    jointure_result: Optional[Dict[str, Any]],
) -> None:
    """Supprime les CSV intermédiaires une fois le pipeline terminé avec succès :
    seul le CSV final (_final.csv, toutes les colonnes ajoutées par le pipeline)
    est conservé sur disque. Chaque étape enrichit une copie du CSV précédent, donc
    aucun des intermédiaires (_Flow.csv brut, _clean.csv, _ml_ready.csv,
    _predicted.csv, _unified.csv) n'apporte plus d'information une fois le CSV
    final produit — les garder tous ne ferait qu'accumuler des Go redondants par analyse.
    """
    paths_to_remove = []
    if cicflowmeter_result:
        paths_to_remove.append(cicflowmeter_result.get("csv_file"))
    if preprocessing_result:
        paths_to_remove.append(preprocessing_result.get("clean_csv"))
        paths_to_remove.append(preprocessing_result.get("ml_ready_csv"))
    if classification_result:
        paths_to_remove.append(classification_result.get("predicted_csv"))
    unification_result = (jointure_result or {}).get("unification_result")
    if unification_result:
        paths_to_remove.append(unification_result.get("unified_csv"))

    removed = 0
    for path in paths_to_remove:
        if path and os.path.exists(path):
            try:
                os.remove(path)
                removed += 1
            except OSError as e:
                logger.warning(f"Impossible de supprimer le fichier intermédiaire {path}: {e}")

    if removed:
        logger.info(f"{removed} fichier(s) CSV intermédiaire(s) supprimé(s) — seul le CSV final est conservé.")


def _start_pipeline_thread(file_path: str, file_size_gb: float) -> None:
    """Démarre le pipeline d'analyse complet (Suricata, CICFlowMeter, prétraitement,
    classification, détection d'anomalies, jointure) dans un thread en arrière-plan.

    L'objectif est de ne pas bloquer le script Streamlit (et donc ne pas griser
    toute la page) pendant les plusieurs minutes que peut durer l'analyse d'un
    gros fichier PCAP. La carte de confirmation reste affichée normalement,
    seule une petite zone de statut (voir _pipeline_status_fragment) se
    rafraîchit périodiquement. CICFlowMeter n'est lancé que si Suricata a réussi
    (inutile d'extraire des features de flux d'un PCAP que Suricata n'a pas pu lire),
    le prétraitement ML n'est lancé que si CICFlowMeter a réussi (inutile de
    prétraiter un CSV qui n'existe pas), la classification n'est lancée que si le
    prétraitement a réussi (même raison), la détection d'anomalies n'est lancée
    que si la classification a réussi (elle enrichit le CSV que la classification
    produit), et la jointure (jointure avec les alertes Suricata puis calcul du
    niveau de risque final, voir risk_correlation.correlate_with_suricata) n'est
    lancée que si la détection d'anomalies a réussi (elle enrichit ce même CSV).
    """
    home_net = st.session_state.get('home_net')
    result_holder: Dict[str, Any] = {
        "suricata_done": False,
        "suricata_result": None,
        "cicflowmeter_done": False,
        "cicflowmeter_result": None,
        "preprocessing_done": False,
        "preprocessing_result": None,
        "classification_done": False,
        "classification_result": None,
        "anomaly_done": False,
        "anomaly_result": None,
        "jointure_done": False,
        "jointure_result": None,
        "pipeline_done": False,
    }
    st.session_state['pipeline_result_holder'] = result_holder
    st.session_state['pipeline_started'] = True
    st.session_state['pipeline_status'] = "Analyse Suricata en cours..."

    def _worker() -> None:
        logger.info(f"Démarrage de l'analyse Suricata: {file_path} (HOME_NET={home_net or 'défaut'})")
        try:
            suricata_result = run_suricata_analysis(file_path, home_net=home_net)
        except Exception as e:
            logger.error(f"Erreur inattendue pendant l'analyse Suricata: {e}")
            suricata_result = {"status": "error", "message": f"Erreur inattendue: {e}", "analysis_folder": None}

        result_holder["suricata_result"] = suricata_result
        result_holder["suricata_done"] = True

        cicflowmeter_result = None
        if suricata_result["status"] == "success":
            analysis_folder = suricata_result["analysis_folder"]
            logger.info(f"Démarrage de l'extraction CICFlowMeter: {file_path}")
            try:
                cicflowmeter_result = run_cicflowmeter_analysis(file_path, analysis_folder)
            except Exception as e:
                logger.error(f"Erreur inattendue pendant l'extraction CICFlowMeter: {e}")
                cicflowmeter_result = {"status": "error", "message": f"Erreur inattendue: {e}", "csv_file": None}

        result_holder["cicflowmeter_result"] = cicflowmeter_result
        result_holder["cicflowmeter_done"] = True

        preprocessing_result = None
        if cicflowmeter_result and cicflowmeter_result.get("status") == "success":
            csv_file = cicflowmeter_result.get("csv_file")
            logger.info(f"Démarrage du prétraitement ML: {csv_file}")
            try:
                preprocessing_result = preprocess_cicflowmeter_csv(csv_file, analysis_folder)
            except Exception as e:
                logger.error(f"Erreur inattendue pendant le prétraitement ML: {e}")
                preprocessing_result = {"status": "error", "message": f"Erreur inattendue: {e}"}

        result_holder["preprocessing_result"] = preprocessing_result
        result_holder["preprocessing_done"] = True

        classification_result = None
        if preprocessing_result and preprocessing_result.get("status") == "success":
            csv_file = cicflowmeter_result.get("csv_file")
            logger.info(f"Démarrage de la classification: {csv_file}")
            try:
                classification_result = classify_cicflowmeter_csv(csv_file, analysis_folder)
            except Exception as e:
                logger.error(f"Erreur inattendue pendant la classification: {e}")
                classification_result = {"status": "error", "message": f"Erreur inattendue: {e}"}

        result_holder["classification_result"] = classification_result
        result_holder["classification_done"] = True

        anomaly_result = None
        if classification_result and classification_result.get("status") == "success":
            csv_file = cicflowmeter_result.get("csv_file")
            logger.info(f"Démarrage de la détection d'anomalies: {csv_file}")
            try:
                anomaly_result = detect_anomalies_cicflowmeter_csv(csv_file, analysis_folder)
            except Exception as e:
                logger.error(f"Erreur inattendue pendant la détection d'anomalies: {e}")
                anomaly_result = {"status": "error", "message": f"Erreur inattendue: {e}"}

        result_holder["anomaly_result"] = anomaly_result
        result_holder["anomaly_done"] = True

        jointure_result = None
        if anomaly_result and anomaly_result.get("status") == "success":
            predicted_csv = anomaly_result.get("predicted_csv")
            eve_json_path = os.path.join(analysis_folder, "eve.json")
            logger.info(f"Démarrage de la jointure (Suricata + niveau de risque): {predicted_csv}")
            try:
                jointure_result = correlate_with_suricata(predicted_csv, eve_json_path, analysis_folder)
            except Exception as e:
                logger.error(f"Erreur inattendue pendant la jointure: {e}")
                jointure_result = {"status": "error", "message": f"Erreur inattendue: {e}"}

        result_holder["jointure_result"] = jointure_result
        result_holder["jointure_done"] = True

        if jointure_result and jointure_result.get("status") == "success":
            _cleanup_intermediate_outputs(
                cicflowmeter_result, preprocessing_result, classification_result, jointure_result
            )

        if suricata_result["status"] == "success":
            save_analysis_to_history(
                file_path, suricata_result, file_size_gb,
                cicflowmeter_result, preprocessing_result, classification_result, anomaly_result,
                jointure_result,
            )

        result_holder["pipeline_done"] = True

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()


@st.fragment(run_every=2)
def _pipeline_status_fragment() -> None:
    """Zone de statut (stepper + message) qui se rafraîchit seule (sans reruns/grisage
    global) pendant que le pipeline tourne en arrière-plan, jusqu'à ce qu'il ait fini.
    """
    result_holder = st.session_state.get('pipeline_result_holder')
    if not result_holder:
        return

    stage_states = _pipeline_stage_states(result_holder)
    _render_pipeline_progress(stage_states)

    if not result_holder.get("pipeline_done"):
        if not result_holder.get("suricata_done"):
            st.info("Analyse Suricata en cours... Cela peut prendre plusieurs minutes selon la taille du fichier.")
        elif not result_holder.get("cicflowmeter_done"):
            st.info("Extraction des features de flux (CICFlowMeter) en cours...")
        elif not result_holder.get("preprocessing_done"):
            st.info("Prétraitement des features pour le ML en cours...")
        elif not result_holder.get("classification_done"):
            st.info("Classification en cours...")
        elif not result_holder.get("anomaly_done"):
            st.info("Détection d'anomalies en cours...")
        else:
            st.info("Jointure avec les alertes Suricata et calcul du niveau de risque en cours...")
        return

    suricata_result = result_holder["suricata_result"]
    st.session_state['analysis_result'] = suricata_result
    st.session_state['cicflowmeter_result'] = result_holder.get("cicflowmeter_result")
    st.session_state['preprocessing_result'] = result_holder.get("preprocessing_result")
    st.session_state['classification_result'] = result_holder.get("classification_result")
    st.session_state['anomaly_result'] = result_holder.get("anomaly_result")
    st.session_state['jointure_result'] = result_holder.get("jointure_result")
    if suricata_result["status"] == "success":
        st.session_state['analysis_folder'] = suricata_result['analysis_folder']
        st.session_state['pipeline_status'] = "Pipeline terminé"
    else:
        st.session_state['pipeline_status'] = "Échec de l'analyse Suricata"
    st.session_state['pipeline_done'] = True

    # Rerun complet unique pour afficher les dashboards / le message d'erreur
    # dans _display_selected_pcap (en dehors de ce fragment).
    st.rerun()


# ===== Main App Configuration =====
def main() -> None:
    """Point d'entrée principal de l'application."""
    st.set_page_config(
        page_title="PCAP Analyzer",
        layout="wide",
        initial_sidebar_state="expanded"
    )

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
