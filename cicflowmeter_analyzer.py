"""Analyseur CICFlowMeter - Extraction de features de flux réseau (pcap -> csv)."""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from config import (
    CICFLOWMETER_JAR,
    CICFLOWMETER_LOG4J_CONFIG,
    CICFLOWMETER_MAIN_CLASS,
    CICFLOWMETER_NATIVE_DIR,
    CICFLOWMETER_TIMEOUT,
)
from logger import setup_logging
from utils import file_exists

logger = setup_logging(__name__)


def _find_java_executable() -> Optional[str]:
    """Trouve l'exécutable Java (java) sur le système.

    Returns:
        Chemin de l'exécutable java, None si non trouvé
    """
    java_path = shutil.which("java")
    if java_path:
        logger.info(f"Java trouvé: {java_path}")
        return java_path
    logger.error("Java n'a pas été trouvé dans le PATH système")
    return None


def run_cicflowmeter_analysis(pcap_path: str, output_folder: str) -> Dict[str, Any]:
    """Exécute CICFlowMeter sur un fichier PCAP pour extraire les features de flux en CSV.

    Args:
        pcap_path: Chemin complet du fichier PCAP (le même que celui analysé par Suricata)
        output_folder: Dossier où écrire le CSV (le dossier d'analyse Suricata, pour que
            tous les fichiers d'une même analyse restent regroupés ensemble)

    Returns:
        Dictionnaire avec statut et infos de l'extraction
    """
    try:
        if not file_exists(pcap_path):
            return {
                "status": "error",
                "message": f"[ERREUR] Fichier PCAP non trouvé: {pcap_path}",
                "csv_file": None,
            }

        if not file_exists(CICFLOWMETER_JAR):
            logger.error(f"Jar CICFlowMeter non trouvé: {CICFLOWMETER_JAR}")
            return {
                "status": "error",
                "message": "[ERREUR] CICFlowMeter n'a pas été trouvé (jar manquant). Assurez-vous qu'il est installé.",
                "csv_file": None,
            }

        java_path = _find_java_executable()
        if not java_path:
            return {
                "status": "error",
                "message": "[ERREUR] Java n'a pas été trouvé. Assurez-vous qu'un JDK/JRE est installé.",
                "csv_file": None,
            }

        Path(output_folder).mkdir(parents=True, exist_ok=True)

        cmd = [
            java_path,
            f"-Djava.library.path={CICFLOWMETER_NATIVE_DIR}",
            f"-Dlog4j.configuration={CICFLOWMETER_LOG4J_CONFIG}",
            "-cp", CICFLOWMETER_JAR,
            CICFLOWMETER_MAIN_CLASS,
            pcap_path,
            output_folder,
        ]
        logger.info(f"Exécution: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=CICFLOWMETER_TIMEOUT,
        )

        # CICFlowMeter nomme systématiquement le CSV <nom_du_pcap_avec_extension>_Flow.csv.
        # Le code de retour de Cmd.java vaut 0 même sur certains échecs "logiques" (ex: argument
        # invalide) : la présence réelle du CSV est donc le signal fiable de succès, pas juste returncode.
        csv_filename = os.path.basename(pcap_path) + "_Flow.csv"
        csv_file = os.path.join(output_folder, csv_filename)

        if result.returncode == 0 and file_exists(csv_file):
            logger.info(f"Extraction CICFlowMeter complétée avec succès: {csv_file}")
            return {
                "status": "success",
                "message": "[OK] Extraction CICFlowMeter complétée avec succès !",
                "csv_file": csv_file,
                "output": result.stdout,
            }

        error_msg = result.stderr if result.stderr else result.stdout
        logger.error(f"Erreur CICFlowMeter (code {result.returncode}): {error_msg[:200]}")
        return {
            "status": "error",
            "message": f"[ERREUR] Erreur CICFlowMeter (code {result.returncode}): {error_msg[:200]}",
            "csv_file": None,
            "output": error_msg,
        }

    except subprocess.TimeoutExpired:
        timeout_minutes = CICFLOWMETER_TIMEOUT // 60
        logger.error(f"L'extraction CICFlowMeter a dépassé le timeout de {timeout_minutes} minutes")
        return {
            "status": "error",
            "message": f"[ERREUR] L'extraction CICFlowMeter a dépassé le délai imparti ({timeout_minutes} minutes)",
            "csv_file": None,
        }
    except Exception as e:
        logger.error(f"Erreur lors de l'extraction CICFlowMeter: {e}")
        return {
            "status": "error",
            "message": f"[ERREUR] Erreur: {str(e)}",
            "csv_file": None,
        }
