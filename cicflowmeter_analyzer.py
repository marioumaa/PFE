"""
Module CICFlowMeter - Gestion de l'extraction des flows réseau
"""
import os
import subprocess
import logging
import shutil
from pathlib import Path
from typing import Dict, Any, Optional
from config import CICFLOWMETER_PATH, CICFLOWMETER_TIMEOUT, CICFLOWMETER_COMMAND

logger = logging.getLogger(__name__)


def _find_mvn_executable() -> Optional[str]:
    """Trouve l'exécutable Maven (mvn) sur le système.

    Returns:
        Chemin complet de l'exécutable mvn, ou None si non trouvé
    """
    # Vérifier si un chemin spécifique est configuré
    if CICFLOWMETER_COMMAND and len(CICFLOWMETER_COMMAND) > 0:
        if os.path.isabs(CICFLOWMETER_COMMAND[0]):
            if os.path.exists(CICFLOWMETER_COMMAND[0]):
                return CICFLOWMETER_COMMAND[0]

    # Recherche automatique de mvn sous Windows et Linux/Mac
    candidates = [CICFLOWMETER_COMMAND[0]] if CICFLOWMETER_COMMAND and len(CICFLOWMETER_COMMAND) > 0 else ["mvn"]
    if os.name == "nt":
        candidates += ["mvn.cmd", "mvn.bat"]

    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            logger.info(f"Maven trouvé: {path}")
            return path

    logger.error("Maven (mvn) non trouvé dans le PATH")
    return None


def run_cicflowmeter_analysis(pcap_path: str, output_folder: str) -> Dict[str, Any]:
    """Exécute CICFlowMeter sur un fichier PCAP pour extraire les flows.

    Args:
        pcap_path: Chemin complet du fichier PCAP
        output_folder: Dossier de sortie pour le fichier CSV (dossier d'analyse Suricata)

    Returns:
        Dictionnaire avec statut et infos de l'extraction
    """
    try:
        # Validation
        if not os.path.exists(pcap_path):
            return {
                "status": "error",
                "message": f"Fichier PCAP non trouvé: {pcap_path}"
            }

        if not os.path.exists(output_folder):
            Path(output_folder).mkdir(parents=True, exist_ok=True)
            logger.info(f"Dossier de sortie créé: {output_folder}")

        # Vérifier que CICFlowMeter existe
        if not os.path.exists(CICFLOWMETER_PATH):
            return {
                "status": "error",
                "message": f"CICFlowMeter non trouvé dans: {CICFLOWMETER_PATH}"
            }

        # Trouver Maven
        mvn_executable = _find_mvn_executable()
        if not mvn_executable:
            return {
                "status": "error",
                "message": "Maven (mvn) introuvable. Verifiez que Maven est installe et accessible depuis le PATH."
            }

        # Construire le chemin du fichier CSV de sortie
        output_csv = os.path.join(output_folder, "flows.csv")
        
        # Utiliser les chemins absolus
        pcap_abs = os.path.abspath(pcap_path)
        output_abs = os.path.abspath(output_csv)

        # Construire la commande CICFlowMeter
        # Format: mvn exec:java -Dexec.mainClass="cic.cs.unb.ca.ifm.Cmd" -Dexec.args="path_pcap path_output"
        cmd = f'"{mvn_executable}" exec:java -Dexec.mainClass="cic.cs.unb.ca.ifm.Cmd" -Dexec.args="{pcap_abs} {output_abs}"'

        logger.info(f"Execution CICFlowMeter: {cmd}")
        logger.info(f"Dossier courant: {CICFLOWMETER_PATH}")

        # Exécuter la commande
        result = subprocess.run(
            cmd,
            cwd=CICFLOWMETER_PATH,
            shell=True,
            capture_output=True,
            text=True,
            timeout=CICFLOWMETER_TIMEOUT
        )

        # Attendre un peu pour que le fichier soit complètement écrit
        import time
        time.sleep(1)

        # Vérifier que le fichier CSV a été généré
        if os.path.exists(output_csv):
            file_size = os.path.getsize(output_csv)
            logger.info(f"Extraction CICFlowMeter completee avec succes (taille: {file_size} bytes)")
            
            return {
                "status": "success",
                "message": "Extraction des flows completee avec succes",
                "output_csv": output_csv,
                "file_size": file_size,
                "returncode": result.returncode
            }
        else:
            error_msg = result.stderr if result.stderr else result.stdout
            logger.error(f"Erreur CICFlowMeter: Fichier CSV non genere. Code retour: {result.returncode}")
            logger.error(f"Sortie: {error_msg[:500]}")
            
            return {
                "status": "error",
                "message": f"Le fichier CSV n'a pas pu etre genere. Verifiez que CICFlowMeter est correctement installe.",
                "output": error_msg[:500],
                "returncode": result.returncode
            }

    except subprocess.TimeoutExpired:
        logger.error("L'extraction CICFlowMeter a depasse le timeout")
        return {
            "status": "error",
            "message": "L'extraction a depasse le delai imparti (10 minutes)"
        }
    except Exception as e:
        logger.error(f"Erreur lors de l'extraction CICFlowMeter: {e}")
        return {
            "status": "error",
            "message": f"Erreur: {str(e)}"
        }