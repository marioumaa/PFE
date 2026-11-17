"""Analyseur Suricata - Analyse de trafic réseau PCAP."""

import subprocess
import os
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional
from config import OUTPUTS_DIR, SURICATA_DIR, SURICATA_TIMEOUT, SURICATA_PATHS, SURICATA_CONFIG_FILE
from logger import setup_logging
from utils import file_exists

logger = setup_logging(__name__)


def _find_suricata_executable() -> Optional[str]:
    """Trouve l'exécutable Suricata.

    Returns:
        Chemin de Suricata, None si non trouvé
    """
    for path in SURICATA_PATHS:
        if file_exists(path):
            logger.info(f"Suricata trouvé: {path}")
            return path
    logger.error("Suricata n'a pas été trouvé dans les chemins configurés")
    return None


def run_suricata_analysis(pcap_path: str, home_net: Optional[str] = None) -> Dict[str, Any]:
    """Exécute Suricata sur un fichier PCAP.

    Args:
        pcap_path: Chemin complet du fichier PCAP
        home_net: Plage(s) réseau interne du client audité (ex: "10.0.0.0/8" ou
            "192.168.1.0/24,172.16.5.0/24"). Si None, utilise la valeur par
            défaut définie dans suricata.yaml.

    Returns:
        Dictionnaire avec statut et infos de l'analyse
    """
    try:
        # Validation
        if not file_exists(pcap_path):
            return {
                "status": "error",
                "message": f"[ERREUR] Fichier PCAP non trouvé: {pcap_path}",
                "analysis_folder": None
            }

        # Créer un dossier unique pour cette analyse : <nom_pcap>_<horodatage>.
        # L'horodatage garantit l'unicité (plusieurs analyses du même PCAP ne
        # s'écrasent jamais) et sert de trace d'audit (quand l'analyse a été lancée).
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename_only = Path(pcap_path).stem
        analysis_folder = os.path.join(str(OUTPUTS_DIR), f"{filename_only}_{timestamp}")

        Path(analysis_folder).mkdir(parents=True, exist_ok=True)
        logger.info(f"Dossier d'analyse créé: {analysis_folder}")

        # Trouver Suricata
        suricata_path = _find_suricata_executable()
        if not suricata_path:
            return {
                "status": "error",
                "message": "[ERREUR] Suricata n'a pas été trouvé. Assurez-vous qu'il est installé.",
                "analysis_folder": None
            }

        # Construire et exécuter la commande
        cmd = [suricata_path, "-c", SURICATA_CONFIG_FILE, "-r", pcap_path, "-l", analysis_folder]
        if home_net:
            if home_net.strip().lower() == "any":
                # Réseau inconnu : HOME_NET et EXTERNAL_NET doivent être réglés
                # ensemble, sinon EXTERNAL_NET (défini comme "!$HOME_NET" dans
                # suricata.yaml) devient "!any" = ne correspond plus à rien.
                cmd.extend(["--set", "vars.address-groups.HOME_NET=any"])
                cmd.extend(["--set", "vars.address-groups.EXTERNAL_NET=any"])
            else:
                cmd.extend(["--set", f"vars.address-groups.HOME_NET=[{home_net}]"])
        logger.info(f"Exécution: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=SURICATA_TIMEOUT,
            cwd=str(SURICATA_DIR),
        )

        if result.returncode == 0:
            logger.info("Analyse Suricata complétée avec succès")
            return {
                "status": "success",
                "message": "[OK] Analyse Suricata complétée avec succès !",
                "analysis_folder": analysis_folder,
                "output": result.stdout,
                "timestamp": timestamp,
                "pcap_name": filename_only,
                "home_net_used": home_net or "Défaut (suricata.yaml)"
            }
        else:
            error_msg = result.stderr if result.stderr else result.stdout
            logger.error(f"Erreur Suricata (code {result.returncode}): {error_msg[:200]}")
            return {
                "status": "error",
                "message": f"[ERREUR] Erreur Suricata (code {result.returncode}): {error_msg[:200]}",
                "output": error_msg,
                "analysis_folder": None
            }

    except subprocess.TimeoutExpired:
        timeout_minutes = SURICATA_TIMEOUT // 60
        logger.error(f"L'analyse a dépassé le timeout de {timeout_minutes} minutes")
        return {
            "status": "error",
            "message": f"[ERREUR] L'analyse a dépassé le délai imparti ({timeout_minutes} minutes)",
            "analysis_folder": None
        }
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse: {e}")
        return {
            "status": "error",
            "message": f"[ERREUR] Erreur: {str(e)}",
            "analysis_folder": None
        }
