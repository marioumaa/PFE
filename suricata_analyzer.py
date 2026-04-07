"""Analyseur Suricata - Analyse de trafic réseau PCAP."""

import json
import subprocess
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from config import SURICATA_TIMEOUT, SURICATA_PATHS, SURICATA_OUTPUT_FILES
from logger import setup_logging
from utils import file_exists, get_file_size_kb, save_json_file

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


def run_suricata_analysis(pcap_path: str) -> Dict[str, Any]:
    """Exécute Suricata sur un fichier PCAP.
    
    Args:
        pcap_path: Chemin complet du fichier PCAP
        output_base_dir: Dossier de base pour les résultats
    
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
        
        # Créer un dossier unique pour cette analyse
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename_only = Path(pcap_path).stem
        analysis_folder = os.path.join("outputs", f"{filename_only}_{timestamp}")
        
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
        cmd = [suricata_path, "-r", pcap_path, "-l", analysis_folder]
        logger.info(f"Exécution: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SURICATA_TIMEOUT
        )
        
        if result.returncode == 0:
            logger.info("Analyse Suricata complétée avec succès")
            return {
                "status": "success",
                "message": "[OK] Analyse Suricata complétée avec succès !",
                "analysis_folder": analysis_folder,
                "output": result.stdout,
                "timestamp": timestamp,
                "pcap_name": filename_only
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
        logger.error("L'analyse a dépassé le timeout")
        return {
            "status": "error",
            "message": "[ERREUR] L'analyse a dépassé le délai imparti (10 minutes)",
            "analysis_folder": None
        }
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse: {e}")
        return {
            "status": "error",
            "message": f"[ERREUR] Erreur: {str(e)}",
            "analysis_folder": None
        }


def parse_eve_alerts(analysis_folder: str) -> Dict[str, Any]:
    """Parse le fichier eve.json généré par Suricata.
    
    Args:
        analysis_folder: Dossier contenant les fichiers d'analyse
    
    Returns:
        Dictionnaire avec alertes parsées et statistiques
    """
    try:
        eve_file = os.path.join(analysis_folder, "eve.json")
        
        if not file_exists(eve_file):
            logger.warning(f"Fichier eve.json non trouvé: {eve_file}")
            return {
                "status": "error",
                "message": "[ATTENTION] Fichier eve.json non trouvé",
                "alert_count": 0,
                "event_types": {},
                "alert_categories": {},
                "total_events": 0
            }
        
        
        event_types: Dict[str, int] = {}
        alert_categories: Dict[str, int] = {}
        alert_count = 0
        
        # Lire le fichier eve.json ligne par ligne (format JSON Lines)
        with open(eve_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    event = json.loads(line)
                    event_type = event.get("event_type", "unknown")
                    event_types[event_type] = event_types.get(event_type, 0) + 1
                    
                    # Extraire les alertes
                    if event_type == "alert":
                        alert_count += 1
                        category = event.get("alert", {}).get("category", "Unknown")
                        alert_categories[category] = alert_categories.get(category, 0) + 1
                        
    
                            
                except json.JSONDecodeError:
                    logger.debug(f"Erreur JSON à la ligne {line_num}, fichier ignorée")
                    continue
        
        logger.info(f"Eve.json parsé: {alert_count} alertes, {sum(event_types.values())} événements")
        return {
            "status": "success",
            "alert_count": alert_count,
            "event_types": event_types,
            "alert_categories": alert_categories,
            "total_events": sum(event_types.values())
        }
        
    except Exception as e:
        logger.error(f"Erreur lors de la lecture de eve.json: {e}")
        return {
            "status": "error",
            "message": f"Erreur lors de la lecture du fichier eve.json: {str(e)}",
            "alert_count": 0,
            "event_types": {},
            "alert_categories": {},
            "total_events": 0
        }


def get_analysis_summary(analysis_folder: str) -> Dict[str, Any]:
    """Obtient un résumé des fichiers générés par Suricata.
    
    Args:
        analysis_folder: Dossier contenant les fichiers d'analyse
    
    Returns:
        Dictionnaire avec infos sur les fichiers générés
    """
    try:
        files_info = {}
        
        for filename, description in SURICATA_OUTPUT_FILES.items():
            filepath = os.path.join(analysis_folder, filename)
            
            if file_exists(filepath):
                file_size_kb = get_file_size_kb(filepath)
                files_info[filename] = {
                    "found": True,
                    "size_kb": file_size_kb,
                    "description": description
                }
            else:
                files_info[filename] = {
                    "found": False,
                    "description": description
                }
        
        logger.info(f"Résumé des fichiers: {analysis_folder}")
        return {
            "status": "success",
            "files": files_info,
            "folder_path": analysis_folder
        }
        
    except Exception as e:
        logger.error(f"Erreur lors de la lecture du dossier d'analyse: {e}")
        return {
            "status": "error",
            "message": f"Erreur lors de la lecture du dossier: {str(e)}",
            "files": {}
        }
