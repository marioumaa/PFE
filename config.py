"""Configuration centralisée du projet."""

import os
from pathlib import Path
from typing import Dict, List

# Chemins
PROJECT_ROOT = Path(__file__).parent
OUTPUTS_DIR = PROJECT_ROOT / "outputs"
HISTORY_FILE = PROJECT_ROOT / "pcap_history.json"

# Créer les répertoires s'ils n'existent pas
OUTPUTS_DIR.mkdir(exist_ok=True)

# Configuration Suricata
SURICATA_TIMEOUT = 600  # 10 minutes
SURICATA_PATHS = [
    r"C:\Program Files\Suricata\suricata.exe",
    "suricata"
]


# Configuration des fichiers
SURICATA_OUTPUT_FILES = {
    "eve.json": "Logs d'événements (alertes, flows, etc)",
    "suricata.log": "Fichier log principal de Suricata",
    "stats.log": "Statistiques de traitement",
    "fast.log": "Alertes en format rapide"
}


# Configuration JSON
JSON_INDENT = 2
JSON_ENSURE_ASCII = False

# Encoding
DEFAULT_ENCODING = "utf-8"
