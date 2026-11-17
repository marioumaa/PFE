"""Configuration centralisée du projet."""

from pathlib import Path

# Chemins (relatifs à la racine du projet, portables d'un poste à l'autre)
PROJECT_ROOT = Path(__file__).parent
OUTPUTS_DIR = PROJECT_ROOT / "outputs"
SURICATA_DIR = PROJECT_ROOT / "Suricata"
HISTORY_FILE = PROJECT_ROOT / "pcap_history.json"

# Créer les répertoires s'ils n'existent pas
OUTPUTS_DIR.mkdir(exist_ok=True)

# Configuration Suricata
SURICATA_TIMEOUT = 1200  # 20 minutes
SURICATA_PATHS = [
    str(SURICATA_DIR / "suricata.exe"),
    "suricata",  # repli sur le PATH système si l'exécutable local est absent
]
SURICATA_CONFIG_FILE = str(SURICATA_DIR / "suricata.yaml")

# Dossier de cache MPM (sgh-mpm-caching-path dans suricata.yaml) : le créer à
# l'avance évite que Suricata saute silencieusement la mise en cache si le
# dossier n'existe pas encore sur un poste tout juste installé.
(SURICATA_DIR / "cache" / "sgh").mkdir(parents=True, exist_ok=True)

# Configuration CICFlowMeter (extraction de features de flux réseau, pcap -> csv)
CICFLOWMETER_DIR = PROJECT_ROOT / "CICFlowMeter-master"
CICFLOWMETER_JAR = str(CICFLOWMETER_DIR / "target" / "CICFlowMeterV3-0.0.4-SNAPSHOT.jar")
CICFLOWMETER_NATIVE_DIR = str(CICFLOWMETER_DIR / "jnetpcap" / "win" / "jnetpcap-1.4.r1425")
CICFLOWMETER_MAIN_CLASS = "cic.cs.unb.ca.ifm.Cmd"
CICFLOWMETER_TIMEOUT = 1200  # 20 minutes, comme Suricata

# Configuration log4j "silencieuse" : le log4j.properties embarqué dans le jar
# CICFlowMeter écrit par défaut des logs de debug illimités (jusqu'à 5 Go) dans un
# dossier logs/ créé relativement au répertoire de travail du process Python. On la
# remplace par une config minimale (console uniquement) via -Dlog4j.configuration.
CICFLOWMETER_LOG4J_CONFIG = (CICFLOWMETER_DIR / "log4j-quiet.properties").as_uri()

# Dossier des modèles ML
MODELS_DIR = PROJECT_ROOT / "models"

# Modèle de classification ML (Random Forest entraîné sur les features CICFlowMeter)
CLASSIFIER_MODEL_PATH = str(MODELS_DIR / "classifieur_rf_v2.joblib")

# Modèle de détection d'anomalies non-supervisé (Isolation Forest), en complément du
# classifieur : {"model", "features", "seuil", "fpr"}
ANOMALY_MODEL_PATH = str(MODELS_DIR / "anomaly_isolation_forest_v2.joblib")

# Configuration JSON
JSON_INDENT = 2
JSON_ENSURE_ASCII = False

# Encoding
DEFAULT_ENCODING = "utf-8"
