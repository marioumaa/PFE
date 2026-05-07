"""
Module CICFlowMeter - Gestion de l'extraction des flows réseau
"""
import os
import subprocess
import logging
import shutil
import pandas as pd
import numpy as np
import pickle
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from config import CICFLOWMETER_PATH, CICFLOWMETER_TIMEOUT, ML_MODEL_PATH, CICFLOWMETER_COMMAND

logger = logging.getLogger(__name__)


def _find_mvn_executable() -> Optional[str]:
    """Trouve l'exécutable Maven (mvn) sur le système.

    Returns:
        Chemin complet de l'exécutable mvn, ou None si non trouvé
    """
    candidates = []

    if CICFLOWMETER_COMMAND and len(CICFLOWMETER_COMMAND) > 0:
        candidates.append(CICFLOWMETER_COMMAND[0])

    if os.name == "nt":
        if "mvn" not in candidates:
            candidates.extend(["mvn", "mvn.cmd", "mvn.bat"])
    else:
        if "mvn" not in candidates:
            candidates.append("mvn")

    for candidate in candidates:
        if os.path.isabs(candidate) and os.path.exists(candidate):
            logger.info(f"Maven trouvé: {candidate}")
            return candidate
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
      
        
        # Utiliser les chemins absolus
        pcap_abs = os.path.abspath(pcap_path)
        output_abs = os.path.abspath(output_folder)

        # Construire la commande CICFlowMeter
        cmd = [
            mvn_executable,
            "exec:java",
            "-Dexec.mainClass=cic.cs.unb.ca.ifm.Cmd",
            f"-Dexec.args={pcap_abs} {output_abs}"
        ]

        logger.info(f"Execution CICFlowMeter: {' '.join(cmd)}")
        logger.info(f"Dossier courant: {CICFLOWMETER_PATH}")

        # Exécuter la commande
        result = subprocess.run(
            cmd,
            cwd=CICFLOWMETER_PATH,
            capture_output=True,
            text=True,
            timeout=CICFLOWMETER_TIMEOUT
        )

        # Attendre un peu pour que le fichier soit complètement écrit
        import time
        time.sleep(3)

        # Chercher spécifiquement le fichier attendu
        pcap_filename = os.path.basename(pcap_path)
        expected_csv = f"{pcap_filename}_Flow.csv"
        output_csv_pattern = os.path.join(output_folder, expected_csv)

        if os.path.exists(output_csv_pattern):
            logger.info(f"Fichier CSV trouvé: {output_csv_pattern}")
        else:
            # Chercher un fichier alternatif dans le dossier de sortie si le nom exact diffère
            alternative = None
            for candidate in Path(output_folder).glob(f"{pcap_filename}*_Flow.csv"):
                alternative = str(candidate)
                break
            # aussi rechercher sans ajout supplémentaire au cas où le nom serait déjà exact
            if not alternative:
                for candidate in Path(output_folder).glob(f"*{pcap_filename}_Flow.csv"):
                    alternative = str(candidate)
                    break

            if alternative:
                output_csv_pattern = alternative
                logger.info(f"Fichier CSV trouvé via recherche alternative: {output_csv_pattern}")
            else:
                logger.warning(f"Fichier CSV attendu non trouvé: {output_csv_pattern}")

        if os.path.exists(output_csv_pattern):
            # Traiter le CSV et appliquer le modèle ML
            model_path = ML_MODEL_PATH
            logger.info(f"Demarrage du traitement ML avec le modèle: {model_path}")
            print(f"DEBUG: Avant appel process_and_predict_csv - csv: {output_csv_pattern}, model: {model_path}")
            ml_result = process_and_predict_csv(output_csv_pattern, model_path)
            print(f"DEBUG: Après appel process_and_predict_csv - result status: {ml_result.get('status') if ml_result else 'None'}")
            logger.info(f"Traitement ML terminé avec status: {ml_result.get('status', 'unknown')}")

            file_size = os.path.getsize(output_csv_pattern)
            return {
                "status": "success",
                "message": "Extraction des flows et analyse ML completee avec succes",
                "output_csv": output_csv_pattern,
                "file_size": file_size,
                "returncode": result.returncode,
                "ml_results": ml_result
            }
        else:
            # Fichier CSV non trouvé - gérer l'erreur
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
            "message": "L'extraction a depasse le delai imparti (20 minutes)"
        }
    except Exception as e:
        logger.error(f"Erreur lors de l'extraction CICFlowMeter: {e}")
        return {
            "status": "error",
            "message": f"Erreur: {str(e)}"
        }


def process_and_predict_csv(csv_path: str, model_path: str) -> Dict[str, Any]:
    """Traite le CSV généré par CICFlowMeter et applique le modèle ML.

    Args:
        csv_path: Chemin du fichier CSV
        model_path: Chemin du modèle ML sauvegardé

    Returns:
        Dictionnaire avec les résultats du traitement et prédictions
    """
    logger.info(f"DEBUT process_and_predict_csv - CSV: {csv_path}, Model: {model_path}")
    print(f"DEBUG: DEBUT process_and_predict_csv - CSV: {csv_path}")
    try:
        # Charger le CSV
        logger.info(f"Chargement du CSV: {csv_path}")
        df = pd.read_csv(csv_path)
        logger.info(f"CSV chargé avec {len(df)} lignes et {len(df.columns)} colonnes")

        # Colonnes à conserver
        selected_features = [
            'Init Fwd Win Byts', 'Fwd Seg Size Min', 'Dst Port', 'Fwd Header Len',
            'Bwd Pkts/s', 'Flow IAT Max', 'Fwd Pkts/s', 'Flow Duration',
            'Subflow Fwd Pkts', 'Flow IAT Mean', 'Tot Fwd Pkts', 'Fwd IAT Tot',
            'Flow Pkts/s', 'TotLen Fwd Pkts', 'Subflow Fwd Byts', 'Fwd IAT Min',
            'Fwd Act Data Pkts', 'Flow Byts/s', 'Fwd IAT Max', 'Fwd IAT Mean',
            'Flow IAT Min', 'Fwd Pkt Len Max', 'Bwd IAT Mean', 'TotLen Bwd Pkts',
            'Flow IAT Std', 'Tot Bwd Pkts', 'Bwd Header Len', 'Pkt Len Max',
            'Subflow Bwd Byts', 'Fwd Seg Size Avg', 'Bwd Pkt Len Std',
            'Bwd IAT Max', 'Bwd Pkt Len Max', 'Bwd Seg Size Avg',
            'Bwd Pkt Len Mean', 'Fwd IAT Std', 'Pkt Len Std', 'Subflow Bwd Pkts',
            'Fwd Pkt Len Mean', 'Pkt Len Var', 'Init Bwd Win Byts', 'Bwd IAT Min',
            'Pkt Len Mean', 'Fwd Pkt Len Std', 'ECE Flag Cnt'
        ]

        # Filtrer les colonnes disponibles
        available_features = [col for col in selected_features if col in df.columns]
        df = df[available_features]
        logger.info(f"Colonnes conservées: {len(df.columns)} sur {len(selected_features)} demandées")

        # Définir les types
        int_features = [
            'Init Fwd Win Byts', 'Fwd Seg Size Min', 'Dst Port', 'Fwd Header Len',
            'Tot Fwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Bwd Header Len',
            'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts',
            'Subflow Bwd Byts', 'Fwd Act Data Pkts', 'Fwd Pkt Len Max', 'Tot Bwd Pkts',
            'Bwd Pkt Len Max', 'Pkt Len Max', 'Init Bwd Win Byts', 'ECE Flag Cnt'
        ]

        float_features = [
            'Bwd Pkts/s', 'Flow IAT Max', 'Fwd Pkts/s', 'Flow Duration',
            'Flow IAT Mean', 'Fwd IAT Tot', 'Flow Pkts/s', 'Fwd IAT Min',
            'Flow Byts/s', 'Fwd IAT Max', 'Fwd IAT Mean', 'Flow IAT Min',
            'Bwd IAT Mean', 'Flow IAT Std', 'Fwd Seg Size Avg', 'Bwd Pkt Len Std',
            'Bwd IAT Max', 'Bwd Seg Size Avg', 'Bwd Pkt Len Mean', 'Fwd IAT Std',
            'Pkt Len Std', 'Fwd Pkt Len Mean', 'Pkt Len Var', 'Bwd IAT Min',
            'Pkt Len Mean', 'Fwd Pkt Len Std'
        ]

        # Convertir les types
        for col in df.columns:
            if col in int_features:
                df[col] = df[col].astype("int64")
            elif col in float_features:
                df[col] = df[col].astype("float64")

        logger.info("Types de colonnes convertis")

        # Traiter NaN et Inf
        nan_count_initial = df.isnull().sum().sum()
        logger.info(f"Total NaN dans tout le dataset : {nan_count_initial}")

        df.replace(["Infinity", "-Infinity"], np.inf, inplace=True)

        # Sélectionner uniquement les colonnes numériques
        df_numeric = df.select_dtypes(include=[np.number])

        # Détecter Inf
        inf_count = np.isinf(df_numeric).sum().sum()
        logger.info(f"Total Inf : {inf_count}")

        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        logger.info(f"Total NaN après remplacement Inf : {df.isnull().sum().sum()}")

        df.dropna(inplace=True)
        logger.info(f"Total NaN après dropna : {df.isnull().sum().sum()}")

        # Filtrer Protocol != 0
        if 'Protocol' in df.columns:
            protocol_zero_count = (df["Protocol"] == 0).sum()
            logger.info(f"Nombre de lignes avec Protocol == 0 : {protocol_zero_count}")

            df = df[df["Protocol"] != 0]
            logger.info(f"Nombre de lignes avec Protocol == 0 après filtrage : {(df['Protocol'] == 0).sum()}")

        logger.info(f"Dataset final : {len(df)} lignes, {len(df.columns)} colonnes")

        # Sauvegarder le CSV prétraité dans le même dossier que le CSV original
        preprocessed_csv_path = os.path.join(
            os.path.dirname(csv_path),
            f"{os.path.splitext(os.path.basename(csv_path))[0]}_preprocessed.csv"
        )
        df.to_csv(preprocessed_csv_path, index=False, encoding='utf-8')
        logger.info(f"CSV prétraité sauvegardé : {preprocessed_csv_path}")

        # Charger le modèle ML
        logger.info(f"Chargement du modèle : {model_path}")
        with open(model_path, 'rb') as f:
            model = pickle.load(f)

        # Faire les prédictions
        logger.info("Application du modèle ML...")
        predictions = model.predict(df)
        prediction_proba = model.predict_proba(df) if hasattr(model, 'predict_proba') else None

        # Compter les prédictions
        unique_preds, counts = np.unique(predictions, return_counts=True)
        pred_summary = dict(zip(unique_preds, counts))

        logger.info(f"Prédictions terminées : {pred_summary}")

        logger.info(f"FIN process_and_predict_csv - SUCCES - {len(df)} lignes traitées")
        print(f"DEBUG: FIN process_and_predict_csv - SUCCES - {len(df)} lignes traitées")
        return {
            "status": "success",
            "processed_data": df,
            "predictions": predictions,
            "prediction_proba": prediction_proba,
            "prediction_summary": pred_summary,
            "preprocessed_csv": preprocessed_csv_path
        }

    except Exception as e:
        logger.error(f"FIN process_and_predict_csv - ERREUR: {e}")
        print(f"DEBUG: FIN process_and_predict_csv - ERREUR: {e}")
        return {
            "status": "error",
            "message": f"Erreur lors du traitement ML : {str(e)}"
        }