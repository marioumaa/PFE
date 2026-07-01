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
import joblib
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from config import CICFLOWMETER_PATH, CICFLOWMETER_TIMEOUT, ML_MODEL_PATH, ML_ANOMALY_MODEL_PATH, CICFLOWMETER_COMMAND

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
            logger.info(f"Traitement ML terminé avec status: {ml_result.get('status', 'unknown') if isinstance(ml_result, dict) else 'None'}")
            print(f"DEBUG: Après appel process_and_predict_csv - result status: {ml_result.get('status') if isinstance(ml_result, dict) else 'None'}")

            if not isinstance(ml_result, dict) or ml_result.get("status") != "success":
                logger.error("Le pipeline ML a échoué après l'extraction des flows.")
                return {
                    "status": "error",
                    "message": "L'analyse ML a échoué après l'extraction des flows.",
                    "output_csv": output_csv_pattern,
                    "file_size": os.path.getsize(output_csv_pattern),
                    "returncode": result.returncode,
                    "ml_results": ml_result
                }

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




def detect_anomalies(
    df: pd.DataFrame,
    anomaly_model_path: str = ML_ANOMALY_MODEL_PATH,
    return_predictions: bool = False
) -> Dict[str, Any]:
    """Applique le modèle de détection d'anomalies pour détecter les anomalies dans les flows.

    Args:
        df: DataFrame contenant les flows à analyser
        anomaly_model_path: Chemin du modèle de détection d'anomalies
        return_predictions: Si True, renvoie également le tableau de prédictions

    Returns:
        Dictionnaire avec les résultats de détection d'anomalies
    """
    logger.info(f"DEBUT detect_anomalies - {len(df)} lignes")
    print(f"DEBUG: Debut detection anomalies - df shape: {df.shape}")
    
    try:
        # Vérifier que le fichier du modèle existe
        if not os.path.exists(anomaly_model_path):
            logger.error(f"Modèle d'anomalies non trouvé: {anomaly_model_path}")
            return {
                "status": "error",
                "message": f"Modèle d'anomalies non trouvé: {anomaly_model_path}"
            }

        # Charger le modèle de détection d'anomalies
        logger.info(f"Chargement du modèle de détection d'anomalies: {anomaly_model_path}")
        model = joblib.load(anomaly_model_path)
        logger.info("Modèle de détection d'anomalies chargé avec succès")

        # Appliquer le modèle pour la prédiction
        logger.info(f"Application du modèle de détection d'anomalies sur {len(df)} lignes...")
        predictions = model.predict(df)
        
        # Compter les résultats:
        # predictions == 1  : normal (inliers)
        # predictions == -1 : anomalies (outliers)
        total = len(predictions)
        n_normal = int((predictions == 1).sum())
        n_anomaly = int((predictions == -1).sum())
        
        logger.info(f"Résultats de la détection d'anomalies - Total: {total}, Normal: {n_normal}, Anomalies: {n_anomaly}")
        
        logger.info("FIN detect_anomalies - SUCCES")
        print(f"DEBUG: FIN detection anomalies - Total: {total}, Normal: {n_normal}, Anomaly: {n_anomaly}")
        
        result = {
            "status": "success",
            "total": total,
            "n_normal": n_normal,
            "n_anomaly": n_anomaly,
            "sample_count": total,
            "benign_count": total
        }
        if return_predictions:
            result["predictions"] = predictions
        return result

    except Exception as e:
        logger.error(f"FIN detect_anomalies - ERREUR: {e}")
        print(f"DEBUG: Erreur detection anomalies: {e}")
        return {
            "status": "error",
            "message": f"Erreur lors de la détection d'anomalies: {str(e)}"
        }


def process_and_predict_csv(csv_path: str, model_path: str, label_encoder_path: str = r"C:\Users\marie\Desktop\Dataset2018\Processed Traffic Data for ML Algorithms\label_encoder_dernier.pkl") -> Dict[str, Any]:
    """Traite le CSV généré par CICFlowMeter avec pipeline à 2 étapes:
    1. Détection d'anomalies (Elliptic Envelope) sur TOUT le CSV
    2. Classification (RandomForest) SEULEMENT sur les lignes anomalies avec seuil 75%

    Args:
        csv_path: Chemin du fichier CSV
        model_path: Chemin du modèle de classification ML
        label_encoder_path: Chemin du label_encoder sauvegardé

    Returns:
        Dictionnaire avec résultats anomaly detection et classification
    """
    logger.info(f"DEBUT process_and_predict_csv - CSV: {csv_path}")
    print(f"DEBUG: DEBUT process_and_predict_csv - CSV: {csv_path}")
    try:
        # ===== CHARGEMENT ET PRÉTRAITEMENT =====
        logger.info(f"Chargement du CSV: {csv_path}")
        df = pd.read_csv(csv_path)
        logger.info(f"CSV chargé avec {len(df)} lignes et {len(df.columns)} colonnes")

        # Colonnes à conserver pour la détection d'anomalies (ensemble initial)
        anomaly_features = ['Dst Port', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts',
        'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
        'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow Byts/s', 
        'Flow Pkts/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot',
        'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean',
        'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd Header Len', 'Bwd Header Len',
        'Fwd Pkts/s', 'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
        'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
        'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg',
        'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts', 'Init Fwd Win Byts',
        'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean', 'Active Std',
        'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']

        # Colonnes à utiliser pour la classification (spécifiques, selon demande utilisateur)
        classification_features = ['Dst Port', 'Init Fwd Win Byts', 'Fwd Seg Size Min', 'Fwd Header Len', 'Bwd Pkts/s', 'Subflow Fwd Pkts',
        'Flow Duration', 'Tot Fwd Pkts', 'Flow IAT Max', 'Fwd IAT Tot', 'Flow IAT Mean', 'Fwd Act Data Pkts', 'Flow Pkts/s', 'Fwd IAT Mean',
        'Bwd Header Len', 'Fwd Pkts/s', 'Fwd IAT Min', 'TotLen Fwd Pkts', 'Fwd IAT Max', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Fwd Pkt Len Max',
        'Flow IAT Std', 'TotLen Bwd Pkts', 'Tot Bwd Pkts', 'Bwd IAT Min', 'Flow Byts/s', 'Pkt Len Mean', 'Pkt Len Max', 'Bwd Pkt Len Max',
        'Subflow Bwd Byts', 'Bwd IAT Mean', 'Fwd Pkt Len Mean', 'Bwd IAT Tot', 'ECE Flag Cnt', 'Bwd IAT Max', 'Fwd Pkt Len Std', 'Pkt Len Var',
        'Init Bwd Win Byts', 'Fwd Seg Size Avg', 'Pkt Size Avg', 'RST Flag Cnt', 'Fwd IAT Std', 'Flow IAT Min']

        # Construire l'ensemble final de colonnes à conserver (union des deux listes dans l'ordre demandé)
        requested_features = anomaly_features + [f for f in classification_features if f not in anomaly_features]
        available_features = [col for col in requested_features if col in df.columns]
        df = df[available_features]
        logger.info(f"Colonnes conservées pour traitement: {len(df.columns)}")

        # Convertir tout en float
        for col in df.columns: 
            df[col] = df[col].astype("float64")
        logger.info("Types de colonnes convertis")

        # Traiter NaN et Inf
        nan_count_initial = df.isnull().sum().sum()
        logger.info(f"Total NaN dans tout le dataset : {nan_count_initial}")

        df.replace(["Infinity", "-Infinity"], np.inf, inplace=True)
        df_numeric = df.select_dtypes(include=[np.number])
        inf_count = np.isinf(df_numeric).sum().sum()
        logger.info(f"Total Inf : {inf_count}")

        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        logger.info(f"CSV prétraité: {len(df)} lignes conservées après nettoyage")

        # Sauvegarder le CSV prétraité
        preprocessed_csv_path = os.path.join(
            os.path.dirname(csv_path),
            f"{os.path.splitext(os.path.basename(csv_path))[0]}_preprocessed.csv"
        )
        df.to_csv(preprocessed_csv_path, index=False, encoding='utf-8')
        logger.info(f"CSV prétraité sauvegardé : {preprocessed_csv_path}")

        # ===== ÉTAPE 1: DÉTECTION D'ANOMALIES =====
        logger.info("="*60)
        logger.info("ÉTAPE 1: DÉTECTION D'ANOMALIES (Elliptic Envelope)")
        logger.info("="*60)
        anomaly_outputs = detect_anomalies(df, return_predictions=True)

        if anomaly_outputs.get("status") != "success":
            logger.error("Détection d'anomalies échouée - abandon du pipeline")
            return {
                "status": "error",
                "message": "Détection d'anomalies a échoué.",
                "anomaly_results": anomaly_outputs
            }

        anomaly_predictions = np.array(anomaly_outputs.get("predictions"))
        n_total = len(df)
        n_normal = int((anomaly_predictions == 1).sum())
        n_anomaly = int((anomaly_predictions == -1).sum())
        anomaly_results = {
            "status": anomaly_outputs.get("status"),
            "total": anomaly_outputs.get("total"),
            "n_normal": anomaly_outputs.get("n_normal"),
            "n_anomaly": anomaly_outputs.get("n_anomaly"),
            "sample_count": anomaly_outputs.get("sample_count")
        }

        logger.info(f"Résultats détection d'anomalies:")
        logger.info(f"  - Total flows: {n_total}")
        logger.info(f"  - Flows normaux: {n_normal}")
        logger.info(f"  - Flows anormaux: {n_anomaly}")

        # ===== ÉTAPE 2: CLASSIFICATION DES ANOMALIES =====
        logger.info("="*60)
        logger.info("ÉTAPE 2: CLASSIFICATION DES ANOMALIES (RandomForest)")
        logger.info("="*60)

        classification_summary = {}

        # Charger modèles de classification
        logger.info(f"Chargement du modèle de classification : {model_path}")
        with open(model_path, 'rb') as f:
            clf = pickle.load(f)

        logger.info(f"Chargement du label_encoder : {label_encoder_path}")
        with open(label_encoder_path, 'rb') as f:
            label_encoder = pickle.load(f)

        # Appliquer classification UNIQUEMENT sur les anomalies
        anomaly_mask = anomaly_predictions == -1

        if not anomaly_mask.any():
            logger.info("Aucune anomalie détectée - classification non appliquée")
            classification_summary = {}
        else:
            df_anomalies = df[anomaly_mask].copy()
            logger.info(f"Classification de {len(df_anomalies)} anomalies détectées...")

            # Préparer le sous-ensemble de features demandé pour la classification
            classification_available = [c for c in classification_features if c in df_anomalies.columns]
            if not classification_available:
                logger.warning("Aucune des features de classification spécifiées n'est disponible dans les anomalies. Classification ignorée.")
                classification_summary = {}
            else:
                df_clf = df_anomalies[classification_available].copy()

                try:
                    # Aligner les colonnes sur ce que le classifieur attend si disponible
                    expected = getattr(clf, 'feature_names_in_', None)
                    df_for_pred = df_clf
                    if expected is not None:
                        expected = list(expected)
                        missing = [c for c in expected if c not in df_clf.columns]
                        if missing:
                            logger.warning(f"Features manquantes pour le classifieur, ajout de colonnes vides: {missing}")
                            for c in missing:
                                df_for_pred[c] = 0.0
                        extra = [c for c in df_for_pred.columns if c not in expected]
                        if extra:
                            df_for_pred = df_for_pred.drop(columns=extra)
                        # réordonner selon expected
                        df_for_pred = df_for_pred[expected]

                    # Prédictions de classe (sur df_for_pred)
                    preds = clf.predict(df_for_pred)

                    # Calcul des confiances
                    confidences = None
                    if hasattr(clf, 'predict_proba'):
                        try:
                            probs = clf.predict_proba(df_for_pred)
                            confidences = probs.max(axis=1)
                            logger.info("Confiances calculées via predict_proba")
                        except Exception as e:
                            logger.warning(f"predict_proba échoué: {e}")

                    if confidences is None and hasattr(clf, 'decision_function'):
                        try:
                            df_scores = clf.decision_function(df_for_pred)
                            if df_scores.ndim == 1:
                                s = 1 / (1 + np.exp(-df_scores))
                                confidences = np.abs(s)
                            else:
                                exp = np.exp(df_scores - np.max(df_scores, axis=1, keepdims=True))
                                soft = exp / np.sum(exp, axis=1, keepdims=True)
                                confidences = soft.max(axis=1)
                            logger.info("Confiances calculées via decision_function")
                        except Exception as e:
                            logger.warning(f"decision_function échoué: {e}")

                    if confidences is None:
                        confidences = np.ones(len(df_for_pred))
                        logger.warning("Confiances par défaut (1.0)")

                    # Décoder les prédictions
                    try:
                        decoded_labels = label_encoder.inverse_transform(preds)
                    except Exception as e:
                        logger.warning(f"Erreur label_encoder.inverse_transform: {e}")
                        decoded_labels = np.array(preds, dtype=object)

                    # Appliquer seuil de confiance 75% et mapper sur indices originaux
                    CONFIDENCE_THRESHOLD = 0.5
                    unknown_mask = confidences < CONFIDENCE_THRESHOLD
                    known_mask = ~unknown_mask
                    unknown_count = int(unknown_mask.sum())

                    # Résumé classification (sur labels connus)
                    from collections import Counter
                    classification_summary = Counter(decoded_labels[known_mask])
                    if unknown_count > 0:
                        classification_summary['unknown'] = unknown_count
                    classification_summary = {label: int(count) for label, count in classification_summary.items()}

                    logger.info(f"Classification terminée - {unknown_count} lignes marquées 'unknown' (confiance < 75%)")
                    logger.info(f"Résumé classification: {classification_summary}")

                except Exception as e:
                    logger.error(f"Erreur lors de la classification: {e}")
                    return {
                        "status": "error",
                        "message": f"Erreur lors de la classification: {str(e)}"
                    }

        # ===== RÉSUMÉ FINAL =====
        logger.info("="*60)
        logger.info("RÉSUMÉ FINAL DU PIPELINE ML")
        logger.info("="*60)
        
        final_summary = {'normal': n_normal}
        final_summary.update(classification_summary)
        
        logger.info(f"FIN process_and_predict_csv - SUCCES")
        print(f"DEBUG: FIN process_and_predict_csv - {n_total} lignes traitées")
        
        return {
            "status": "success",
            "prediction_summary": final_summary,
            "anomaly_detection_results": {
                "total_flows": n_total,
                "normal_flows": n_normal,
                "anomaly_flows": n_anomaly
            },
            "classification_results": classification_summary,
            "preprocessed_csv": preprocessed_csv_path,
            "anomaly_results": anomaly_results
        }

    except Exception as e:
        logger.error(f"FIN process_and_predict_csv - ERREUR: {e}")
        print(f"DEBUG: FIN process_and_predict_csv - ERREUR: {e}")
        return {
            "status": "error",
            "message": f"Erreur lors du traitement ML : {str(e)}"
        }