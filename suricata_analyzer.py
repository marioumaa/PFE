"""Analyseur Suricata - Analyse de trafic réseau PCAP."""

import json
import subprocess
import os
from collections import Counter
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
            # suricata.yaml référence ses fichiers annexes (rules/, classification.config,
            # threshold.config, cache...) par des chemins relatifs : Suricata les résout
            # par rapport à son répertoire de travail, pas par rapport à celui du yaml.
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


def parse_eve_alerts(analysis_folder: str) -> Dict[str, Any]:
    """Parse le fichier eve.json généré par Suricata.

    Args:
        analysis_folder: Dossier contenant les fichiers d'analyse

    Returns:
        Dictionnaire avec alertes parsées et statistiques (une seule passe du fichier)
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

        event_types: Counter = Counter()
        alert_categories: Counter = Counter()
        signatures: Counter = Counter()
        severity_distribution: Counter = Counter()
        signature_severity_distribution: Counter = Counter()
        mitre_tactics: Counter = Counter()
        mitre_techniques: Counter = Counter()
        top_src_ips: Counter = Counter()
        top_dest_ips: Counter = Counter()
        app_proto_distribution: Counter = Counter()
        timeline: Counter = Counter()
        anomaly_types: Counter = Counter()
        # Détail par signature : compte, sévérité, couple (IP source, IP destination) le plus fréquent,
        # et métadonnées de la règle (MITRE tactique/technique, produit affecté, cible d'attaque)
        signature_details: Dict[str, Dict[str, Any]] = {}
        # Pour la heatmap signature x heure : {signature: Counter(heure -> compte)}
        signature_hour_matrix: Dict[str, Counter] = {}
        # Pour le graphe réseau : couple (IP source, IP destination) -> nombre d'alertes, tous types confondus
        global_ip_pairs: Counter = Counter()
        # Pour la matrice IP x Signature : qui déclenche quelle signature (IP source),
        # qui est visé par quelle signature (IP destination)
        src_signature_counts: Counter = Counter()
        signature_dest_counts: Counter = Counter()
        alert_count = 0
        anomaly_count = 0

        # Lire le fichier eve.json ligne par ligne (format JSON Lines)
        with open(eve_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                    event_type = event.get("event_type", "unknown")
                    event_types[event_type] += 1

                    if event_type == "alert":
                        alert_count += 1
                        alert = event.get("alert", {})
                        category = alert.get("category", "Unknown")
                        alert_categories[category] += 1

                        signature = alert.get("signature", "Unknown")
                        signatures[signature] += 1

                        severity = alert.get("severity")
                        if severity is not None:
                            severity_distribution[severity] += 1

                        metadata = alert.get("metadata", {}) or {}
                        for tactic in metadata.get("mitre_tactic_name", []):
                            mitre_tactics[tactic.replace("_", " ").title()] += 1
                        for technique in metadata.get("mitre_technique_name", []):
                            mitre_techniques[technique.replace("_", " ").title()] += 1
                        for sig_sev in metadata.get("signature_severity", []):
                            signature_severity_distribution[sig_sev] += 1

                        src_ip = event.get("src_ip")
                        dest_ip = event.get("dest_ip")
                        if src_ip:
                            top_src_ips[src_ip] += 1
                        if dest_ip:
                            top_dest_ips[dest_ip] += 1
                        if src_ip and dest_ip:
                            global_ip_pairs[(src_ip, dest_ip)] += 1
                        if src_ip:
                            src_signature_counts[(src_ip, signature)] += 1
                        if dest_ip:
                            signature_dest_counts[(signature, dest_ip)] += 1

                        app_proto = event.get("app_proto")
                        if app_proto and app_proto != "failed":
                            app_proto_distribution[app_proto] += 1

                        timestamp = event.get("timestamp", "")
                        hour_bucket = None
                        if len(timestamp) >= 13:
                            # Regroupe par heure : "2017-07-04T12:54:14..." -> "2017-07-04 12h"
                            hour_bucket = f"{timestamp[:10]} {timestamp[11:13]}h"
                            timeline[hour_bucket] += 1
                            signature_hour_matrix.setdefault(signature, Counter())[hour_bucket] += 1

                        detail = signature_details.setdefault(signature, {
                            "count": 0,
                            "severity": severity,
                            # Couple (IP source, IP destination) observé ensemble, pour garder
                            # la correspondance réelle entre les deux (pas deux top indépendants)
                            "ip_pairs": Counter(),
                            # Métadonnées de la règle (identiques à chaque déclenchement d'une même
                            # signature, mais on prend le plus fréquent au cas où une signature
                            # partagerait un nom entre plusieurs règles légèrement différentes)
                            "mitre_tactics": Counter(),
                            "mitre_techniques": Counter(),
                            "affected_products": Counter(),
                            "attack_targets": Counter(),
                        })
                        detail["count"] += 1
                        if src_ip and dest_ip:
                            detail["ip_pairs"][(src_ip, dest_ip)] += 1
                        for tactic in metadata.get("mitre_tactic_name", []):
                            detail["mitre_tactics"][tactic.replace("_", " ").title()] += 1
                        for technique in metadata.get("mitre_technique_name", []):
                            detail["mitre_techniques"][technique.replace("_", " ").title()] += 1
                        for product in metadata.get("affected_product", []):
                            detail["affected_products"][product.replace("_", " ")] += 1
                        for target in metadata.get("attack_target", []):
                            detail["attack_targets"][target.replace("_", " ")] += 1

                    elif event_type == "anomaly":
                        anomaly_count += 1
                        anomaly_event = event.get("anomaly", {}).get("event", "unknown")
                        anomaly_types[anomaly_event] += 1

                except json.JSONDecodeError:
                    logger.debug(f"Erreur JSON à la ligne {line_num}, fichier ignorée")
                    continue

        # Finaliser la table détaillée par signature (couple IP source/destination le plus
        # fréquent, réellement observé ensemble - pas deux tops indépendants - et métadonnées
        # de règle les plus fréquentes pour cette signature)
        def _top_or_na(counter: Counter) -> str:
            top = counter.most_common(1)
            return top[0][0] if top else "N/A"

        signature_table = []
        for sig, detail in signature_details.items():
            top_pair = detail["ip_pairs"].most_common(1)
            if top_pair:
                (top_src_ip, top_dest_ip), pair_count = top_pair[0]
            else:
                top_src_ip, top_dest_ip, pair_count = "N/A", "N/A", 0
            signature_table.append({
                "signature": sig,
                "count": detail["count"],
                "severity": detail["severity"],
                "top_src_ip": top_src_ip,
                "top_dest_ip": top_dest_ip,
                "pair_count": pair_count,
                "mitre_tactic": _top_or_na(detail["mitre_tactics"]),
                "mitre_technique": _top_or_na(detail["mitre_techniques"]),
                "affected_product": _top_or_na(detail["affected_products"]),
                "attack_target": _top_or_na(detail["attack_targets"]),
            })
        signature_table.sort(key=lambda x: x["count"], reverse=True)

        # Matrice pour la heatmap signature x heure : limitée aux 10 signatures les plus
        # fréquentes pour rester lisible
        top_signatures_for_heatmap = [s for s, _ in signatures.most_common(10)]
        signature_hour_heatmap = {
            sig: dict(signature_hour_matrix.get(sig, Counter()))
            for sig in top_signatures_for_heatmap
        }

        # Graphe réseau : limité aux 15 IP les plus impliquées (source + destination
        # confondues), et seulement les liens entre ces IP-là, pour rester lisible
        node_involvement: Counter = Counter()
        for (src, dest), cnt in global_ip_pairs.items():
            node_involvement[src] += cnt
            node_involvement[dest] += cnt
        top_graph_nodes = [ip for ip, _ in node_involvement.most_common(15)]
        top_graph_nodes_set = set(top_graph_nodes)
        network_graph = {
            "nodes": top_graph_nodes,
            "node_weights": {ip: node_involvement[ip] for ip in top_graph_nodes},
            "edges": [
                {"src": src, "dest": dest, "count": cnt}
                for (src, dest), cnt in global_ip_pairs.items()
                if src in top_graph_nodes_set and dest in top_graph_nodes_set
            ],
        }

        # Matrice IP x Signature : qui déclenche quelle signature (IP source) et qui est
        # visé par quelle signature (IP destination), limité aux 10 IP et 10 signatures
        # les plus fréquentes pour rester lisible. Remplace l'ancien diagramme de Sankey
        # (IP -> signature -> IP), jugé peu lisible à cause des flux qui s'entrecroisent :
        # une matrice se lit directement ligne x colonne, sans lignes qui se chevauchent.
        matrix_signatures = [s for s, _ in signatures.most_common(10)]
        matrix_src_ips = [ip for ip, _ in top_src_ips.most_common(10)]
        matrix_dest_ips = [ip for ip, _ in top_dest_ips.most_common(10)]
        ip_signature_matrix = {
            "signatures": matrix_signatures,
            "src_ips": matrix_src_ips,
            "dest_ips": matrix_dest_ips,
            "src_counts": {
                sig: {ip: src_signature_counts.get((ip, sig), 0) for ip in matrix_src_ips}
                for sig in matrix_signatures
            },
            "dest_counts": {
                sig: {ip: signature_dest_counts.get((sig, ip), 0) for ip in matrix_dest_ips}
                for sig in matrix_signatures
            },
        }

        logger.info(f"Eve.json parsé: {alert_count} alertes, {sum(event_types.values())} événements")
        return {
            "status": "success",
            "alert_count": alert_count,
            "event_types": dict(event_types),
            "alert_categories": dict(alert_categories),
            "total_events": sum(event_types.values()),
            "signatures": dict(signatures.most_common(20)),
            "severity_distribution": dict(severity_distribution),
            "signature_severity_distribution": dict(signature_severity_distribution),
            "mitre_tactics": dict(mitre_tactics),
            "mitre_techniques": dict(mitre_techniques.most_common(15)),
            "top_src_ips": dict(top_src_ips.most_common(10)),
            "top_dest_ips": dict(top_dest_ips.most_common(10)),
            "app_proto_distribution": dict(app_proto_distribution),
            "timeline": dict(sorted(timeline.items())),
            "signature_hour_heatmap": signature_hour_heatmap,
            "network_graph": network_graph,
            "ip_signature_matrix": ip_signature_matrix,
            "anomaly_count": anomaly_count,
            "anomaly_types": dict(anomaly_types.most_common(15)),
            "signature_table": signature_table[:30],
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


