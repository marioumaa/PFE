"""Fonctions utilitaires générales."""

import json
import os
from pathlib import Path
from typing import Any, Optional

from config import DEFAULT_ENCODING, JSON_INDENT, JSON_ENSURE_ASCII
from logger import setup_logging

logger = setup_logging(__name__)


def load_json_file(filepath: str) -> Optional[Any]:
    """Charge un fichier JSON de manière sécurisée.
    
    Args:
        filepath: Chemin du fichier JSON
    
    Returns:
        Dictionnaire ou liste chargée, None si erreur
    """
    try:
        with open(filepath, 'r', encoding=DEFAULT_ENCODING) as f:
            content = f.read()
        if not content.strip():
            # Fichier vide (ex: première exécution) : pas une erreur, juste absence de données.
            return None
        return json.loads(content)
    except FileNotFoundError:
        logger.warning(f"Fichier non trouvé: {filepath}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Erreur de parsing JSON {filepath}: {e}")
        return None
    except Exception as e:
        logger.error(f"Erreur lors du chargement de {filepath}: {e}")
        return None


def save_json_file(filepath: str, data: Any, create_dirs: bool = True) -> bool:
    """Sauvegarde des données en JSON de manière sécurisée.
    
    Args:
        filepath: Chemin du fichier JSON
        data: Données à sauvegarder
        create_dirs: Créer les répertoires parent si nécessaire
    
    Returns:
        True si succès, False sinon
    """
    try:
        if create_dirs:
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'w', encoding=DEFAULT_ENCODING) as f:
            json.dump(data, f, indent=JSON_INDENT, ensure_ascii=JSON_ENSURE_ASCII)
        return True
    except Exception as e:
        logger.error(f"Erreur lors de la sauvegarde de {filepath}: {e}")
        return False


def get_file_size_gb(filepath: str) -> float:
    """Obtient la taille d'un fichier en GB.
    
    Args:
        filepath: Chemin du fichier
    
    Returns:
        Taille en GB, arrondie à 2 décimales
    """
    try:
        return round(os.path.getsize(filepath) / (1024 ** 3), 2)
    except Exception as e:
        logger.error(f"Erreur lors du calcul de la taille de {filepath}: {e}")
        return 0.0


def get_file_size_kb(filepath: str) -> float:
    """Obtient la taille d'un fichier en KB.
    
    Args:
        filepath: Chemin du fichier
    
    Returns:
        Taille en KB, arrondie à 2 décimales
    """
    try:
        return round(os.path.getsize(filepath) / 1024, 2)
    except Exception as e:
        logger.error(f"Erreur lors du calcul de la taille de {filepath}: {e}")
        return 0.0


def file_exists(filepath: str) -> bool:
    """Vérifie si un fichier existe.
    
    Args:
        filepath: Chemin du fichier
    
    Returns:
        True si existe, False sinon
    """
    return os.path.exists(filepath)
