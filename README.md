# Analyseur PCAP : détection de menaces réseau par corrélation de trois sources

Application web (Streamlit) qui analyse un fichier de capture réseau (PCAP) et attribue un niveau de risque (CRITIQUE, ELEVE, MOYEN ou NORMAL) à chaque flux, afin d'améliorer la précision de détection des menaces et de réduire les faux positifs des systèmes de détection d'intrusion classiques.

Elle corrèle trois sources d'analyse complémentaires : une détection par signatures avec Suricata, une classification supervisée des menaces avec un modèle Random Forest, et une détection d'anomalies non supervisée avec un modèle Isolation Forest. Les deux modèles d'apprentissage automatique sont entraînés sur le jeu de données CICIDS2018 et alimentés par les caractéristiques de flux extraites avec CICFlowMeter. Les résultats sont présentés dans un tableau de bord interactif, et l'historique des analyses peut être consulté dans l'application.

