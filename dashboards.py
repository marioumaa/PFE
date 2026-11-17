"""Dashboard de corrélation multi-sources.

Contrairement aux anciens dashboards (un par couche : Suricata seul, classifieur
seul, détecteur d'anomalies seul), ce module ne travaille que sur la table finale
unifiée (voir risk_correlation.load_correlation_dataframe) et se concentre sur ce
que chaque couche apporte par rapport aux autres.

Graphiques en Plotly (même rendu interactif/poli que les anciens dashboards).
networkx sert à calculer la disposition du graphe de communication (Section 2),
rendu ensuite en Plotly.

Le fichier source peut contenir plusieurs centaines de milliers de lignes : chaque
section n'affiche jamais les lignes brutes (seulement des agrégats, des graphiques,
ou un aperçu limité), et le chargement en amont (load_correlation_dataframe) ne lit
déjà que les colonnes nécessaires.
"""

from typing import Any, Dict, List, Optional, Tuple

import networkx as nx
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from risk_correlation import RISK_CLASSIFIER_CONFIDENCE_THRESHOLD

# Au-delà de ce nombre d'IP uniques, le graphe réseau (Section 2) devient illisible :
# seuls les liens (communications) les plus fréquents sont gardés, jusqu'à respecter
# cette limite de nœuds — pas de repli en tableau, le graphe reste toujours affiché.
_MAX_GRAPH_NODES = 30

# Au-delà de ce nombre de catégories (signature Suricata / classe ML / combinaison des
# deux) distinctes parmi les liens affichés, les moins fréquentes sont regroupées sous
# "Autres" : au-delà, la légende couleur devient illisible et perd son intérêt.
_MAX_EDGE_CATEGORIES = 9

# Palette qualitative pour les catégories de liens du graphe de communication
# (Section 2) : une couleur par combinaison signature Suricata / classe ML, distincte
# des couleurs de niveau de risque utilisées ailleurs pour éviter toute confusion.
_EDGE_CATEGORY_COLORS = [
    "#e74c3c", "#3498db", "#2ecc71", "#f39c12", "#9b59b6",
    "#1abc9c", "#d35400", "#2980b9", "#27ae60",
]
_EDGE_CATEGORY_OTHER_COLOR = "#95a5a6"

# Nombre d'IP affichées dans les bar charts "IP les plus impliquées" (Section 2).
_TOP_IPS_COUNT = 15

# Couleurs communes, réutilisées pour les cartes de métriques ET les graphiques,
# pour que le même niveau de risque soit toujours associé à la même couleur.
_COLOR_TOTAL = "#34495e"
_COLOR_CRITIQUE = "#c0392b"
_COLOR_ELEVE = "#e67e22"
_COLOR_MOYEN = "#d4ac0d"
_COLOR_NORMAL = "#16a085"
_COLOR_ACCENT = "#8e44ad"

# Fond transparent commun à tous les graphiques Plotly, pour se fondre dans la page
# quel que soit le thème Streamlit de l'utilisateur (clair ou sombre).
_TRANSPARENT_LAYOUT = dict(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')


def _render_metric_cards(cards: List[Tuple[str, Any, str, Optional[str]]]) -> None:
    """Affiche une rangée de cartes de métriques stylées (fond teinté, bordure
    colorée, grand chiffre) plutôt que des st.metric nus, pour un rendu plus soigné.

    Args:
        cards: liste de (label, valeur, couleur_hex, sous-texte optionnel)
    """
    # HTML construit sur une seule ligne, sans indentation : une chaîne multi-ligne
    # indentée est interprétée par le moteur Markdown de Streamlit comme un bloc de
    # code (règle des lignes indentées précédées d'une ligne vide), et s'affiche
    # alors comme du texte brut au lieu d'être rendue comme du HTML.
    tiles = []
    for label, value, color, sub in cards:
        sub_html = f'<div style="font-size:11px;opacity:0.75;margin-top:2px;">{sub}</div>' if sub else ""
        tiles.append(
            f'<div style="flex:1 1 150px;min-width:150px;background:{color}18;'
            f'border:1.5px solid {color};border-radius:10px;padding:14px 12px;'
            f'text-align:center;">'
            f'<div style="font-size:26px;font-weight:700;color:{color};line-height:1.2;">{value}</div>'
            f'<div style="font-size:12.5px;margin-top:4px;opacity:0.85;">{label}</div>'
            f'{sub_html}'
            f'</div>'
        )
    st.markdown(
        f'<div style="display:flex;gap:10px;flex-wrap:wrap;margin:6px 0 4px 0;">{"".join(tiles)}</div>',
        unsafe_allow_html=True,
    )


def display_correlation_dashboard(
    df: pd.DataFrame, event_type_counts: Optional[Dict[str, int]] = None
) -> None:
    """Affiche les sections du dashboard de corrélation, dans l'ordre.

    Args:
        df: DataFrame chargé via risk_correlation.load_correlation_dataframe
            (colonnes lisibles + classification/score_confiance + anomalie/
            score_anomalie + suricata_alerte/signature/severite + niveau_risque/
            raison + signal_classifieur/signal_anomalie/signal_suricata)
        event_type_counts: occurrences de chaque event_type de eve.json (voir
            risk_correlation.count_eve_event_types), tous types confondus (pas
            seulement "alert") — optionnel, section masquée si absent/vide
    """
    if df.empty:
        st.info("Aucun flux à afficher.")
        return

    _section_summary_metrics(df)
    _section_top_ips(df)
    _section_communication_graph(df)
    _section_priority_threats_table(df)
    _section_temporal_distribution(df)
    _section_attack_classes(df)
    _section_suricata_signatures(df)
    _section_event_types(event_type_counts or {})


# ===== Section 1 : métriques de synthèse =====
def _section_summary_metrics(df: pd.DataFrame) -> None:
    st.divider()
    st.subheader("Synthèse")

    # Pas de st.container(border=True) autour des cartes ici : elles ont déjà chacune
    # leur propre bordure colorée (_render_metric_cards), un cadre gris englobant en
    # plus ne fait qu'ajouter une boîte grise superflue autour de cartes déjà colorées.
    total = len(df)
    counts = df["niveau_risque"].value_counts()
    critique = int(counts.get("CRITIQUE", 0))
    eleve = int(counts.get("ELEVE", 0))
    moyen = int(counts.get("MOYEN", 0))
    normal = int(counts.get("NORMAL", 0))
    normal_pct = round(normal / total * 100, 1) if total else 0.0

    _render_metric_cards([
        ("Flux analysés", total, _COLOR_TOTAL, None),
        ("CRITIQUE", critique, _COLOR_CRITIQUE, None),
        ("ELEVE", eleve, _COLOR_ELEVE, None),
        ("MOYEN", moyen, _COLOR_MOYEN, None),
        ("NORMAL", normal, _COLOR_NORMAL, f"{normal_pct}% du trafic"),
    ])


# ===== Section 2 : IP les plus impliquées (CRITIQUE ou ELEVE, au choix) =====
def _section_top_ips(df: pd.DataFrame) -> None:
    st.divider()
    st.subheader("IP les plus impliquées")
    st.caption(
        f"Top {_TOP_IPS_COUNT} IP sources et destinations parmi les flux du niveau "
        "de risque choisi."
    )

    level = st.radio(
        "Niveau de risque à afficher", ["CRITIQUE", "ELEVE"], horizontal=True, key="top_ips_level"
    )
    subset = df[df["niveau_risque"] == level]
    if subset.empty:
        st.info(f"Aucun flux {level} à afficher.")
        return

    color = _COLOR_CRITIQUE if level == "CRITIQUE" else _COLOR_ELEVE

    col1, col2 = st.columns(2)
    with col1:
        with st.container(border=True):
            src_counts = subset["Src IP"].value_counts().head(_TOP_IPS_COUNT).sort_values()
            fig = go.Figure(data=[go.Bar(
                x=src_counts.values, y=src_counts.index, orientation="h",
                marker=dict(color=color),
                hovertemplate="<b>%{y}</b><br>Flux: %{x}<extra></extra>",
            )])
            fig.update_layout(
                height=max(320, 28 * len(src_counts)),
                margin=dict(l=10, r=10, t=40, b=10),
                title=f"IP sources ({level})",
                xaxis=dict(title="Nombre de flux"),
                **_TRANSPARENT_LAYOUT,
            )
            st.plotly_chart(fig, width='stretch')
    with col2:
        with st.container(border=True):
            dst_counts = subset["Dst IP"].value_counts().head(_TOP_IPS_COUNT).sort_values()
            fig = go.Figure(data=[go.Bar(
                x=dst_counts.values, y=dst_counts.index, orientation="h",
                marker=dict(color=color),
                hovertemplate="<b>%{y}</b><br>Flux: %{x}<extra></extra>",
            )])
            fig.update_layout(
                height=max(320, 28 * len(dst_counts)),
                margin=dict(l=10, r=10, t=40, b=10),
                title=f"IP destinations ({level})",
                xaxis=dict(title="Nombre de flux"),
                **_TRANSPARENT_LAYOUT,
            )
            st.plotly_chart(fig, width='stretch')


# ===== Section 3 : graphe de communication (CRITIQUE ou ELEVE, au choix) =====
def _edge_label(subset: pd.DataFrame) -> pd.Series:
    """Détermine, pour chaque flux, l'étiquette de son lien dans le graphe de
    communication : signature Suricata si seule cette source a déclenché, classe
    prédite par le classifieur si lui seul a déclenché, ou la combinaison des deux
    si les deux ont déclenché sur ce flux (l'anomalie n'entre pas dans l'étiquette,
    seulement dans le calcul du niveau de risque lui-même).
    """
    has_suricata = subset["signal_suricata"] == "oui"
    has_classifieur = subset["signal_classifieur"] == "oui"
    signature = subset["suricata_signature"].fillna("Alerte Suricata").astype(str)
    classification = subset["classification"].fillna("").astype(str)
    return pd.Series(
        np.select(
            [has_suricata & has_classifieur, has_suricata & ~has_classifieur, ~has_suricata & has_classifieur],
            [signature + " + " + classification, signature, classification],
            default="Anomalie seule",
        ),
        index=subset.index,
    )


def _section_communication_graph(df: pd.DataFrame) -> None:
    st.divider()
    st.subheader("Graphe de communication")
    st.caption(
        "Nœuds = IP (source ou destination), liens = communications impliquées dans "
        "un flux du niveau choisi. Épaisseur du lien = nombre de flux entre ces deux "
        "IP ; couleur = ce qui a déclenché sur ce lien (signature Suricata, classe "
        "prédite, ou les deux), détaillé dans la légende au-dessus du graphe."
    )

    level = st.radio(
        "Niveau de risque à afficher", ["CRITIQUE", "ELEVE"], horizontal=True, key="comm_graph_level"
    )
    subset = df[df["niveau_risque"] == level]
    if subset.empty:
        st.info(f"Aucun flux {level} à afficher.")
        return

    with st.container(border=True):
        subset = subset.assign(_label=_edge_label(subset))

        edges = (
            subset.groupby(["Src IP", "Dst IP"])["_label"]
            .agg(nb_flux="size", label=lambda s: s.value_counts().idxmax())
            .reset_index()
            .sort_values("nb_flux", ascending=False)
        )

        # Garde les liens les plus fréquents tant que le nombre total d'IP impliquées
        # reste sous _MAX_GRAPH_NODES, plutôt qu'un repli en tableau (moins lisible
        # visuellement) : un lien plus léger mais ne créant aucun nouveau nœud reste
        # ajouté même après le tri par fréquence décroissante.
        seen_nodes: set = set()
        kept_rows = []
        for _, row in edges.iterrows():
            new_nodes = {row["Src IP"], row["Dst IP"]} - seen_nodes
            if len(seen_nodes) + len(new_nodes) > _MAX_GRAPH_NODES:
                continue
            seen_nodes |= new_nodes
            kept_rows.append(row)
        capped_edges = pd.DataFrame(kept_rows, columns=edges.columns) if kept_rows else edges.iloc[0:0]

        if capped_edges.empty:
            st.info("Aucun lien à afficher.")
            return

        if len(capped_edges) < len(edges):
            st.caption(
                f"{len(edges)} liens au total pour {level} — affichage limité aux "
                f"{len(capped_edges)} liens les plus fréquents ({_MAX_GRAPH_NODES} IP max)."
            )

        # Catégories couleur : les _MAX_EDGE_CATEGORIES étiquettes les plus fréquentes
        # (par flux total) gardent une couleur dédiée, le reste est regroupé sous
        # "Autres" pour que la légende reste lisible.
        label_totals = capped_edges.groupby("label")["nb_flux"].sum().sort_values(ascending=False)
        top_labels = list(label_totals.index[:_MAX_EDGE_CATEGORIES])
        capped_edges = capped_edges.assign(
            _category=capped_edges["label"].where(capped_edges["label"].isin(top_labels), "Autres")
        )
        category_order = [c for c in label_totals.index if c in top_labels]
        if (capped_edges["_category"] == "Autres").any():
            category_order.append("Autres")
        color_map = {
            cat: _EDGE_CATEGORY_COLORS[i % len(_EDGE_CATEGORY_COLORS)]
            for i, cat in enumerate(category_order) if cat != "Autres"
        }
        if "Autres" in category_order:
            color_map["Autres"] = _EDGE_CATEGORY_OTHER_COLOR

        graph = nx.DiGraph()
        for _, row in capped_edges.iterrows():
            graph.add_edge(row["Src IP"], row["Dst IP"], weight=row["nb_flux"], category=row["_category"])

        pos = nx.spring_layout(graph, seed=42, k=0.9)
        nodes = list(graph.nodes())

        node_weight = {n: 0 for n in nodes}
        for u, v, d in graph.edges(data=True):
            node_weight[u] += d["weight"]
            node_weight[v] += d["weight"]
        max_node_weight = max(node_weight.values()) if node_weight else 1

        node_x = [pos[n][0] for n in nodes]
        node_y = [pos[n][1] for n in nodes]
        node_size = [16 + 34 * (node_weight[n] / max_node_weight) for n in nodes]

        node_color = _COLOR_CRITIQUE if level == "CRITIQUE" else _COLOR_ELEVE

        max_edge_weight = max((d["weight"] for _, _, d in graph.edges(data=True)), default=1)
        annotations = []
        for u, v, d in graph.edges(data=True):
            x0, y0 = pos[u]
            x1, y1 = pos[v]
            annotations.append(dict(
                x=x1, y=y1, ax=x0, ay=y0,
                xref="x", yref="y", axref="x", ayref="y",
                showarrow=True, arrowhead=3, arrowsize=1,
                arrowwidth=1 + 5 * (d["weight"] / max_edge_weight),
                arrowcolor=color_map[d["category"]],
                standoff=14, startstandoff=14,
            ))

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=node_x, y=node_y, mode="markers+text",
            text=nodes, textposition="top center", textfont=dict(size=10),
            marker=dict(size=node_size, color=node_color, line=dict(width=1.5, color="white")),
            customdata=[node_weight[n] for n in nodes],
            hovertemplate="<b>%{text}</b><br>Flux impliqués: %{customdata}<extra></extra>",
            showlegend=False,
        ))
        # Traces "fantômes" (aucun point réel, x/y=None) uniquement pour faire
        # apparaître chaque catégorie dans la légende avec sa couleur — les liens
        # eux-mêmes sont dessinés via des annotations fléchées (ci-dessus), qui ne
        # génèrent pas d'entrée de légende.
        for cat in category_order:
            fig.add_trace(go.Scatter(
                x=[None], y=[None], mode="markers",
                marker=dict(size=10, color=color_map[cat]),
                name=cat, hoverinfo="skip",
            ))

        fig.update_layout(
            annotations=annotations,
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0, font=dict(size=10)),
            xaxis=dict(visible=False),
            yaxis=dict(visible=False),
            height=650,
            margin=dict(l=10, r=10, t=10, b=10),
            **_TRANSPARENT_LAYOUT,
        )
        st.caption(f"{graph.number_of_nodes()} IP, {graph.number_of_edges()} liens ({level})")
        st.plotly_chart(fig, width='stretch')


# Ordre de colonnes fixe pour la table des menaces prioritaires (affichage ET
# téléchargement) : "score_confiance" reste le nom technique de la colonne (utilisé
# tel quel dans le CSV téléchargé), seul l'affichage à l'écran le renomme (voir
# _section_priority_threats_table) pour éviter la confusion avec "score_anomalie" juste à côté.
_PRIORITY_THREATS_COLUMNS = [
    "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp",
    "classification", "score_confiance", "score_anomalie", "anomalie",
    "suricata_alerte", "suricata_signature", "niveau_risque", "raison",
]


# ===== Section 4 : tableau des menaces prioritaires + téléchargement =====
def _section_priority_threats_table(df: pd.DataFrame) -> None:
    st.divider()
    st.subheader("Menaces prioritaires (CRITIQUE + ELEVE)")

    threats = df[df["niveau_risque"].isin(["CRITIQUE", "ELEVE"])].copy()
    if threats.empty:
        st.info("Aucune menace CRITIQUE ou ELEVE détectée.")
        return

    with st.container(border=True):
        risk_rank = {"CRITIQUE": 0, "ELEVE": 1}
        threats["_rang"] = threats["niveau_risque"].map(risk_rank)
        threats = threats.sort_values(
            ["_rang", "score_confiance"], ascending=[True, False], na_position="last"
        ).drop(columns="_rang")

        display_cols = [c for c in _PRIORITY_THREATS_COLUMNS if c in threats.columns]
        threats = threats[display_cols]

        st.caption(f"{len(threats)} flux au total — aperçu des 50 premiers ci-dessous.")
        display_df = threats.head(50).rename(columns={"score_confiance": "confiance_classification"})
        st.dataframe(display_df, width='stretch', hide_index=True)

        csv_bytes = threats.to_csv(index=False).encode("utf-8")
        st.download_button(
            f"Télécharger les {len(threats)} flux CRITIQUE + ELEVE (CSV)",
            data=csv_bytes,
            file_name="menaces_prioritaires.csv",
            mime="text/csv",
        )


# ===== Section 5 : distribution temporelle des menaces =====
def _section_temporal_distribution(df: pd.DataFrame) -> None:
    st.divider()
    st.subheader("Distribution temporelle des menaces")

    threats = df[df["niveau_risque"].isin(["CRITIQUE", "ELEVE", "MOYEN"])].copy()
    if threats.empty:
        st.info("Aucune menace CRITIQUE, ELEVE ou MOYEN à situer dans le temps.")
        return

    # Format CICFlowMeter connu ("06/07/2017 12:59:17 PM") : le préciser évite le repli
    # sur dateutil (lent, et émet un avertissement) pour un format déjà homogène.
    threats["Timestamp"] = pd.to_datetime(
        threats["Timestamp"], format="%d/%m/%Y %I:%M:%S %p", errors="coerce"
    )
    threats = threats.dropna(subset=["Timestamp"])
    if threats.empty:
        st.info("Horodatages illisibles — impossible de tracer la distribution temporelle.")
        return

    with st.container(border=True):
        total_seconds = (threats["Timestamp"].max() - threats["Timestamp"].min()).total_seconds()
        # Fréquence de regroupement adaptée à la durée totale du PCAP : trop fine sur un
        # PCAP long produirait des centaines de barres illisibles, trop grossière sur un
        # PCAP court écraserait toute variation utile.
        if total_seconds <= 120:
            freq = "1s"
        elif total_seconds <= 3600:
            freq = "1min"
        elif total_seconds <= 6 * 3600:
            freq = "5min"
        else:
            freq = "15min"

        grouped = (
            threats.groupby([pd.Grouper(key="Timestamp", freq=freq), "niveau_risque"])
            .size()
            .unstack(fill_value=0)
        )
        for level in ("CRITIQUE", "ELEVE", "MOYEN"):
            if level not in grouped.columns:
                grouped[level] = 0

        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=grouped.index, y=grouped["CRITIQUE"], name="CRITIQUE",
            marker=dict(color=_COLOR_CRITIQUE),
            hovertemplate="<b>%{x}</b><br>CRITIQUE: %{y}<extra></extra>",
        ))
        fig.add_trace(go.Bar(
            x=grouped.index, y=grouped["ELEVE"], name="ELEVE",
            marker=dict(color=_COLOR_ELEVE),
            hovertemplate="<b>%{x}</b><br>ELEVE: %{y}<extra></extra>",
        ))
        fig.add_trace(go.Bar(
            x=grouped.index, y=grouped["MOYEN"], name="MOYEN",
            marker=dict(color=_COLOR_MOYEN),
            hovertemplate="<b>%{x}</b><br>MOYEN: %{y}<extra></extra>",
        ))
        fig.update_layout(
            barmode="stack",
            height=420,
            margin=dict(l=10, r=10, t=40, b=60),
            title=f"Menaces dans le temps (tranches de {freq})",
            xaxis=dict(title="Temps"),
            yaxis=dict(title="Nombre de flux"),
            legend=dict(title="Niveau"),
            **_TRANSPARENT_LAYOUT,
        )
        st.plotly_chart(fig, width='stretch')


# ===== Section 6 : types d'attaques détectées par le classifieur =====
def _section_attack_classes(df: pd.DataFrame) -> None:
    st.divider()
    st.subheader(f"Classes prédites avec confiance ≥ {RISK_CLASSIFIER_CONFIDENCE_THRESHOLD}")

    confident = df[df["score_confiance"] >= RISK_CLASSIFIER_CONFIDENCE_THRESHOLD]
    if confident.empty:
        st.info(f"Aucun flux avec une confiance ≥ {RISK_CLASSIFIER_CONFIDENCE_THRESHOLD}.")
        return

    with st.container(border=True):
        benign_count = int((confident["classification"] == "Benign").sum())
        attack_counts = confident.loc[confident["classification"] != "Benign", "classification"].value_counts()

        col1, col2 = st.columns([1, 3])
        with col1:
            _render_metric_cards([
                (f"Flux Benign (confiance ≥ {RISK_CLASSIFIER_CONFIDENCE_THRESHOLD})", benign_count, _COLOR_NORMAL, None),
            ])
        with col2:
            if attack_counts.empty:
                st.info("Aucune classe d'attaque prédite avec cette confiance.")
            else:
                attack_counts = attack_counts.sort_values()
                fig = go.Figure(data=[go.Bar(
                    x=attack_counts.values, y=attack_counts.index, orientation="h",
                    marker=dict(color=_COLOR_CRITIQUE),
                    hovertemplate="<b>%{y}</b><br>Flux: %{x}<extra></extra>",
                )])
                fig.update_layout(
                    height=max(300, 35 * len(attack_counts)),
                    margin=dict(l=10, r=10, t=10, b=10),
                    xaxis=dict(title="Nombre de flux"),
                    **_TRANSPARENT_LAYOUT,
                )
                st.plotly_chart(fig, width='stretch')


# ===== Section 7 : signatures Suricata (flux MOYEN où Suricata est seul en cause) =====
def _section_suricata_signatures(df: pd.DataFrame) -> None:
    st.divider()
    st.subheader("Signatures Suricata (flux MOYEN)")
    st.caption(
        "Seuls les flux MOYEN pour lesquels Suricata est la seule source déclenchée (alerte "
        "de sévérité 1 ou 2, non confirmée par le classifieur ni le détecteur d'anomalies) "
        "sont comptés ici."
    )

    moyen_alerts = df[(df["niveau_risque"] == "MOYEN") & (df["signal_suricata"] == "oui")]
    if moyen_alerts.empty:
        st.info("Aucune signature Suricata parmi les flux MOYEN.")
        return

    with st.container(border=True):
        sig_counts = moyen_alerts["suricata_signature"].value_counts().head(20).sort_values()
        fig = go.Figure(data=[go.Bar(
            x=sig_counts.values, y=sig_counts.index, orientation="h",
            marker=dict(color=_COLOR_ACCENT),
            hovertemplate="<b>%{y}</b><br>Flux: %{x}<extra></extra>",
        )])
        fig.update_layout(
            height=max(400, 28 * len(sig_counts)),
            margin=dict(l=10, r=10, t=40, b=10),
            title="Top 20 signatures Suricata (par nombre de flux, niveau MOYEN)",
            xaxis=dict(title="Nombre de flux"),
            yaxis=dict(tickfont=dict(size=10)),
            **_TRANSPARENT_LAYOUT,
        )
        st.plotly_chart(fig, width='stretch')


# ===== Section 8 : types d'événements Suricata (eve.json, tous types) =====
def _section_event_types(event_type_counts: Dict[str, int]) -> None:
    st.divider()
    st.subheader("Types d'événements Suricata (eve.json)")
    st.caption(
        "Vue d'ensemble de tout ce que Suricata a journalisé pour ce PCAP (alert, "
        "flow, dns, http, tls, ssh, fileinfo, stats, ...), pas seulement les alertes."
    )

    if not event_type_counts:
        st.info("Aucun événement trouvé dans eve.json.")
        return

    with st.container(border=True):
        counts = pd.Series(event_type_counts).sort_values(ascending=False)
        fig = go.Figure(data=[go.Bar(
            x=counts.index, y=counts.values,
            marker=dict(color=_COLOR_TOTAL),
            hovertemplate="<b>%{x}</b><br>Occurrences: %{y}<extra></extra>",
        )])
        fig.update_layout(
            height=420,
            margin=dict(l=10, r=10, t=10, b=60),
            xaxis=dict(title="Type d'événement", tickangle=-30),
            yaxis=dict(title="Nombre d'occurrences"),
            **_TRANSPARENT_LAYOUT,
        )
        st.plotly_chart(fig, width='stretch')
