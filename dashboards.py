import streamlit as st
from typing import Any, Dict
import plotly.graph_objects as go
import pandas as pd


def _display_alerts_statistics(alerts_data: Dict[str, Any]) -> None:
    """Affiche les statistiques des alertes.
    
    Args:
        alerts_data: Données des alertes parsées
    """
    st.divider()
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Nombre d'alertes", alerts_data["alert_count"])
    with col2:
        st.metric("Total d'événements", alerts_data["total_events"])
    with col3:
        st.metric("Types d'événements", len(alerts_data["event_types"]))
    
    # Détails des types d'événements
    st.write("**Distribution des événements :**")
    event_dist = alerts_data["event_types"]
    if event_dist:
        st.bar_chart(event_dist)


def _display_alerts_charts(alerts_data: Dict[str, Any]) -> None:
    """Affiche les graphiques d'analyse des alertes.
    
    Args:
        alerts_data: Données des alertes parsées
    """
    st.divider()
    if alerts_data.get("alert_categories"):
        st.subheader("Distribution des catégories d'alertes")
        
        categories_data = alerts_data["alert_categories"]
        
        # Créer un dataframe pour le pie chart
        cat_df = pd.DataFrame({
            "Catégorie": list(categories_data.keys()),
            "Nombre d'alertes": list(categories_data.values())
        }).sort_values('Nombre d\'alertes', ascending=False)
        
        # Afficher le pie chart
        fig = go.Figure(data=[go.Pie(
            labels=cat_df['Catégorie'],
            values=cat_df['Nombre d\'alertes'],
            textposition='auto',
            textinfo='label+percent',
            hovertemplate='<b>%{label}</b><br>Alertes: %{value}<br>Pourcentage: %{percent}<extra></extra>',
            marker=dict(line=dict(color='white', width=2))
        )])
        
        fig.update_layout(
            height=600,
            showlegend=True,
            font=dict(size=12),
            title={
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 18}
            },
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)'
        )
        
        st.plotly_chart(fig, use_container_width='stretch')
        


