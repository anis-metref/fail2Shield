"""
Fail2Shield Dashboard - Main Streamlit Application
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
from datetime import datetime, timedelta
import time
import threading
from typing import Dict, List
import config
import utils
from fail2ban_manager import Fail2banManager
import performance_config

# Optional imports for map functionality
try:
    import folium
    from streamlit_folium import st_folium
    MAP_AVAILABLE = True
except ImportError:
    MAP_AVAILABLE = False
    st.warning("Modules de cartographie non installés. Installez avec: pip install folium streamlit-folium")

# Page configuration
st.set_page_config(
    page_title=config.APP_TITLE,
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for modern UI
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1f77b4 0%, #dc3545 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        border-left: 4px solid #667eea;
    }
    
    .status-active {
        color: #28a745;
        font-weight: bold;
    }
    
    .status-inactive {
        color: #dc3545;
        font-weight: bold;
    }
    
    .jail-card {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        margin: 0.5rem 0;
        border-left: 4px solid #17a2b8;
    }
    
    .ip-info {
        background: #e9ecef;
        padding: 0.5rem;
        border-radius: 5px;
        margin: 0.2rem 0;
        font-size: 0.9rem;
    }
</style>
""", unsafe_allow_html=True)

class Fail2ShieldApp:
    """Main application class"""
    
    def __init__(self):
        self.manager = Fail2banManager()
        self.check_system_status()
        self.initialize_session_state()
        self.initialize_cache()
    
    def check_system_status(self):
        """Check system status and display warnings if needed"""
        if not self.manager.is_fail2ban_running():
            st.error("Fail2ban n'est pas en cours d'exécution. Veuillez démarrer le service fail2ban.")
            st.info("Commande: `sudo systemctl start fail2ban`")
            st.stop()
    
    def initialize_session_state(self):
        """Initialize Streamlit session state variables"""
        if 'last_update' not in st.session_state:
            st.session_state.last_update = datetime.now()
        if 'auto_refresh' not in st.session_state:
            st.session_state.auto_refresh = True
        if 'jails_data' not in st.session_state:
            st.session_state.jails_data = []
        if 'banned_ips_data' not in st.session_state:
            st.session_state.banned_ips_data = {}
        if 'show_config_editor' not in st.session_state:
            st.session_state.show_config_editor = False
        if 'editing_jail' not in st.session_state:
            st.session_state.editing_jail = None
        if 'data_cache' not in st.session_state:
            st.session_state.data_cache = {}
        if 'cache_timestamp' not in st.session_state:
            st.session_state.cache_timestamp = {}
        if 'current_tab' not in st.session_state:
            st.session_state.current_tab = 0
    
    def initialize_cache(self):
        """Initialize caching system"""
        self.cache_duration = 30  # Cache duration in seconds
        self.geo_cache_duration = 3600  # Geolocation cache for 1 hour
    
    def refresh_data(self, force=False):
        """Refresh all data from fail2ban with caching and session preservation"""
        try:
            current_time = datetime.now()
            
            # Check if we need to refresh based on cache
            if not force and self.is_data_cached('jails_data', current_time):
                return
            
            # Preserve session state if enabled
            preserve_session = st.session_state.get('preserve_session', True)
            
            # Store current UI state before refresh
            if preserve_session:
                ui_state = {
                    'show_config_editor': st.session_state.get('show_config_editor', False),
                    'editing_jail': st.session_state.get('editing_jail', None),
                    'auto_refresh': st.session_state.get('auto_refresh', True)
                }
            
            with st.spinner("Actualisation des données..."):
                # Refresh jails data
                st.session_state.jails_data = self.manager.get_all_jails_status()
                st.session_state.cache_timestamp['jails_data'] = current_time
                
                # Refresh banned IPs data
                st.session_state.banned_ips_data = self.manager.get_banned_ips()
                st.session_state.cache_timestamp['banned_ips'] = current_time
                
                st.session_state.last_update = current_time
                
                # Restore UI state if preservation is enabled
                if preserve_session:
                    for key, value in ui_state.items():
                        st.session_state[key] = value
                
        except Exception as e:
            st.error(f"Erreur lors de l'actualisation: {str(e)}")
            # Don't destroy session on error
            if not st.session_state.get('preserve_session', True):
                st.info("Essayez d'activer le 'Mode préservation session' pour éviter les erreurs")
    
    def is_data_cached(self, data_type, current_time):
        """Check if data is still valid in cache"""
        if data_type not in st.session_state.cache_timestamp:
            return False
        
        last_update = st.session_state.cache_timestamp[data_type]
        time_diff = (current_time - last_update).total_seconds()
        
        return time_diff < self.cache_duration
    
    def render_header(self):
        """Render the main header"""
        st.markdown(f"""
        <div class="main-header">
            <h1>{config.APP_TITLE}</h1>
            <p>Monitoring et gestion en temps réel de Fail2ban</p>
        </div>
        """, unsafe_allow_html=True)
    
    def render_sidebar(self):
        """Render the sidebar with controls"""
        st.sidebar.title("Contrôles")
        
        # Refresh controls
        st.sidebar.subheader("Actualisation")
        
        # Single refresh button
        if st.sidebar.button("Actualiser maintenant", use_container_width=True):
            self.refresh_data(force=True)
            # Preserve current tab when refreshing
            st.success("Données actualisées !")
        
        st.session_state.auto_refresh = st.sidebar.checkbox(
            "Actualisation automatique", 
            value=st.session_state.auto_refresh
        )
        
        if st.session_state.auto_refresh:
            refresh_interval = st.sidebar.slider(
                "Intervalle (minutes)", 
                min_value=1, 
                max_value=30, 
                value=5,
                help="Fréquence d'actualisation automatique"
            )
            # Convert minutes to seconds for internal use
            refresh_interval_seconds = refresh_interval * 60
        
        # System status
        st.sidebar.subheader("État du système")
        server_status = self.manager.get_server_status()
        
        if server_status['running']:
            st.sidebar.success("Fail2ban actif")
            if server_status.get('version'):
                st.sidebar.info(f"Version: {server_status['version']}")
            
            # Show jail statistics
            st.sidebar.metric("Jails totales", server_status.get('total_jails', 0))
            st.sidebar.metric("Jails actives", server_status.get('active_jails', 0))
        else:
            st.sidebar.error("Fail2ban inactif")
            st.sidebar.warning("Veuillez démarrer fail2ban")
        
        # Last update info and status
        st.sidebar.subheader("État de l'application")
        st.sidebar.info(f"Dernière MAJ: {st.session_state.last_update.strftime('%H:%M:%S')}")
        
        # Set session preservation to always true (no UI control needed)
        st.session_state.preserve_session = True
        
        return st.session_state.auto_refresh
    
    def render_metrics_overview(self):
        """Render overview metrics"""
        jails_data = st.session_state.jails_data
        banned_ips_data = st.session_state.banned_ips_data
        
        # Calculate metrics
        active_jails = len([j for j in jails_data if j.get('enabled', False)])
        total_failures = sum(j.get('total_failed', 0) for j in jails_data)
        total_banned_historical = sum(j.get('total_banned', 0) for j in jails_data)
        currently_banned = sum(len(ips) for ips in banned_ips_data.values())
        
        # Display metrics in columns
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                label="Jails Actives",
                value=active_jails,
                delta=f"sur {len(jails_data)} total"
            )
        
        with col2:
            st.metric(
                label="Tentatives Échouées",
                value=f"{total_failures:,}",
                delta="Total historique"
            )
        
        with col3:
            st.metric(
                label="IPs Bannies (Total)",
                value=f"{total_banned_historical:,}",
                delta="Historique"
            )
        
        with col4:
            st.metric(
                label="IPs Bannies (Actuel)",
                value=currently_banned,
                delta="En cours"
            )
    
    def render_charts(self):
        """Render interactive charts"""
        jails_data = st.session_state.jails_data
        banned_ips_data = st.session_state.banned_ips_data
        
        if not jails_data:
            st.warning("Aucune donnée de jail disponible")
            return
        
        # SSH Connection Analysis
        self.render_ssh_analysis()
        
        st.divider()
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Failures by jail chart
            st.subheader("Tentatives d'attaque par Jail")
            
            jail_names = [j['name'] for j in jails_data if j.get('enabled', False)]
            jail_failures = [j.get('total_failed', 0) for j in jails_data if j.get('enabled', False)]
            jail_currently_banned = [j.get('currently_banned', 0) for j in jails_data if j.get('enabled', False)]
            
            if jail_names and any(jail_failures):
                # Create horizontal bar chart with additional info
                fig_failures = go.Figure()
                
                # Add bars for total failures
                fig_failures.add_trace(go.Bar(
                    y=jail_names,
                    x=jail_failures,
                    name='Tentatives totales',
                    orientation='h',
                    marker_color='#dc3545',
                    text=[f'{val:,}' for val in jail_failures],
                    textposition='auto',
                    hovertemplate="<b>%{y}</b><br>Tentatives: %{x:,}<extra></extra>"
                ))
                
                # Add bars for currently banned
                fig_failures.add_trace(go.Bar(
                    y=jail_names,
                    x=jail_currently_banned,
                    name='IPs bannies actuellement',
                    orientation='h',
                    marker_color='#ffc107',
                    text=[f'{val}' if val > 0 else '' for val in jail_currently_banned],
                    textposition='auto',
                    hovertemplate="<b>%{y}</b><br>IPs bannies: %{x}<extra></extra>"
                ))
                
                fig_failures.update_layout(
                    title="Activité de sécurité par service",
                    xaxis_title="Nombre",
                    yaxis_title="Services",
                    barmode='overlay',
                    showlegend=True,
                    legend=dict(
                        orientation="h",
                        yanchor="bottom",
                        y=1.02,
                        xanchor="right",
                        x=1
                    ),
                    height=400
                )
                
                st.plotly_chart(fig_failures, use_container_width=True)
            else:
                st.info("Aucune tentative d'intrusion enregistrée")
        
        with col2:
            # Banned IPs by jail chart
            st.subheader("IPs Bannies par Jail")
            
            banned_counts = {jail: len(ips) for jail, ips in banned_ips_data.items() if ips}
            
            # Debug: Check if we have data
            if not banned_counts:
                st.info("Aucune IP actuellement bannie")
                return
            
            if banned_counts:
                # Prepare simple data for sunburst chart
                labels = []
                parents = []
                values = []
                
                # Add root
                labels.append("IPs Bannies")
                parents.append("")
                values.append(sum(banned_counts.values()))
                
                # Add jails as children of root
                for jail, count in banned_counts.items():
                    labels.append(jail)
                    parents.append("IPs Bannies")
                    values.append(count)
                    
                    ips = banned_ips_data[jail]
                    
                    # Add IPs directly as children of jails (simplified)
                    for ip in ips:
                        labels.append(ip)
                        parents.append(jail)
                        values.append(1)
                
                # Create simple sunburst chart
                fig_banned = go.Figure(go.Sunburst(
                    labels=labels,
                    parents=parents,
                    values=values,
                ))
                
                # Update layout for tight margin
                fig_banned.update_layout(
                    margin=dict(t=30, l=0, r=0, b=0),
                    title="Distribution des IPs bannies",
                    height=400
                )
                
                st.plotly_chart(fig_banned, use_container_width=True)
                
                # Show simple summary instead of color legend
                st.write("**Résumé:**")
                summary_col1, summary_col2 = st.columns(2)
                
                with summary_col1:
                    st.write("**Services avec IPs bannies:**")
                    for jail, count in banned_counts.items():
                        st.write(f"• {jail}: {count} IPs")
                
                with summary_col2:
                    st.write("**Pays:**")
                    # Country flags mapping
                    country_flags = {
                        'France': '🇫🇷',
                        'Chine': '🇨🇳',
                        'China': '🇨🇳',
                        'Russie': '🇷🇺',
                        'Russia': '🇷🇺',
                        'États-Unis': '🇺🇸',
                        'United States': '🇺🇸',
                        'Allemagne': '🇩🇪',
                        'Germany': '🇩🇪',
                        'Brésil': '🇧🇷',
                        'Brazil': '🇧🇷',
                        'Inde': '🇮🇳',
                        'India': '🇮🇳',
                        'Japon': '🇯🇵',
                        'Japan': '🇯🇵',
                        'Royaume-Uni': '🇬🇧',
                        'United Kingdom': '🇬🇧',
                        'Canada': '🇨🇦',
                        'Italie': '🇮🇹',
                        'Italy': '🇮🇹',
                        'Espagne': '🇪🇸',
                        'Spain': '🇪🇸',
                        'Pays-Bas': '🇳🇱',
                        'Netherlands': '🇳🇱',
                        'Corée du Sud': '🇰🇷',
                        'South Korea': '🇰🇷',
                        'Australie': '🇦🇺',
                        'Australia': '🇦🇺',
                        'Mexique': '🇲🇽',
                        'Mexico': '🇲🇽',
                        'Argentine': '🇦🇷',
                        'Argentina': '🇦🇷',
                        'Turquie': '🇹🇷',
                        'Turkey': '🇹🇷',
                        'Pologne': '🇵🇱',
                        'Poland': '🇵🇱',
                        'Ukraine': '🇺🇦',
                        'Suède': '🇸🇪',
                        'Sweden': '🇸🇪',
                        'Norvège': '🇳🇴',
                        'Norway': '🇳🇴',
                        'Finlande': '🇫🇮',
                        'Finland': '🇫🇮',
                        'Suisse': '🇨🇭',
                        'Switzerland': '🇨🇭',
                        'Autriche': '🇦🇹',
                        'Austria': '🇦🇹',
                        'Belgique': '🇧🇪',
                        'Belgium': '🇧🇪',
                        'Portugal': '🇵🇹',
                        'Grèce': '🇬🇷',
                        'Greece': '🇬🇷',
                        'République tchèque': '🇨🇿',
                        'Czech Republic': '🇨🇿',
                        'Hongrie': '🇭🇺',
                        'Hungary': '🇭🇺',
                        'Roumanie': '🇷🇴',
                        'Romania': '🇷🇴',
                        'Bulgarie': '🇧🇬',
                        'Bulgaria': '🇧🇬',
                        'Croatie': '🇭🇷',
                        'Croatia': '🇭🇷',
                        'Slovénie': '🇸🇮',
                        'Slovenia': '🇸🇮',
                        'Slovaquie': '🇸🇰',
                        'Slovakia': '🇸🇰',
                        'Estonie': '🇪🇪',
                        'Estonia': '🇪🇪',
                        'Lettonie': '🇱🇻',
                        'Latvia': '🇱🇻',
                        'Lituanie': '🇱🇹',
                        'Lithuania': '🇱🇹',
                        'Iran': '🇮🇷',
                        'Irak': '🇮🇶',
                        'Iraq': '🇮🇶',
                        'Israël': '🇮🇱',
                        'Israel': '🇮🇱',
                        'Arabie Saoudite': '🇸🇦',
                        'Saudi Arabia': '🇸🇦',
                        'Émirats arabes unis': '🇦🇪',
                        'United Arab Emirates': '🇦🇪',
                        'Égypte': '🇪🇬',
                        'Egypt': '🇪🇬',
                        'Afrique du Sud': '🇿🇦',
                        'South Africa': '🇿🇦',
                        'Nigeria': '🇳🇬',
                        'Kenya': '🇰🇪',
                        'Maroc': '🇲🇦',
                        'Morocco': '🇲🇦',
                        'Algérie': '🇩🇿',
                        'Algeria': '🇩🇿',
                        'Tunisie': '🇹🇳',
                        'Tunisia': '🇹🇳',
                        'Thaïlande': '🇹🇭',
                        'Thailand': '🇹🇭',
                        'Vietnam': '🇻🇳',
                        'Singapour': '🇸🇬',
                        'Singapore': '🇸🇬',
                        'Malaisie': '🇲🇾',
                        'Malaysia': '🇲🇾',
                        'Indonésie': '🇮🇩',
                        'Indonesia': '🇮🇩',
                        'Philippines': '🇵🇭',
                        'Pakistan': '🇵🇰',
                        'Bangladesh': '🇧🇩',
                        'Sri Lanka': '🇱🇰',
                        'Myanmar': '🇲🇲',
                        'Cambodge': '🇰🇭',
                        'Cambodia': '🇰🇭',
                        'Laos': '🇱🇦',
                        'Mongolie': '🇲🇳',
                        'Mongolia': '🇲🇳',
                        'Kazakhstan': '🇰🇿',
                        'Ouzbékistan': '🇺🇿',
                        'Uzbekistan': '🇺🇿',
                        'Kirghizistan': '🇰🇬',
                        'Kyrgyzstan': '🇰🇬',
                        'Tadjikistan': '🇹🇯',
                        'Tajikistan': '🇹🇯',
                        'Turkménistan': '🇹🇲',
                        'Turkmenistan': '🇹🇲',
                        'Azerbaïdjan': '🇦🇿',
                        'Azerbaijan': '🇦🇿',
                        'Arménie': '🇦🇲',
                        'Armenia': '🇦🇲',
                        'Géorgie': '🇬🇪',
                        'Georgia': '🇬🇪',
                        'Biélorussie': '🇧🇾',
                        'Belarus': '🇧🇾',
                        'Moldavie': '🇲🇩',
                        'Moldova': '🇲🇩',
                        'Non déterminé': '🏴‍☠️',
                        'Unknown': '🏴‍☠️',
                        'Réseau Local': '🏠',
                        'Réseau Privé': '🏠',
                        'Non disponible': '❓'
                    }
                    
                    # Show countries that appear in the data
                    data_countries = {}
                    for ips in banned_ips_data.values():
                        for ip in ips:
                            geo_info = utils.get_ip_geolocation(ip)
                            country = geo_info.get('country', 'Non déterminé') if geo_info else 'Non déterminé'
                            data_countries[country] = data_countries.get(country, 0) + 1
                    
                    for country, count in sorted(data_countries.items(), key=lambda x: x[1], reverse=True):
                        flag = country_flags.get(country, '🌍')  # Default globe emoji
                        st.write(f"{flag} {country}: {count} IPs")
                
                # Add summary table below the chart
                st.write("**Résumé détaillé:**")
                summary_data = []
                for jail, count in banned_counts.items():
                    ips = banned_ips_data[jail]
                    
                    # Get countries for this jail
                    countries = []
                    for ip in ips:
                        geo_info = utils.get_ip_geolocation(ip)
                        country = geo_info.get('country', 'Non disponible') if geo_info else 'Non disponible'
                        if country not in countries and country != 'Non disponible':
                            countries.append(country)
                    
                    countries_str = ', '.join(countries[:3])
                    if len(countries) > 3:
                        countries_str += f" (+{len(countries)-3})"
                    
                    summary_data.append({
                        'Service': jail,
                        'IPs Bannies': count,
                        'IPs': ', '.join(ips[:3]) + ('...' if len(ips) > 3 else ''),
                        'Pays': countries_str if countries_str else 'Non déterminé'
                    })
                
                df_summary = pd.DataFrame(summary_data)
                st.dataframe(df_summary, use_container_width=True, hide_index=True)
            else:
                st.info("Aucune IP actuellement bannie")
    
    def render_ssh_analysis(self):
        """Render SSH connection analysis"""
        st.subheader("Analyse des Connexions SSH")
        
        try:
            # Find SSH log file
            log_file = utils.find_ssh_log_file()
            
            if not log_file:
                st.warning("Aucun fichier de logs SSH trouvé ou accessible")
                st.info("Fichiers recherchés : /var/log/auth.log, /var/log/secure, /var/log/messages")
                st.info("Vérifiez les permissions ou lancez avec sudo")
                return
            
            st.info(f"Analyse du fichier : {log_file}")
            
            # Parse SSH logs
            ssh_entries = utils.parse_ssh_logs(log_file)
            
            if not ssh_entries:
                st.warning("Aucune donnée SSH trouvée dans les logs récents")
                st.info("Vérifiez que le service SSH est actif et génère des logs")
                return
            
            # Get SSH statistics
            ssh_stats = utils.get_ssh_connection_stats(ssh_entries)
            
            # Display metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric(
                    label="Connexions Réussies",
                    value=ssh_stats['total_accepted'],
                    delta="Dernières 24h"
                )
            
            with col2:
                st.metric(
                    label="Tentatives Échouées",
                    value=ssh_stats['total_failed'],
                    delta=f"dont {ssh_stats.get('total_failed_password', 0)} mots de passe"
                )
            
            with col3:
                st.metric(
                    label="IPs Uniques",
                    value=ssh_stats['unique_ips'],
                    delta="Total"
                )
            
            with col4:
                success_rate = 0
                if ssh_stats['total_accepted'] + ssh_stats['total_failed'] > 0:
                    success_rate = round((ssh_stats['total_accepted'] / (ssh_stats['total_accepted'] + ssh_stats['total_failed'])) * 100, 1)
                st.metric(
                    label="Taux de Réussite",
                    value=f"{success_rate}%",
                    delta="Global"
                )
            
            # Charts
            chart_col1, chart_col2 = st.columns(2)
            
            with chart_col1:
                # Success vs Failed pie chart
                if ssh_stats['total_accepted'] > 0 or ssh_stats['total_failed'] > 0:
                    fig_ssh_status = go.Figure(data=[go.Pie(
                        labels=['Connexions Réussies', 'Tentatives Échouées'],
                        values=[ssh_stats['total_accepted'], ssh_stats['total_failed']],
                        hole=0.4,
                        marker_colors=['#28a745', '#dc3545'],
                        textinfo='label+value+percent',
                        hovertemplate="<b>%{label}</b><br>Nombre: %{value}<br>Pourcentage: %{percent}<extra></extra>"
                    )])
                    
                    fig_ssh_status.update_layout(
                        title="Statut des Connexions SSH",
                        annotations=[dict(text='SSH', x=0.5, y=0.5, font_size=20, showarrow=False)]
                    )
                    
                    st.plotly_chart(fig_ssh_status, use_container_width=True)
            
            with chart_col2:
                # Top attacking IPs
                if ssh_stats['top_attacking_ips']:
                    top_attackers = dict(sorted(ssh_stats['top_attacking_ips'].items(), 
                                               key=lambda x: x[1], reverse=True)[:10])
                    
                    # Create hover text with geolocation
                    hover_texts = []
                    for ip in top_attackers.keys():
                        geo_info = utils.get_ip_geolocation(ip)
                        if geo_info:
                            hover_text = f"<b>{ip}</b><br>Tentatives: {top_attackers[ip]}<br>Pays: {geo_info.get('country', 'Unknown')}<br>Ville: {geo_info.get('city', 'Unknown')}<br>ISP: {geo_info.get('isp', 'Unknown')}"
                        else:
                            hover_text = f"<b>{ip}</b><br>Tentatives: {top_attackers[ip]}<br>Géolocalisation: Non disponible"
                        hover_texts.append(hover_text)
                    
                    fig_attackers = go.Figure(data=[go.Bar(
                        x=list(top_attackers.keys()),
                        y=list(top_attackers.values()),
                        marker_color='#dc3545',
                        hovertemplate="%{customdata}<extra></extra>",
                        customdata=hover_texts
                    )])
                    
                    fig_attackers.update_layout(
                        title="Top 10 IPs Attaquantes",
                        xaxis_title="Adresses IP",
                        yaxis_title="Nombre de tentatives",
                        xaxis_tickangle=-45
                    )
                    
                    st.plotly_chart(fig_attackers, use_container_width=True)
                else:
                    st.info("Aucune tentative d'attaque détectée")
            
            # Detailed tables
            if ssh_stats['accepted'] or ssh_stats['failed'] or ssh_stats['failed_password']:
                st.subheader("Détails des Connexions")
                
                tab1, tab2, tab3, tab4 = st.tabs(["Connexions Réussies", "Échecs Mot de Passe", "Autres Échecs", "Utilisateurs"])
                
                with tab1:
                    if ssh_stats['accepted']:
                        accepted_data = []
                        for ip, users in ssh_stats['accepted'].items():
                            geo_info = utils.get_ip_geolocation(ip)
                            accepted_data.append({
                                'IP': ip,
                                'Utilisateurs': ', '.join(set(users)),
                                'Connexions': len(users),
                                'Pays': geo_info.get('country', 'Non disponible'),
                                'Ville': geo_info.get('city', 'Non disponible'),
                                'ISP': geo_info.get('isp', 'Non disponible')
                            })
                        
                        df_accepted = pd.DataFrame(accepted_data)
                        st.dataframe(df_accepted, use_container_width=True, hide_index=True)
                    else:
                        st.info("Aucune connexion réussie récente")
                
                with tab2:
                    if ssh_stats['failed_password']:
                        password_failed_data = []
                        for ip, attempts in ssh_stats['failed_password'].items():
                            geo_info = utils.get_ip_geolocation(ip)
                            users = [attempt['user'] for attempt in attempts]
                            failure_types = [attempt['failure_type'] for attempt in attempts]
                            
                            password_failed_data.append({
                                'IP': ip,
                                'Utilisateurs Tentés': ', '.join(set(users)),
                                'Tentatives': len(attempts),
                                'Type d\'Échec': ', '.join(set(failure_types)),
                                'Pays': geo_info.get('country', 'Non disponible'),
                                'Ville': geo_info.get('city', 'Non disponible'),
                                'ISP': geo_info.get('isp', 'Non disponible')
                            })
                        
                        df_password_failed = pd.DataFrame(password_failed_data)
                        # Sort by number of attempts (descending)
                        df_password_failed = df_password_failed.sort_values('Tentatives', ascending=False)
                        st.dataframe(df_password_failed, use_container_width=True, hide_index=True)
                    else:
                        st.info("Aucun échec de mot de passe récent")
                
                with tab3:
                    if ssh_stats['failed']:
                        other_failed_data = []
                        for ip, attempts in ssh_stats['failed'].items():
                            geo_info = utils.get_ip_geolocation(ip)
                            users = [attempt['user'] if isinstance(attempt, dict) else attempt for attempt in attempts]
                            failure_types = [attempt['failure_type'] if isinstance(attempt, dict) else 'Autre échec' for attempt in attempts]
                            
                            other_failed_data.append({
                                'IP': ip,
                                'Utilisateurs Tentés': ', '.join(set(users)),
                                'Tentatives': len(attempts),
                                'Type d\'Échec': ', '.join(set(failure_types)),
                                'Pays': geo_info.get('country', 'Non disponible'),
                                'Ville': geo_info.get('city', 'Non disponible'),
                                'ISP': geo_info.get('isp', 'Non disponible')
                            })
                        
                        df_other_failed = pd.DataFrame(other_failed_data)
                        # Sort by number of attempts (descending)
                        df_other_failed = df_other_failed.sort_values('Tentatives', ascending=False)
                        st.dataframe(df_other_failed, use_container_width=True, hide_index=True)
                    else:
                        st.info("Aucune autre tentative échouée récente")
                
                with tab4:
                    user_col1, user_col2 = st.columns(2)
                    
                    with user_col1:
                        st.write("**Utilisateurs - Connexions Réussies**")
                        if ssh_stats['top_users_accepted']:
                            users_accepted = dict(sorted(ssh_stats['top_users_accepted'].items(), 
                                                       key=lambda x: x[1], reverse=True))
                            for user, count in list(users_accepted.items())[:10]:
                                st.write(f"• {user}: {count} connexions")
                        else:
                            st.info("Aucune donnée")
                    
                    with user_col2:
                        st.write("**Utilisateurs - Tentatives Échouées**")
                        if ssh_stats['top_users_failed']:
                            users_failed = dict(sorted(ssh_stats['top_users_failed'].items(), 
                                                     key=lambda x: x[1], reverse=True))
                            for user, count in list(users_failed.items())[:10]:
                                st.write(f"• {user}: {count} tentatives")
                        else:
                            st.info("Aucune donnée")
                
                # Show failure types statistics
                if ssh_stats.get('failure_types'):
                    st.subheader("Types d'Échecs")
                    failure_col1, failure_col2 = st.columns(2)
                    
                    with failure_col1:
                        # Failure types pie chart
                        fig_failure_types = go.Figure(data=[go.Pie(
                            labels=list(ssh_stats['failure_types'].keys()),
                            values=list(ssh_stats['failure_types'].values()),
                            textinfo='label+value+percent',
                            hovertemplate="<b>%{label}</b><br>Nombre: %{value}<br>Pourcentage: %{percent}<extra></extra>"
                        )])
                        
                        fig_failure_types.update_layout(
                            title="Répartition des Types d'Échecs",
                            showlegend=True
                        )
                        
                        st.plotly_chart(fig_failure_types, use_container_width=True)
                    
                    with failure_col2:
                        st.write("**Statistiques des Échecs**")
                        for failure_type, count in sorted(ssh_stats['failure_types'].items(), 
                                                         key=lambda x: x[1], reverse=True):
                            percentage = round((count / ssh_stats['total_failed']) * 100, 1) if ssh_stats['total_failed'] > 0 else 0
                            st.write(f"• **{failure_type}**: {count} ({percentage}%)")
                        
                        if ssh_stats.get('total_failed_password', 0) > 0:
                            st.write("---")
                            st.write(f"**Total échecs de mot de passe**: {ssh_stats['total_failed_password']}")
                            password_rate = round((ssh_stats['total_failed_password'] / ssh_stats['total_failed']) * 100, 1) if ssh_stats['total_failed'] > 0 else 0
                            st.write(f"**Pourcentage des échecs**: {password_rate}%")
        
        except Exception as e:
            st.error(f"Erreur lors de l'analyse SSH: {str(e)}")
            st.info("Vérifiez que le fichier /var/log/auth.log est accessible")
    
    def render_banned_ips_map(self, banned_ips_data):
        """Render interactive map of banned IPs"""
        if not MAP_AVAILABLE:
            st.error("Modules de cartographie non disponibles")
            return
            
        st.subheader("Carte Géographique des IPs Bannies")
        
        # Collect all IPs with geolocation
        map_data = []
        for jail_name, ips in banned_ips_data.items():
            if ips:
                for ip in ips:
                    geo_info = utils.get_ip_geolocation(ip)
                    if geo_info and geo_info.get('lat', 0) != 0 and geo_info.get('lon', 0) != 0:
                        map_data.append({
                            'ip': ip,
                            'jail': jail_name,
                            'lat': geo_info.get('lat', 0),
                            'lon': geo_info.get('lon', 0),
                            'country': geo_info.get('country', 'Non déterminé'),
                            'city': geo_info.get('city', 'Non déterminé'),
                            'isp': geo_info.get('isp', 'Non déterminé')
                        })
        
        if not map_data:
            st.warning("Aucune IP avec géolocalisation disponible pour afficher sur la carte")
            return
        
        # Create base map centered on world
        m = folium.Map(
            location=[20, 0],  # Center of world
            zoom_start=2,
            tiles='OpenStreetMap'
        )
        
        # Color mapping for different jails
        jail_colors = {
            'sshd': 'red',
            'apache-auth': 'blue', 
            'nginx-http-auth': 'green',
            'postfix': 'orange',
            'dovecot': 'purple'
        }
        
        # Add markers for each IP
        for data in map_data:
            jail_color = jail_colors.get(data['jail'], 'gray')
            
            # Create popup content
            popup_content = f"""
            <div style="width: 200px;">
                <h4 style="margin: 0; color: {jail_color};">{data['ip']}</h4>
                <hr style="margin: 5px 0;">
                <b>Jail:</b> {data['jail']}<br>
                <b>Pays:</b> {data['country']}<br>
                <b>Ville:</b> {data['city']}<br>
                <b>ISP:</b> {data['isp']}
            </div>
            """
            
            folium.CircleMarker(
                location=[data['lat'], data['lon']],
                radius=8,
                popup=folium.Popup(popup_content, max_width=250),
                color='white',
                weight=2,
                fillColor=jail_color,
                fillOpacity=0.7,
                tooltip=f"{data['ip']} ({data['country']})"
            ).add_to(m)
        
        # Add legend
        legend_html = '''
        <div style="position: fixed; 
                    bottom: 50px; left: 50px; width: 150px; height: auto; 
                    background-color: white; border:2px solid grey; z-index:9999; 
                    font-size:14px; padding: 10px">
        <h4 style="margin: 0 0 10px 0;">Légende</h4>
        '''
        
        # Add jail colors to legend
        unique_jails = set(data['jail'] for data in map_data)
        for jail in unique_jails:
            color = jail_colors.get(jail, 'gray')
            legend_html += f'<p style="margin: 5px 0;"><span style="color: {color};">●</span> {jail}</p>'
        
        legend_html += '</div>'
        m.get_root().html.add_child(folium.Element(legend_html))
        
        # Display map
        map_data_result = st_folium(m, width=700, height=500)
        
        # Show statistics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("IPs sur la carte", len(map_data))
        
        with col2:
            countries = set(data['country'] for data in map_data)
            st.metric("Pays représentés", len(countries))
        
        with col3:
            jails = set(data['jail'] for data in map_data)
            st.metric("Jails concernées", len(jails))
        
        # Show country distribution
        if len(map_data) > 0:
            st.write("**Répartition par pays:**")
            country_counts = {}
            for data in map_data:
                country = data['country']
                country_counts[country] = country_counts.get(country, 0) + 1
            
            # Sort by count
            sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
            
            for country, count in sorted_countries[:10]:  # Top 10
                percentage = round((count / len(map_data)) * 100, 1)
                st.write(f"• {country}: {count} IPs ({percentage}%)")
    
    def render_jail_config_editor(self, jail_name, current_config):
        """Render jail configuration editor"""
        st.write("### Modifier Configuration")
        
        with st.form(f"config_form_{jail_name}"):
            st.write(f"**Configuration pour {jail_name}:**")
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Ban time configuration
                st.write("**Durée de bannissement:**")
                ban_type = st.radio(
                    "Type de ban",
                    ["Temporaire", "Permanent"],
                    key=f"ban_type_{jail_name}",
                    help="Temporaire: durée limitée, Permanent: jusqu'à débannissement manuel"
                )
                
                if ban_type == "Temporaire":
                    ban_duration = st.selectbox(
                        "Durée",
                        ["1 minute", "5 minutes", "10 minutes", "30 minutes", "1 heure", "6 heures", "12 heures", "24 heures", "7 jours"],
                        index=4,  # Default to 1 hour
                        key=f"ban_duration_{jail_name}"
                    )
                    
                    duration_map = {
                        "1 minute": 60,
                        "5 minutes": 300,
                        "10 minutes": 600,
                        "30 minutes": 1800,
                        "1 heure": 3600,
                        "6 heures": 21600,
                        "12 heures": 43200,
                        "24 heures": 86400,
                        "7 jours": 604800
                    }
                    bantime_value = duration_map[ban_duration]
                else:
                    bantime_value = -1
                    st.info("Bannissement permanent activé")
                
                # Max retry
                maxretry_value = st.number_input(
                    "Tentatives max",
                    min_value=1,
                    max_value=20,
                    value=int(current_config.get('maxretry', 5)),
                    key=f"maxretry_{jail_name}",
                    help="Nombre de tentatives avant bannissement"
                )
            
            with col2:
                # Find time
                st.write("**Période de détection:**")
                findtime_option = st.selectbox(
                    "Période",
                    ["5 minutes", "10 minutes", "30 minutes", "1 heure", "2 heures", "6 heures", "12 heures"],
                    index=3,  # Default to 1 hour
                    key=f"findtime_{jail_name}",
                    help="Période pendant laquelle compter les tentatives"
                )
                
                findtime_map = {
                    "5 minutes": 300,
                    "10 minutes": 600,
                    "30 minutes": 1800,
                    "1 heure": 3600,
                    "2 heures": 7200,
                    "6 heures": 21600,
                    "12 heures": 43200
                }
                findtime_value = findtime_map[findtime_option]
                
                # Preview
                st.write("**Aperçu:**")
                if bantime_value == -1:
                    ban_preview = "Permanent"
                else:
                    hours = bantime_value // 3600
                    minutes = (bantime_value % 3600) // 60
                    if hours > 0:
                        ban_preview = f"{hours}h {minutes}min"
                    else:
                        ban_preview = f"{minutes}min"
                
                find_hours = findtime_value // 3600
                find_minutes = (findtime_value % 3600) // 60
                if find_hours > 0:
                    find_preview = f"{find_hours}h {find_minutes}min"
                else:
                    find_preview = f"{find_minutes}min"
                
                st.success(f"• Ban: {ban_preview}\n• Max: {maxretry_value} tentatives\n• Période: {find_preview}")
            
            # Form buttons
            col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1])
            
            with col_btn1:
                if st.form_submit_button("Sauvegarder", use_container_width=True):
                    success = self.save_jail_config(jail_name, bantime_value, maxretry_value, findtime_value)
                    if success:
                        st.success("Configuration sauvegardée avec succès!")
                        st.session_state.show_config_editor = False
                        # Force data refresh without rerun
                        self.refresh_data(force=True)
                    else:
                        st.error("Erreur lors de la sauvegarde")
            
            with col_btn2:
                if st.form_submit_button("Annuler", use_container_width=True):
                    st.session_state.show_config_editor = False
                    # No rerun needed, just close editor
            
            with col_btn3:
                if st.form_submit_button("Réinitialiser", use_container_width=True):
                    success = self.reset_jail_config(jail_name)
                    if success:
                        st.success("Configuration réinitialisée!")
                        st.session_state.show_config_editor = False
                        # Force data refresh without rerun
                        self.refresh_data(force=True)
                    else:
                        st.error("Erreur lors de la réinitialisation")
    
    def save_jail_config(self, jail_name, bantime, maxretry, findtime):
        """Save jail configuration"""
        try:
            # Apply configuration changes
            success1, _, _ = utils.safe_execute_command([
                self.manager.client_path, 'set', jail_name, 'bantime', str(bantime)
            ])
            
            success2, _, _ = utils.safe_execute_command([
                self.manager.client_path, 'set', jail_name, 'maxretry', str(maxretry)
            ])
            
            success3, _, _ = utils.safe_execute_command([
                self.manager.client_path, 'set', jail_name, 'findtime', str(findtime)
            ])
            
            return success1 and success2 and success3
        except Exception as e:
            st.error(f"Erreur lors de la sauvegarde: {e}")
            return False
    
    def reset_jail_config(self, jail_name):
        """Reset jail configuration to defaults"""
        try:
            # Reload the jail to reset to default configuration
            success, message = self.manager.reload_jail(jail_name)
            return success
        except Exception as e:
            st.error(f"Erreur lors de la réinitialisation: {e}")
            return False
    
    def format_time_display(self, time_value, is_findtime=False):
        """Format time value for display"""
        if time_value == 'Non défini':
            return "Non défini"
        
        try:
            time_int = int(time_value)
            if time_int == -1 and not is_findtime:
                return "Permanent"
            elif time_int == 0:
                return "Aucun bannissement" if not is_findtime else "Immédiat"
            else:
                hours = time_int // 3600
                minutes = (time_int % 3600) // 60
                if hours > 0:
                    return f"{hours}h {minutes}min"
                else:
                    return f"{minutes}min"
        except:
            return f"{time_value} secondes"
    
    def execute_ban(self, jail_name, ip_address, ban_type, custom_bantime):
        """Execute IP ban with specified parameters"""
        if ban_type == "Permanent":
            return self.manager.ban_ip_with_time(jail_name, ip_address, -1)
        elif ban_type == "Temporaire personnalisé" and custom_bantime:
            return self.manager.ban_ip_with_time(jail_name, ip_address, custom_bantime)
        else:
            return self.manager.ban_ip(jail_name, ip_address)
    
    def render_jails_management(self):
        """Render jails management interface"""
        st.subheader("Gestion des Jails")
        
        jails_data = st.session_state.jails_data
        
        if not jails_data:
            st.warning("Aucune jail configurée")
            return
        
        for jail in jails_data:
            with st.expander(f"{jail['name']}", expanded=False):
                col1, col2, col3 = st.columns([2, 1, 1])
                
                with col1:
                    # Jail status and info
                    status_color = "status-active" if jail.get('enabled', False) else "status-inactive"
                    status_text = "Actif" if jail.get('enabled', False) else "Inactif"
                    
                    st.markdown(f"""
                    <div class="jail-card">
                        <h4>{jail['name']}</h4>
                        <p><strong>Statut:</strong> <span class="{status_color}">{status_text}</span></p>
                        <p><strong>Filtre:</strong> {jail.get('filter', 'N/A')}</p>
                        <p><strong>Actions:</strong> {', '.join(jail.get('actions', []))}</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    # Current metrics
                    st.metric("Échecs actuels", jail.get('currently_failed', 0))
                    st.metric("Bannies actuelles", jail.get('currently_banned', 0))
                
                with col3:
                    # Historical metrics
                    st.metric("Total échecs", jail.get('total_failed', 0))
                    st.metric("Total bannies", jail.get('total_banned', 0))
                
                # Jail configuration
                if jail.get('enabled', False):
                    config_data = self.manager.get_jail_config(jail['name'])
                    if config_data:
                        st.write("**Configuration:**")
                        config_cols = st.columns(len(config_data))
                        for i, (key, value) in enumerate(config_data.items()):
                            with config_cols[i % len(config_cols)]:
                                st.write(f"**{key}:** {value}")
    
    def render_ip_management(self):
        """Render IP management interface"""
        st.subheader("Gestion des IPs")
        
        # Manual IP ban section
        st.write("### Bannissement et Configuration")
        
        # Get jail configurations for ban times
        jail_configs = {}
        for jail_data in st.session_state.jails_data:
            if jail_data.get('enabled', False):
                config_data = self.manager.get_jail_config(jail_data['name'])
                jail_configs[jail_data['name']] = config_data
        
        # Main interface
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.write("**Bannissement d'IP:**")
            ip_to_ban = st.text_input("Adresse IP à bannir", placeholder="192.168.1.100")
            
            active_jails = [j['name'] for j in st.session_state.jails_data if j.get('enabled', False)]
            if active_jails:
                selected_jail = st.selectbox("Jail cible", active_jails)
            else:
                st.warning("Aucune jail active")
                selected_jail = None
        
        with col2:
            st.write("**Type de bannissement:**")
            ban_type = st.radio(
                "Choisir le type",
                ["Temporaire (selon jail)", "Temporaire personnalisé", "Permanent"],
                help="Temporaire: utilise la durée configurée\nPersonnalisé: durée spécifique\nPermanent: bannissement définitif"
            )
            
            if ban_type == "Temporaire personnalisé":
                custom_duration = st.selectbox(
                    "Durée personnalisée",
                    ["1 minute", "5 minutes", "10 minutes", "30 minutes", "1 heure", "6 heures", "12 heures", "24 heures", "7 jours"],
                    index=4
                )
                duration_map = {
                    "1 minute": 60, "5 minutes": 300, "10 minutes": 600, "30 minutes": 1800,
                    "1 heure": 3600, "6 heures": 21600, "12 heures": 43200, 
                    "24 heures": 86400, "7 jours": 604800
                }
                custom_bantime = duration_map[custom_duration]
            else:
                custom_bantime = None
        
        # Configuration and ban section
        if selected_jail:
            st.write("---")
            config_col1, config_col2, config_col3 = st.columns([2, 1, 1])
            
            with config_col1:
                # Show current configuration
                if selected_jail in jail_configs:
                    bantime = jail_configs[selected_jail].get('bantime', 'Non défini')
                    maxretry = jail_configs[selected_jail].get('maxretry', 'Non défini')
                    findtime = jail_configs[selected_jail].get('findtime', 'Non défini')
                    
                    # Format display
                    bantime_display = self.format_time_display(bantime)
                    findtime_display = self.format_time_display(findtime, is_findtime=True)
                    
                    st.info(f"**Configuration actuelle de {selected_jail}:**\n"
                           f"• Durée de ban: {bantime_display}\n"
                           f"• Tentatives max: {maxretry}\n"
                           f"• Période de détection: {findtime_display}")
            
            with config_col2:
                if st.button("Modifier Config", use_container_width=True):
                    st.session_state.show_config_editor = True
                    st.session_state.editing_jail = selected_jail
            
            with config_col3:
                if st.button("Bannir IP", disabled=not ip_to_ban, use_container_width=True):
                    if utils.validate_ip_address(ip_to_ban):
                        success, message = self.execute_ban(selected_jail, ip_to_ban, ban_type, custom_bantime)
                        if success:
                            st.success(f"{message}")
                            self.refresh_data(force=True)
                            # Data refreshed without rerun to preserve tab
                        else:
                            st.error(f"{message}")
                    else:
                        st.error("Format d'adresse IP invalide")
            
            # Configuration editor (appears below when activated)
            if st.session_state.get('show_config_editor', False) and st.session_state.get('editing_jail') == selected_jail:
                st.write("---")
                self.render_jail_config_editor(selected_jail, jail_configs[selected_jail])
        
        # Banned IPs display
        st.write("### IPs Actuellement Bannies")
        banned_ips_data = st.session_state.banned_ips_data
        
        if not banned_ips_data or not any(banned_ips_data.values()):
            st.info("Aucune IP actuellement bannie")
            return
        
        # Add map view option
        if MAP_AVAILABLE:
            view_option = st.radio(
                "Mode d'affichage:",
                ["Liste détaillée", "Carte géographique"],
                horizontal=True
            )
            
            if view_option == "Carte géographique":
                self.render_banned_ips_map(banned_ips_data)
                st.divider()
        else:
            st.info("Mode carte non disponible. Installez les dépendances: pip install folium streamlit-folium")
        
        st.write("### Liste Détaillée")
        
        for jail_name, ips in banned_ips_data.items():
            if ips:
                with st.expander(f"{jail_name} ({len(ips)} IPs)", expanded=False):
                    for ip in ips:
                        col1, col2, col3 = st.columns([2, 3, 1])
                        
                        with col1:
                            st.write(f"**{ip}**")
                        
                        with col2:
                            # Get geolocation info
                            geo_info = utils.get_ip_geolocation(ip)
                            if geo_info:
                                st.markdown(f"""
                                <div class="ip-info">
                                    📍 {geo_info.get('city', 'Unknown')}, {geo_info.get('region', 'Unknown')}, {geo_info.get('country', 'Unknown')}<br>
                                    🏢 {geo_info.get('isp', 'Unknown ISP')}
                                </div>
                                """, unsafe_allow_html=True)
                            else:
                                st.write("Informations géographiques non disponibles")
                        
                        with col3:
                            if st.button(f"Débannir", key=f"unban_{jail_name}_{ip}"):
                                success, message = self.manager.unban_ip(jail_name, ip)
                                if success:
                                    st.success(message)
                                    self.refresh_data(force=True)
                                    # Data refreshed without rerun to preserve tab
                                else:
                                    st.error(message)
    
    def render_logs_viewer(self):
        """Render logs viewer interface"""
        st.subheader("Visualiseur de Logs")
        
        # Log parsing options
        col1, col2 = st.columns([1, 1])
        
        with col1:
            lines_to_read = st.slider("Nombre de lignes à lire", 100, 5000, 1000)
        
        with col2:
            if st.button("Actualiser les logs"):
                # Force refresh without rerun to preserve tab state
                st.session_state.cache_timestamp.pop('logs', None)
                st.success("Logs actualisés !")
        
        # Parse and display logs
        try:
            log_entries = utils.parse_fail2ban_log(config.FAIL2BAN_LOG_PATH, lines_to_read)
            
            if log_entries:
                # Convert to DataFrame for better display
                df = pd.DataFrame(log_entries)
                
                # Filter options
                st.write("### Filtres")
                filter_col1, filter_col2, filter_col3 = st.columns(3)
                
                with filter_col1:
                    action_filter = st.selectbox(
                        "Action", 
                        ['Toutes'] + list(df['action'].unique()) if 'action' in df.columns else ['Toutes']
                    )
                
                with filter_col2:
                    jail_filter = st.selectbox(
                        "Jail", 
                        ['Toutes'] + list(df['jail'].unique()) if 'jail' in df.columns else ['Toutes']
                    )
                
                with filter_col3:
                    ip_filter = st.text_input("IP (partielle)", placeholder="192.168")
                
                # Apply filters
                filtered_df = df.copy()
                
                if action_filter != 'Toutes':
                    filtered_df = filtered_df[filtered_df['action'] == action_filter]
                
                if jail_filter != 'Toutes':
                    filtered_df = filtered_df[filtered_df['jail'] == jail_filter]
                
                if ip_filter:
                    filtered_df = filtered_df[filtered_df['ip'].str.contains(ip_filter, na=False)]
                
                # Display filtered logs
                st.write(f"### Logs ({len(filtered_df)} entrées)")
                
                if not filtered_df.empty:
                    # Format timestamp for display
                    display_df = filtered_df.copy()
                    display_df['timestamp'] = display_df['timestamp'].apply(utils.format_timestamp)
                    
                    st.dataframe(
                        display_df[['timestamp', 'jail', 'action', 'ip']],
                        use_container_width=True,
                        hide_index=True
                    )
                else:
                    st.info("Aucune entrée correspondant aux filtres")
            else:
                st.warning("Aucun log trouvé ou erreur de lecture")
                
        except Exception as e:
            st.error(f"Erreur lors de la lecture des logs: {str(e)}")
    
    def run(self):
        """Main application runner"""
        self.render_header()
        
        # Sidebar
        auto_refresh = self.render_sidebar()
        
        # Auto-refresh logic with intelligent caching
        if auto_refresh:
            # Use the configured interval (default 5 minutes)
            interval = refresh_interval_seconds if 'refresh_interval_seconds' in locals() else 300
            # Check if it's time to refresh
            time_since_update = datetime.now() - st.session_state.last_update
            if time_since_update.total_seconds() >= interval:
                # Only refresh if cache is expired and no user interaction is happening
                if not self.is_data_cached('jails_data', datetime.now()):
                    # Silent refresh without UI disruption
                    self.refresh_data(force=False)
        
        # Check if fail2ban is still running
        if not self.manager.is_fail2ban_running():
            st.error("Fail2ban s'est arrêté. Veuillez redémarrer le service.")
            st.stop()
        
        # Initial data load with cache check
        if not st.session_state.jails_data or not self.is_data_cached('jails_data', datetime.now()):
            self.refresh_data()
        
        # Main content tabs with state preservation
        tab_names = ["Dashboard", "Jails", "IPs Bannies", "Logs"]
        
        # Create tabs but don't use the returned objects directly
        selected_tab = st.radio(
            "Navigation",
            tab_names,
            index=st.session_state.current_tab,
            horizontal=True,
            key="tab_selector"
        )
        
        # Update current tab index
        st.session_state.current_tab = tab_names.index(selected_tab)
        
        # Render content based on selected tab
        if selected_tab == "Dashboard":
            self.render_dashboard_content()
        elif selected_tab == "Jails":
            self.render_jails_management()
        elif selected_tab == "IPs Bannies":
            self.render_ip_management()
        elif selected_tab == "Logs":
            self.render_logs_viewer()
        
    def render_dashboard_content(self):
        """Render dashboard tab content"""
        self.render_metrics_overview()
        st.divider()
        self.render_charts()

def main():
    """Main entry point"""
    app = Fail2ShieldApp()
    app.run()

if __name__ == "__main__":
    main()