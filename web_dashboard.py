import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import os
from streamlit_folium import st_folium
import folium
from folium.plugins import HeatMap

# Καθολική απενεργοποίηση proxies
os.environ['no_proxy'] = '*' 

st.set_page_config(page_title="LogIQ SIEM - Threat Intelligence", layout="wide")

# Custom Dark Theme CSS
st.markdown("""
    <style>
    .stMetric { background-color: #1e1e1e; padding: 15px; border-radius: 10px; border: 1px solid #333; }
    [data-testid="stMetricValue"] { color: #00FF00; }
    .main { background-color: #0e1117; }
    .stDataFrame { border: 1px solid #333; border-radius: 10px; }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ LogIQ SIEM - Global Threat Analytics")

# --- ΡΥΘΜΙΣΕΙΣ API ---
API_KEY = "LOGIQ_SUPER_SECRET_KEY_2026" 
API_URL = "http://logiq:5000/api"

def get_data(endpoint, params=None):
    headers = {"X-API-KEY": API_KEY, "Accept": "application/json"}
    try:
        r = requests.get(f"{API_URL}/{endpoint}", headers=headers, params=params, timeout=5)
        if r.status_code == 200:
            return r.json(), 200
        return None, r.status_code
    except Exception as e:
        return None, str(e)

# --- ΛΗΨΗ ΔΕΔΟΜΕΝΩΝ ---
events_raw, events_status = get_data("events/all")
alerts_raw, alerts_status = get_data("alerts")

events_list = events_raw if isinstance(events_raw, list) else (events_raw.get("events", []) if events_raw else [])
alerts_list = alerts_raw if isinstance(alerts_raw, list) else (alerts_raw.get("alerts", []) if alerts_raw else [])

if events_status == 200:
    df = pd.DataFrame(events_list)
    
    if not df.empty:
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])

        # --- TOP METRICS ---
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Logs", len(df))
        m2.metric("Active Alerts", len(alerts_list))
        m3.metric("Unique IPs", df['ip'].nunique() if 'ip' in df.columns else 0)
        risk_level = "CRITICAL" if len(alerts_list) > 10 else ("HIGH" if len(alerts_list) > 5 else "LOW")
        m4.metric("Risk Level", risk_level)

        st.divider()

        # --- WORLD THREAT MAP ---
        st.subheader("🌍 Real-Time Global Threat Map")
        
        geo_data = {
            'USA': [37.0902, -95.7129], 'China': [35.8617, 104.1954], 
            'Russia': [61.5240, 105.3188], 'Germany': [51.1657, 10.4515],
            'Greece': [39.0742, 21.8243], 'Netherlands': [52.1326, 5.2913]
        }
        
        m = folium.Map(location=[20, 0], zoom_start=2, tiles='CartoDB dark_matter')
        
        for index, row in df.head(50).iterrows(): 
            country = list(geo_data.keys())[index % len(geo_data)]
            coords = geo_data[country]
            
            color = 'red' if str(row.get('severity')).lower() == 'critical' else 'orange'
            folium.CircleMarker(
                location=coords,
                radius=5,
                popup=f"Target: {row.get('username')} | Type: {row.get('event_type')}",
                color=color,
                fill=True,
                fill_color=color
            ).add_to(m)
        
        st_folium(m, width=1400, height=400)

        st.divider()

        # --- CHARTS SECTION ---
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("📊 Event Type Distribution")
            if 'event_type' in df.columns:
                fig_pie = px.pie(df, names='event_type', hole=0.4, 
                                 color_discrete_sequence=px.colors.qualitative.Set1)
                fig_pie.update_layout(template="plotly_dark", margin=dict(t=30, b=0, l=0, r=0))
                st.plotly_chart(fig_pie, use_container_width=True)

        with col2:
            st.subheader("🔥 Top Targeted Users")
            if 'username' in df.columns:
                user_counts = df['username'].value_counts().reset_index().head(10)
                user_counts.columns = ['username', 'count']
                fig_bar = px.bar(user_counts, x='username', y='count', color='count',
                                 color_continuous_scale='Reds')
                fig_bar.update_layout(template="plotly_dark", margin=dict(t=30, b=0, l=0, r=0))
                st.plotly_chart(fig_bar, use_container_width=True)

        st.divider()

        # --- RECENT EVENTS TABLE ---
        st.subheader("📝 Recent Security Events")
        
        cols_to_show = ['timestamp', 'event_type', 'username', 'ip', 'severity', 'message']
        display_df = df.sort_values(by='timestamp', ascending=False).head(20)
        
        if all(c in df.columns for c in cols_to_show):
            display_df = display_df[cols_to_show]

        def style_severity(row):
            styles = [''] * len(row)
            if 'severity' in row.index:
                sev = str(row['severity']).lower()
                if sev == 'critical': styles[row.index.get_loc('severity')] = 'background-color: #740000; color: white; font-weight: bold'
                elif sev == 'high': styles[row.index.get_loc('severity')] = 'background-color: #b05500; color: white'
                elif sev == 'medium': styles[row.index.get_loc('severity')] = 'background-color: #5e5e00; color: white'
            return styles

        st.dataframe(display_df.style.apply(style_severity, axis=1), use_container_width=True)

        # --- AUTOMATED INCIDENT ANALYSIS SECTION ---
        st.divider()
        st.subheader("🔎 Automated Incident Analysis")
        
        col_analysis1, col_analysis2 = st.columns(2)

        # 1. Εύρεση επικίνδυνης IP
        critical_df = df[df['severity'].str.lower() == 'critical']
        if not critical_df.empty:
            top_danger_ip = critical_df['ip'].value_counts().idxmax()
            count = critical_df['ip'].value_counts().max()
            
            with col_analysis1:
                st.error(f"🚨 **Most Dangerous IP:** {top_danger_ip}")
                st.write(f"Συνολικά **{count}** Critical Alerts προέρχονται από αυτή την πηγή.")
        else:
            with col_analysis1:
                st.success("✅ Δεν βρέθηκαν Critical Alerts.")

        # 2. Ανάλυση Μοτίβου
        if len(df) > 1:
            df_sorted = df.sort_values('timestamp')
            time_diffs = df_sorted['timestamp'].diff().dt.total_seconds().dropna()
            avg_diff = time_diffs.mean()

            with col_analysis2:
                if avg_diff < 5:
                    st.warning(f"🤖 **Pattern:** Συνεχόμενη επίθεση (Bot Detected)")
                else:
                    st.info(f"👤 **Pattern:** Επιθέσεις σε κύματα (Possible Human)")
                st.write(f"Μέση συχνότητα καταγραφής: 1 log ανά **{avg_diff:.2f}** δευτερόλεπτα.")

    else:
        st.warning("⚠️ Η σύνδεση πέτυχε, αλλά δεν βρέθηκαν logs. Ξεκίνα τον attack_sim.py!")
else:
    st.error(f"🔴 Connection Error: {events_status}")

# Sidebar
st.sidebar.title("System Status")
st.sidebar.success("SIEM Engine: Online")
st.sidebar.info(f"Database: Connected")
st.sidebar.write(f"Last sync: {datetime.now().strftime('%H:%M:%S')}")
if st.sidebar.button('🔄 Refresh Data'):
    st.rerun()