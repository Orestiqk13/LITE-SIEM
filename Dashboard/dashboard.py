import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import os
import subprocess

def get_smart_local_ip():
    try:
        ips = subprocess.check_output(['hostname', '-I']).decode().strip().split()
        for ip in ips:
            if not ip.startswith("10.") and not ip.startswith("127."):
                return ip
        if ips: return ips[0]
    except:
        pass
    return "127.0.0.1"

VICTIM_IP = get_smart_local_ip()

st.set_page_config(page_title="SIEM SOC Dashboard", layout="wide", initial_sidebar_state="collapsed")

st.markdown("""
    <style>
    .block-container { padding-top: 2rem; padding-bottom: 0rem; }
    h1, h2, h3, h4 { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
    .stDataFrame { font-size: 14px; }
    </style>
""", unsafe_allow_html=True)

DB_PATH = "../Engine/siem_database.db"

@st.cache_data(ttl=5) 
def load_data():
    df_alerts = pd.DataFrame()
    df_perf = pd.DataFrame()
    
    if os.path.exists(DB_PATH):
        try:
            conn = sqlite3.connect(DB_PATH, timeout=5)
            df_alerts = pd.read_sql_query("SELECT * FROM alerts", conn)
            try:
                df_perf = pd.read_sql_query("SELECT * FROM performance", conn)
            except:
                pass
            conn.close()
        except Exception as e:
            st.error(f"Database connection error: {e}")
            
    if not df_alerts.empty and 'event_count' not in df_alerts.columns:
        df_alerts['event_count'] = 1
        
    return df_alerts, df_perf

col_title, col_sync = st.columns([8, 2])
with col_title:
    st.title("Security Operations Center (SOC) Overview")
    st.markdown(f"Stateful Security Information and Event Management (SIEM) | Sensor IP: **{VICTIM_IP}**")
with col_sync:
    st.write("") 
    if st.button("Synchronize Telemetry", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

st.markdown("---")

df_alerts, df_perf = load_data()

if df_alerts.empty:
    df_alerts = pd.DataFrame(columns=['id', 'timestamp', 'src_ip', 'tag', 'risk_level', 'score', 'tactic', 'technique_id', 'message', 'cve', 'event_count'])

tab_sec, tab_perf = st.tabs(["Security Events & Vulnerability Intel", "System Performance & Kernel Telemetry"])

with tab_sec:
    if not df_alerts.empty:
        df_alerts['dest_ip'] = df_alerts['message'].str.extract(r'\(Dest:\s*([\d\.]+)\)')
        df_alerts['dest_ip'] = df_alerts['dest_ip'].fillna("Unknown")
        df_alerts['Sensor_Type'] = df_alerts['dest_ip'].apply(
            lambda x: "Local SIEM Host (HIDS)" if x == VICTIM_IP or x == "Unknown" else "External Network Device (NIDS)"
        )

    total_db_alerts = len(df_alerts)
    total_raw_events = df_alerts['event_count'].sum() if not df_alerts.empty else 0
    critical_alerts = len(df_alerts[df_alerts['risk_level'] == 'CRITICAL'])
    
    df_cves = df_alerts[(df_alerts['cve'].notnull()) & (df_alerts['cve'] != 'None') & (df_alerts['cve'] != '')].copy()
    total_cves = df_cves['cve'].nunique() if not df_cves.empty else 0

    st.markdown("### Operational Telemetry Metrics")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Raw Network Events", f"{total_raw_events:,}")
    m2.metric("Deduplicated Incidents (Database)", f"{total_db_alerts:,}")
    m3.metric("Critical Security Incidents", critical_alerts)
    m4.metric("Known Vulnerabilities (CVE) Detected", total_cves)

    st.markdown("---")

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.markdown("### Incident Timeline Analysis")
        if not df_alerts.empty:
            df_alerts['timestamp'] = pd.to_datetime(df_alerts['timestamp'])
            timeline_df = df_alerts.groupby([df_alerts['timestamp'].dt.floor('Min'), 'risk_level']).size().reset_index(name='Incident Count')
            
            color_map = {'CRITICAL': '#d62728', 'HIGH': '#ff7f0e', 'MEDIUM': '#bcbd22', 'LOW': '#1f77b4', 'INFO': '#7f7f7f'}
            fig_timeline = px.line(timeline_df, x='timestamp', y='Incident Count', color='risk_level', color_discrete_map=color_map, markers=True)
            fig_timeline.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", margin=dict(l=0, r=0, t=30, b=0))
            st.plotly_chart(fig_timeline, use_container_width=True)
        else:
            st.info("Awaiting telemetry data to generate timeline.")

    with chart_col2:
        st.markdown("### Threat Actor Profiling (Top Source IPs)")
        if not df_alerts.empty and len(df_alerts[df_alerts['src_ip'] != 'Unknown']) > 0:
            top_ips = df_alerts[df_alerts['src_ip'] != 'Unknown'].groupby('src_ip')['event_count'].sum().nlargest(5).reset_index()
            top_ips.columns = ['Source IP Address', 'Total Malicious Actions']
            fig_ips = px.bar(top_ips, x='Total Malicious Actions', y='Source IP Address', orientation='h', color='Total Malicious Actions', color_continuous_scale='Reds')
            fig_ips.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", margin=dict(l=0, r=0, t=30, b=0))
            st.plotly_chart(fig_ips, use_container_width=True)
        else:
            st.info("No threat actors identified currently.")

    st.markdown("---")
    st.markdown("### Advanced Threat Architecture & MITRE Analytics")
    ana_col1, ana_col2 = st.columns(2)
    
    with ana_col1:
        st.markdown("#### Attack Surface Target (HIDS vs NIDS)")
        if not df_alerts.empty:
            sensor_df = df_alerts.groupby('Sensor_Type')['event_count'].sum().reset_index()
            fig_sensor = px.pie(sensor_df, values='event_count', names='Sensor_Type', hole=0.45,
                                color='Sensor_Type',
                                color_discrete_map={
                                    "Local SIEM Host (HIDS)": "#2ca02c", 
                                    "External Network Device (NIDS)": "#1f77b4"
                                })
            fig_sensor.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", margin=dict(l=0, r=0, t=30, b=0))
            st.plotly_chart(fig_sensor, use_container_width=True)
        else:
            st.info("Awaiting architectural telemetry.")

    with ana_col2:
        st.markdown("#### MITRE ATT&CK® Tactics Distribution")
        if not df_alerts.empty:
            tactic_df = df_alerts.groupby('tactic')['event_count'].sum().reset_index()
            fig_tactic = px.bar(tactic_df, x='event_count', y='tactic', orientation='h', 
                                color='event_count', color_continuous_scale='Purples')
            fig_tactic.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", margin=dict(l=0, r=0, t=30, b=0))
            st.plotly_chart(fig_tactic, use_container_width=True)
        else:
            st.info("Awaiting MITRE classification data.")

    st.markdown("---")

    if total_cves > 0:
        st.markdown("### Vulnerability Intelligence (CVE Tracking)")
        st.markdown("Displays unique CVEs grouped by attacker. Total hits are aggregated.")
        
        cve_grouped = df_cves.groupby(['cve', 'src_ip', 'tag']).agg({
            'timestamp': 'max',       
            'event_count': 'sum',     
            'message': 'first'        
        }).reset_index()

        cve_display_df = cve_grouped[['timestamp', 'src_ip', 'cve', 'tag', 'event_count', 'message']].sort_values(by='timestamp', ascending=False)
        
        st.dataframe(
            cve_display_df,
            use_container_width=True,
            height=250, 
            hide_index=True,
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Last Seen", format="YYYY-MM-DD HH:mm:ss"),
                "src_ip": "Attacker IP",
                "cve": "Detected CVE",
                "tag": "IDS Rule Category",
                "event_count": st.column_config.NumberColumn("Total Hits"), 
                "message": st.column_config.TextColumn("Example Payload / Signature", width="large")
            }
        )
        st.markdown("---")

    st.markdown("### Master Incident Log (Correlated Alerts)")
    if not df_alerts.empty:
        master_grouped = df_alerts.groupby(['src_ip', 'risk_level', 'score', 'tactic', 'technique_id']).agg({
            'timestamp': 'max',       
            'event_count': 'sum',     
            'message': 'first'        
        }).reset_index()

        display_df = master_grouped[['timestamp', 'src_ip', 'risk_level', 'score', 'tactic', 'technique_id', 'event_count', 'message']].sort_values(by='timestamp', ascending=False)
        
        st.dataframe(
            display_df, 
            use_container_width=True, 
            height=400, 
            hide_index=True,
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Last Activity", format="YYYY-MM-DD HH:mm:ss"),
                "src_ip": "Source IP Address",
                "risk_level": "Severity Level",
                "score": st.column_config.ProgressColumn("Risk Score (%)", min_value=0, max_value=100, format="%d%%"),
                "tactic": "MITRE Tactic",
                "technique_id": "MITRE ID", 
                "event_count": st.column_config.NumberColumn("Aggregated Events"),
                "message": st.column_config.TextColumn("Forensic Raw Data (Sample)", width="large")
            }
        )

with tab_perf:
    st.markdown("### Enterprise System Resource & Kernel Telemetry")
    st.markdown("Continuous monitoring of the SIEM architecture footprint. Data acquired via direct `/proc/stat` and `/proc/loadavg` kernel interfaces.")
    
    if df_perf.empty:
        st.warning("Awaiting performance telemetry. Engine polls kernel metrics every 30 seconds.")
    else:
        latest_perf = df_perf.iloc[-1]
        
        st.markdown("#### Hardware Resource Utilization")
        c1, c2, c3, c4 = st.columns(4)
        total_ram = latest_perf['collector_ram_mb'] + latest_perf['engine_ram_mb']
        c1.metric("Total Memory Allocation", f"{total_ram:.2f} Megabytes")
        c2.metric("Collector Agent (C) CPU", f"{latest_perf['collector_cpu']:.2f} %")
        c3.metric("Correlation Engine (Python) CPU", f"{latest_perf['engine_cpu']:.2f} %")
        c4.metric("Database Storage Size", f"{latest_perf['db_size_mb']:.3f} Megabytes")

        st.markdown("---")

        st.markdown("#### Operating System & Kernel Activity")
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("System Load Average (1 Minute)", f"{latest_perf['sys_load_1m']:.2f}")
        k2.metric("Logical CPU Cores Detected", f"{int(latest_perf['cpu_cores_count'])}")
        k3.metric("Processor Context Switches", f"{int(latest_perf['ctx_switches']):,}")
        k4.metric("Hardware Interrupts", f"{int(latest_perf['interrupts']):,}")

        st.markdown("---")

        perf_col1, perf_col2 = st.columns(2)

        with perf_col1:
            st.markdown("#### Memory Allocation Over Time")
            ram_df = df_perf[['timestamp', 'collector_ram_mb', 'engine_ram_mb']].melt(
                id_vars='timestamp', var_name='Process Component', value_name='Memory Allocated (Megabytes)'
            )
            ram_df['Process Component'] = ram_df['Process Component'].map({'collector_ram_mb': 'Collector Agent (C)', 'engine_ram_mb': 'Correlation Engine (Python)'})
            fig_ram = px.area(ram_df, x='timestamp', y='Memory Allocated (Megabytes)', color='Process Component', color_discrete_sequence=['#1f77b4', '#2ca02c'])
            fig_ram.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", margin=dict(l=0, r=0, t=30, b=0), legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1))
            st.plotly_chart(fig_ram, use_container_width=True)

        with perf_col2:
            st.markdown("#### CPU Utilization Comparison")
            cpu_df = df_perf[['timestamp', 'collector_cpu', 'engine_cpu']].melt(
                id_vars='timestamp', var_name='Process Component', value_name='CPU Utilization (%)'
            )
            cpu_df['Process Component'] = cpu_df['Process Component'].map({'collector_cpu': 'Collector Agent (C)', 'engine_cpu': 'Correlation Engine (Python)'})
            fig_cpu = px.line(cpu_df, x='timestamp', y='CPU Utilization (%)', color='Process Component', color_discrete_sequence=['#d62728', '#ff7f0e'])
            fig_cpu.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", margin=dict(l=0, r=0, t=30, b=0), legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1))
            st.plotly_chart(fig_cpu, use_container_width=True)

        st.markdown("---")
        
        st.markdown("#### Raw Performance Telemetry Data")
        st.dataframe(
            df_perf.sort_values(by='timestamp', ascending=False), 
            use_container_width=True, 
            height=250, 
            hide_index=True
        )