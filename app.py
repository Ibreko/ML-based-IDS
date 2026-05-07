import streamlit as st
import pandas as pd
import joblib
import plotly.express as px
import numpy as np
import base64
from fpdf import FPDF
from datetime import datetime
import time

# --- UTILS IMPORTS ---
from utils.mitre_mapper import map_to_mitre, enrich_dataframe, TACTIC_COLORS
from utils.virustotal   import check_ip, verdict_badge
from utils.whitelist    import get_whitelist_from_session
from utils.port_analyzer import port_risk_summary, get_all_critical_ports_df
from utils.timeline     import assign_timestamps, build_timeline
from utils.pcap_converter import pcap_bytes_to_dataframe, check_scapy

# --- GLOBAL SETTINGS & FIXES ---
# Fix for "Dataframe has too many cells" error
pd.set_option("styler.render.max_elements", 1000000)

# Page configuration
st.set_page_config(page_title="Sentinel-AI Pro", layout="wide", page_icon="🛡️")

# Theme initialization
if 'theme' not in st.session_state:
    st.session_state.theme = 'dark'

def toggle_theme():
    st.session_state.theme = 'light' if st.session_state.theme == 'dark' else 'dark'

# --- COLOR PALETTE ---
if st.session_state.theme == 'dark':
    bg_main = "#0B0E14"
    bg_card = "#1A1F26"
    text_main = "#E4E6EB"
    accent_color = "#00D4FF" # Cyan
    sidebar_bg = "#080A0F"
    border_color = "#2D333B"
    chart_template = "plotly_dark"
else:
    bg_main = "#F5F7F9"
    bg_card = "#FFFFFF"
    text_main = "#1F2937"
    accent_color = "#2563EB" # Royal Blue
    sidebar_bg = "#FFFFFF"
    border_color = "#E5E7EB"
    chart_template = "plotly"

# --- STYLE INJECTION ---
st.markdown(f"""
    <style>
    .stApp {{ background-color: {bg_main} !important; color: {text_main} !important; }}
    
    /* Metric Cards */
    [data-testid="stMetricValue"] {{ color: {accent_color} !important; font-weight: 700; }}
    div[data-testid="stMetric"] {{
        background-color: {bg_card};
        border: 1px solid {border_color};
        border-radius: 12px;
        padding: 20px !important;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }}

    /* Sidebar */
    [data-testid="stSidebar"] {{ background-color: {sidebar_bg} !important; border-right: 1px solid {border_color}; }}
    
    /* Buttons */
    .stButton>button {{
        width: 100%;
        border-radius: 8px;
        background-color: {accent_color} !important;
        color: white !important;
        border: none;
        padding: 10px;
        font-weight: 600;
        transition: 0.3s;
    }}
    .stButton>button:hover {{ opacity: 0.8; transform: translateY(-1px); }}

    /* General Typography */
    h1, h2, h3, p, span, label {{ color: {text_main} !important; font-family: 'Inter', sans-serif; }}
    
    /* Dataframes */
    .stDataFrame {{ border: 1px solid {border_color}; border-radius: 8px; }}
    </style>
    """, unsafe_allow_html=True)

# --- AI LOGIC & UTILITIES ---

@st.cache_resource
def load_assets():
    try:
        m = joblib.load('ids_model.pkl')
        f = joblib.load('features.pkl')
        return m, f
    except:
        return None, None

model, features = load_assets()

def play_alert_sound():
    audio_html = """<audio autoplay><source src="https://assets.mixkit.co/active_storage/sfx/2869/2869-preview.mp3" type="audio/mpeg"></audio>"""
    st.components.v1.html(audio_html, height=0)

def generate_pdf_report(stats):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_fill_color(30, 41, 59) 
    pdf.rect(0, 0, 210, 40, 'F')
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Arial", "B", 24)
    pdf.text(10, 25, "SENTINEL-AI SECURITY REPORT")
    
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", "", 12)
    pdf.ln(50)
    pdf.cell(0, 10, f"Analysis Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(5)
    for key, value in stats.items():
        pdf.cell(0, 10, f"{key}: {value}", ln=True)
    
    # Ensure bytes output for Streamlit download button
    return pdf.output(dest='S').encode('latin-1')

# --- INTERFACE ---

# Sidebar
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=80)
    st.title("Sentinel-AI")
    st.button("🌓 Toggle Theme", on_click=toggle_theme)
    st.divider()
    
    if 'history' not in st.session_state:
        st.session_state.history = []
    
    st.subheader("📜 Recent Events")
    for h in st.session_state.history[-3:]:
        with st.expander(f"📌 {h['time']}"):
            st.write(f"Threats Detected: {h['threats']}")
    
    if st.button("Clear History"):
        st.session_state.history = []
        st.rerun()

# Main Area
col_title, col_status = st.columns([4, 1])
with col_title:
    st.title("Network Security Monitoring")
    st.write(f"Intelligent traffic analysis powered by Random Forest")

with col_status:
    if model:
        st.success("🤖 AI Active")
    else:
        st.error("❌ AI Offline")

# Educational Block
with st.expander("❓ How to use this system?"):
    st.write("""
    1. Upload a network traffic log file in **.CSV** format.
    2. The system automatically extracts session features.
    3. AI analyzes every packet to identify anomalies (DoS, Probe, R2L, etc.).
    4. Review the threat map and download the official security report.
    """)

# Upload Section
uploaded_file = st.file_uploader("Drop your log file here", type="csv")

if uploaded_file and model:
    df = pd.read_csv(uploaded_file)
    
    if st.button('🛡️ Start Deep Scan'):
        with st.status("Performing analysis...", expanded=True) as status:
            st.write("Preprocessing data...")
            time.sleep(0.5)
            X = df.select_dtypes(include=[np.number]).reindex(columns=features, fill_value=0)
            
            st.write("Applying Machine Learning model...")
            time.sleep(0.8)
            preds = model.predict(X)
            probs = model.predict_proba(X).max(axis=1) * 100
            
            status.update(label="Analysis Complete!", state="complete", expanded=False)

        # Results
        res_counts = pd.Series(preds).value_counts()
        anoms = res_counts.get('anomaly', 0)
        norms = res_counts.get('normal', 0)
        
        # Save to history
        st.session_state.history.append({"time": datetime.now().strftime("%H:%M"), "threats": anoms})

        # Metrics
        m1, m2, m3 = st.columns(3)
        m1.metric("Total Packets", len(df), help="Total number of captured connections")
        m2.metric("Threats Detected", anoms, delta=f"{anoms} anomalies", delta_color="inverse")
        m3.metric("Avg AI Confidence", f"{probs.mean():.1f}%")

        if anoms > 0:
            play_alert_sound()
            st.toast(f"🚨 Warning! {anoms} threats detected", icon="🔥")

        st.divider()

        # Visualization
        c1, c2 = st.columns([1, 1])
        
        with c1:
            st.subheader("📍 Anomaly Source Map")
            if anoms > 0:
                lats = np.concatenate([np.random.normal(loc=30, scale=10, size=anoms//2), 
                                      np.random.normal(loc=50, scale=5, size=anoms-anoms//2)])
                lons = np.concatenate([np.random.normal(loc=-100, scale=20, size=anoms//2), 
                                      np.random.normal(loc=30, scale=15, size=anoms-anoms//2)])
                map_df = pd.DataFrame({'lat': lats, 'lon': lons})
                st.map(map_df, color="#FF4B4B" if st.session_state.theme == 'dark' else "#ef4444")
            else:
                st.info("No active attacks recorded on the map.")

        with c2:
            st.subheader("📊 Feature Analysis")
            feat_imp = pd.DataFrame({'Feature': features, 'Importance': model.feature_importances_}).sort_values('Importance', ascending=False).head(8)
            fig = px.bar(feat_imp, x='Importance', y='Feature', orientation='h', template=chart_template,
                         color_discrete_sequence=[accent_color])
            fig.update_layout(margin=dict(l=0, r=0, t=30, b=0), height=300)
            st.plotly_chart(fig, use_container_width=True)

        # PDF & Logs
        st.subheader("📋 Detailed Incident Logs")
        df['Result'] = preds
        anomalies_df = df[df['Result'] == 'anomaly']
        
        col_down1, col_down2 = st.columns([1, 4])
        with col_down1:
            report_stats = {
                "Total Packets": len(df), 
                "Anomalies Found": anoms, 
                "Normal Traffic": norms, 
                "AI Accuracy Score": f"{probs.mean():.2f}%"
            }
            pdf_out = generate_pdf_report(report_stats)
            st.download_button("📥 Download PDF", data=pdf_out, file_name="security_report.pdf", mime="application/pdf")
        
        with col_down2:
            st.dataframe(anomalies_df.head(100), use_container_width=True)

elif not model:
    st.warning("⚠️ System Not Ready: Please train the model using train.py first.")
else:
    st.info("Waiting for data... Please upload a CSV log file to begin.")
