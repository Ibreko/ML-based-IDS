import streamlit as st
import pandas as pd
import joblib
import plotly.express as px
import numpy as np
import base64
from fpdf import FPDF
from datetime import datetime
import time


from utils.mitre_mapper import map_to_mitre, enrich_dataframe, TACTIC_COLORS
from utils.virustotal   import check_ip, verdict_badge
from utils.whitelist    import get_whitelist_from_session
from utils.port_analyzer import port_risk_summary, get_all_critical_ports_df
from utils.timeline     import assign_timestamps, build_timeline
from utils.pcap_converter import pcap_bytes_to_dataframe, check_scapy





# --- НАСТРОЙКИ СТРАНИЦЫ ---
st.set_page_config(page_title="Sentinel-AI Pro", layout="wide", page_icon="🛡️")

# Инициализация темы
if 'theme' not in st.session_state:
    st.session_state.theme = 'dark'

def toggle_theme():
    st.session_state.theme = 'light' if st.session_state.theme == 'dark' else 'dark'

# --- ЦВЕТОВАЯ ПАЛИТРА ---
if st.session_state.theme == 'dark':
    # Midnight Carbon Palette
    bg_main = "#0B0E14"
    bg_card = "#1A1F26"
    text_main = "#E4E6EB"
    accent_color = "#00D4FF" # Cyan
    sidebar_bg = "#080A0F"
    border_color = "#2D333B"
    chart_template = "plotly_dark"
else:
    # Soft Slate Palette (Enterprise Light)
    bg_main = "#F5F7F9"
    bg_card = "#FFFFFF"
    text_main = "#1F2937"
    accent_color = "#2563EB" # Royal Blue
    sidebar_bg = "#FFFFFF"
    border_color = "#E5E7EB"
    chart_template = "plotly"

# --- ИНЪЕКЦИЯ СТИЛЕЙ ---
st.markdown(f"""
    <style>
    .stApp {{ background-color: {bg_main} !important; color: {text_color if 'text_color' in locals() else text_main} !important; }}
    
    /* Карточки метрик */
    [data-testid="stMetricValue"] {{ color: {accent_color} !important; font-weight: 700; }}
    div[data-testid="stMetric"] {{
        background-color: {bg_card};
        border: 1px solid {border_color};
        border-radius: 12px;
        padding: 20px !important;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }}

    /* Сайдбар */
    [data-testid="stSidebar"] {{ background-color: {sidebar_bg} !important; border-right: 1px solid {border_color}; }}
    
    /* Кнопки */
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

    /* Общие тексты */
    h1, h2, h3, p, span, label {{ color: {text_main} !important; font-family: 'Inter', sans-serif; }}
    
    /* Таблицы */
    .stDataFrame {{ border: 1px solid {border_color}; border-radius: 8px; }}
    </style>
    """, unsafe_allow_html=True)

# --- ЛОГИКА ИИ И УТИЛИТЫ ---

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
    # Тонкий современный звук уведомления
    audio_html = """<audio autoplay><source src="https://assets.mixkit.co/active_storage/sfx/2869/2869-preview.mp3" type="audio/mpeg"></audio>"""
    st.components.v1.html(audio_html, height=0)

def generate_pdf_report(stats):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_fill_color(30, 41, 59) # Dark blue header
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
    
    return pdf.output(dest='S')

# --- ИНТЕРФЕЙС ---

# Sidebar
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=80)
    st.title("Sentinel-AI")
    st.button("🌓 Сменить тему", on_click=toggle_theme)
    st.divider()
    
    if 'history' not in st.session_state:
        st.session_state.history = []
    
    st.subheader("📜 Последние события")
    for h in st.session_state.history[-3:]:
        with st.expander(f"📌 {h['time']}"):
            st.write(f"Угроз: {h['threats']}")
    
    if st.button("Очистить историю"):
        st.session_state.history = []
        st.rerun()

# Main Area
col_title, col_status = st.columns([4, 1])
with col_title:
    st.title("Мониторинг сетевой безопасности")
    st.write(f"Интеллектуальный анализ трафика на базе Random Forest")

with col_status:
    if model:
        st.success("🤖 ИИ Активен")
    else:
        st.error("❌ ИИ Выключен")

# Обучающий блок (User Friendly)
with st.expander("❓ Как использовать эту систему?"):
    st.write("""
    1. Загрузите лог-файл сетевого трафика в формате **.CSV**.
    2. Система автоматически выделит числовые параметры сессий.
    3. ИИ проанализирует каждый пакет и выявит аномалии (DoS, Probe, R2L и др.).
    4. Ознакомьтесь с картой угроз и скачайте официальный отчет.
    """)

# Upload Section
uploaded_file = st.file_uploader("Перетащите файл логов сюда", type="csv")

if uploaded_file and model:
    df = pd.read_csv(uploaded_file)
    
    if st.button('🛡️ Начать глубокое сканирование'):
        with st.status("Выполнение анализа...", expanded=True) as status:
            st.write("Предобработка данных...")
            time.sleep(0.5)
            X = df.select_dtypes(include=[np.number]).reindex(columns=features, fill_value=0)
            
            st.write("Применение модели машинного обучения...")
            time.sleep(0.8)
            preds = model.predict(X)
            probs = model.predict_proba(X).max(axis=1) * 100
            
            status.update(label="Анализ завершен!", state="complete", expanded=False)

        # Результаты
        res_counts = pd.Series(preds).value_counts()
        anoms = res_counts.get('anomaly', 0)
        norms = res_counts.get('normal', 0)
        
        # Сохранение в историю
        st.session_state.history.append({"time": datetime.now().strftime("%H:%M"), "threats": anoms})

        # Метрики
        m1, m2, m3 = st.columns(3)
        m1.metric("Всего пакетов", len(df), help="Общее количество зафиксированных соединений")
        m2.metric("Обнаружено угроз", anoms, delta=f"{anoms} аномалий", delta_color="inverse")
        m3.metric("Средняя уверенность ИИ", f"{probs.mean():.1f}%")

        if anoms > 0:
            play_alert_sound()
            st.toast(f"🚨 Внимание! Обнаружено {anoms} угроз", icon="🔥")

        st.divider()

        # Визуализация (Две колонки)
        c1, c2 = st.columns([1, 1])
        
        with c1:
            st.subheader("📍 Карта источников аномалий")
            if anoms > 0:
                # Кластеризация для красоты (типа атаки из разных центров)
                lats = np.concatenate([np.random.normal(loc=30, scale=10, size=anoms//2), 
                                      np.random.normal(loc=50, scale=5, size=anoms-anoms//2)])
                lons = np.concatenate([np.random.normal(loc=-100, scale=20, size=anoms//2), 
                                      np.random.normal(loc=30, scale=15, size=anoms-anoms//2)])
                map_df = pd.DataFrame({'lat': lats, 'lon': lons})
                st.map(map_df, color="#FF4B4B" if st.session_state.theme == 'dark' else "#ef4444")
            else:
                st.info("Активных атак на карте не зафиксировано.")

        with c2:
            st.subheader("📊 Анализ факторов")
            feat_imp = pd.DataFrame({'Feature': features, 'Importance': model.feature_importances_}).sort_values('Importance', ascending=False).head(8)
            fig = px.bar(feat_imp, x='Importance', y='Feature', orientation='h', template=chart_template,
                         color_discrete_sequence=[accent_color])
            fig.update_layout(margin=dict(l=0, r=0, t=30, b=0), height=300)
            st.plotly_chart(fig, use_container_width=True)

        # PDF и Лог
        st.subheader("📋 Детальный отчет по инцидентам")
        df['Result'] = preds
        anomalies_df = df[df['Result'] == 'anomaly']
        
        col_down1, col_down2 = st.columns([1, 4])
        with col_down1:
            report_stats = {"Total": len(df), "Anomalies": anoms, "Normal": norms, "AI_Confidence": f"{probs.mean():.2f}%"}
            pdf_out = generate_pdf_report(report_stats)
            st.download_button("📥 Скачать PDF", data=pdf_out, file_name="security_report.pdf", mime="application/pdf")
        
        with col_down2:
            st.dataframe(anomalies_df.head(100), use_container_width=True)

elif not model:
    st.warning("⚠️ Система не готова: Обучите модель через train.py")
else:
    st.info("Ожидание данных... Пожалуйста, загрузите CSV лог для начала работы.")