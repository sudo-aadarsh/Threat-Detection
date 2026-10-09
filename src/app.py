import streamlit as st
import os
import sys
import re
import json
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime

# ─── Path Setup ───────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
load_dotenv()

from database.db_setup import init_db, SessionLocal, IncidentReport
from agents import EmailAgent, IPAgent, LogAgent, CorrelationAgent
from utils.sample_data import SAMPLE_EMAIL, SAMPLE_LOG, SAMPLE_IPS

# ─── Database Init ────────────────────────────────────────────────────────────
init_db()

# ─── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CyberSentinel AI — Multi-Agent SIEM",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─── Global CSS — Premium Light Enterprise UI ─────────────────────────────────
st.markdown('''
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

/* ── Base & Background ── */
[data-testid="stAppViewContainer"], [data-testid="stMain"] {
    background-color: #f8fafc !important; /* Tailwind slate-50 */
    color: #0f172a !important; /* slate-900 */
    font-family: 'Inter', -apple-system, sans-serif !important;
}

[data-testid="stSidebar"] {
    background-color: #ffffff !important;
    border-right: 1px solid #e2e8f0 !important;
}

/* ── Typography ── */
h1, h2, h3, h4, h5, h6 {
    color: #0f172a !important;
    font-weight: 700 !important;
    letter-spacing: -0.02em !important;
    font-family: 'Inter', sans-serif !important;
}
p, li, span, label {
    color: #475569 !important; /* slate-600 */
}
.cs-page-title {
    font-size: 2rem !important;
    font-weight: 800 !important;
    color: #0f172a !important;
    margin-bottom: 0.5rem !important;
}
.cs-page-sub {
    font-size: 1rem !important;
    color: #64748b !important;
    margin-bottom: 2rem !important;
}

/* ── Cards & Containers ── */
[data-testid="metric-container"], .streamlit-expanderHeader, div[data-testid="stForm"], div.stChatFloatingInputContainer, .stDataFrame, .cs-card {
    background-color: #ffffff !important;
    border: 1px solid #e2e8f0 !important;
    border-radius: 12px !important;
    box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1) !important;
    padding: 1.5rem !important;
    transition: box-shadow 0.2s ease, transform 0.2s ease !important;
}

[data-testid="metric-container"]:hover, .cs-card:hover {
    box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1) !important;
    transform: translateY(-1px) !important;
}

[data-testid="metric-container"] label {
    color: #64748b !important;
    font-size: 0.875rem !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.05em !important;
}

[data-testid="metric-container"] [data-testid="stMetricValue"] {
    color: #0f172a !important;
    font-size: 2.25rem !important;
    font-weight: 800 !important;
}

/* ── Buttons ── */
.stButton > button {
    background-color: #2563eb !important; /* blue-600 */
    color: #ffffff !important;
    border: none !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    padding: 0.6rem 1.2rem !important;
    box-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05) !important;
    transition: all 0.2s ease !important;
}
.stButton > button:hover {
    background-color: #1d4ed8 !important; /* blue-700 */
    box-shadow: 0 4px 6px -1px rgb(37 99 235 / 0.2) !important;
}
.stButton > button p { color: #ffffff !important; margin: 0 !important; }

/* Secondary buttons */
.stButton > button[kind="secondary"] {
    background-color: #ffffff !important;
    color: #334155 !important;
    border: 1px solid #cbd5e1 !important;
    box-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05) !important;
}
.stButton > button[kind="secondary"]:hover {
    background-color: #f8fafc !important;
    border-color: #94a3b8 !important;
    color: #0f172a !important;
}

/* ── Inputs ── */
.stTextInput > div > div > input, .stTextArea > div > div > textarea, .stSelectbox > div > div > div {
    background-color: #ffffff !important;
    border: 1px solid #cbd5e1 !important;
    border-radius: 8px !important;
    color: #0f172a !important;
    box-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05) !important;
}
.stTextInput > div > div > input:focus, .stTextArea > div > div > textarea:focus {
    border-color: #2563eb !important;
    box-shadow: 0 0 0 2px rgb(37 99 235 / 0.2) !important;
}

/* ── Alerts & Badges ── */
.cs-finding-row {
    padding: 12px 16px;
    border-radius: 8px;
    margin-bottom: 8px;
    border-left: 4px solid transparent;
    background-color: #ffffff;
    box-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05);
    border: 1px solid #e2e8f0;
}
.cs-finding-row.danger { border-left-color: #ef4444; background-color: #fef2f2; }
.cs-finding-row.warn { border-left-color: #f59e0b; background-color: #fffbeb; }
.cs-finding-row.success { border-left-color: #10b981; background-color: #ecfdf5; }
.cs-finding-row.info { border-left-color: #3b82f6; background-color: #eff6ff; }

.cs-badge {
    padding: 4px 10px;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.025em;
}
.cs-badge-critical { background-color: #fee2e2; color: #991b1b; }
.cs-badge-high { background-color: #fef3c7; color: #92400e; }
.cs-badge-medium { background-color: #e0e7ff; color: #3730a3; }
.cs-badge-low { background-color: #d1fae5; color: #065f46; }

/* ── Pipeline Steps ── */
.cs-agent-step {
    padding: 16px;
    border-radius: 12px;
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 16px;
    box-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05);
}
.cs-agent-step.running { border-left: 4px solid #f59e0b; }
.cs-agent-step.done { border-left: 4px solid #10b981; }
.cs-agent-step.waiting { opacity: 0.7; }
.cs-agent-icon { font-size: 1.5rem; }
.cs-agent-name { font-weight: 600; color: #0f172a; }
.cs-agent-status { font-size: 0.875rem; color: #64748b; }

/* Sidebar overrides */
[data-testid="stSidebar"] .stButton > button {
    background: transparent !important;
    color: #475569 !important;
    border: none !important;
    border-radius: 8px !important;
    font-weight: 500 !important;
    box-shadow: none !important;
    text-align: left !important;
    justify-content: flex-start !important;
}
[data-testid="stSidebar"] .stButton > button:hover {
    background: #f1f5f9 !important;
    color: #0f172a !important;
}
[data-testid="stSidebar"] .stButton > button[kind="primary"] {
    background: #eff6ff !important;
    color: #1d4ed8 !important;
    font-weight: 600 !important;
}
</style>
''', unsafe_allow_html=True)


# ─── Session State Defaults ────────────────────────────────────────────────────
if "page" not in st.session_state:
    st.session_state.page = "Dashboard"
if "gemini_key" not in st.session_state:
    st.session_state.gemini_key = os.getenv("GEMINI_API_KEY", "")
if "last_results" not in st.session_state:
    st.session_state.last_results = None


# ─── Helpers ──────────────────────────────────────────────────────────────────
def severity_badge(level: str) -> str:
    cls = f"cs-badge-{level.lower()}" if level else "cs-badge-unknown"
    label = level or "UNKNOWN"
    dot = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🔵", "LOW": "🟢"}.get(label, "⚪")
    return f'<span class="cs-badge {cls}">{dot} {label}</span>'

def plotly_base_layout():
    return dict(
        paper_bgcolor="#ffffff",
        plot_bgcolor="#ffffff",
        font=dict(family="Inter, sans-serif", color="#475569", size=12),
        margin=dict(t=30, b=20, l=10, r=10),
        xaxis=dict(gridcolor="#f1f5f9", tickfont=dict(color="#64748b")),
        yaxis=dict(gridcolor="#f1f5f9", tickfont=dict(color="#64748b")),
        legend=dict(font=dict(color="#475569"), bgcolor="#ffffff"),
    )

def gauge_chart(value: float, title: str):
    color = "#ef4444" if value >= 75 else "#f59e0b" if value >= 50 else "#6366f1" if value >= 25 else "#10b981"
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        title={"text": title, "font": {"color": "#64748b", "size": 12, "family": "Inter"}},
        number={"font": {"color": "#0f172a", "size": 40, "family": "Inter"}, "suffix": "/100"},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#cbd5e1", "tickfont": {"color": "#64748b"}},
            "bar": {"color": color, "thickness": 0.7},
            "bgcolor": "#ffffff",
            "bordercolor": "#e2e8f0",
            "borderwidth": 1,
            "steps": [
                {"range": [0, 25], "color": "rgba(16,185,129,0.15)"},
                {"range": [25, 50], "color": "rgba(99,102,241,0.15)"},
                {"range": [50, 75], "color": "rgba(245,158,11,0.15)"},
                {"range": [75, 100], "color": "rgba(239,68,68,0.15)"},
            ],
            "threshold": {"line": {"color": color, "width": 2}, "thickness": 0.85, "value": value}
        }
    ))
    fig.update_layout(**plotly_base_layout(), height=240)
    return fig

def bar_chart_ips(ip_findings: dict):
    if not ip_findings:
        return None
    ips = list(ip_findings.keys())
    scores = [ip_findings[ip].get("malicious_score", 0) for ip in ips]
    colors = ["#ef4444" if s >= 75 else "#f59e0b" if s >= 50 else "#6366f1" if s >= 25 else "#10b981" for s in scores]
    fig = go.Figure(go.Bar(
        x=ips, y=scores,
        marker=dict(color=colors, opacity=0.85, line=dict(color="rgba(0,0,0,0)", width=0)),
        text=scores, textposition="outside",
        textfont={"color": "#64748b", "size": 11},
    ))
    base = plotly_base_layout()
    base["yaxis"]["range"] = [0, 115]
    fig.update_layout(
        **base,
        title=dict(text="IP Threat Scores", font=dict(color="#475569", size=11, family="Inter"), x=0),
        height=260,
        bargap=0.4,
    )
    return fig

def pie_chart_attack_patterns(log_findings: dict):
    patterns = log_findings.get("attack_patterns_detected", {})
    if not patterns:
        return None
    labels = list(patterns.keys())
    values = [len(v) for v in patterns.values()]
    fig = go.Figure(go.Pie(
        labels=labels, values=values, hole=0.65,
        marker=dict(colors=["#ef4444", "#f59e0b", "#6366f1", "#10b981", "#8b5cf6"],
                    line=dict(color="#ffffff", width=2)),
        textfont=dict(color="#475569", size=11),
    ))
    fig.update_layout(
        **plotly_base_layout(),
        title=dict(text="Attack Pattern Distribution", font=dict(color="#475569", size=11, family="Inter"), x=0),
        height=280,
    )
    return fig


# ─── Sidebar Navigation ────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('''
    <div style="padding:10px 0 20px;">
        <h2 style="margin:0;">🛡️ CyberSentinel</h2>
        <span style="font-size:0.75rem; color:#64748b; text-transform:uppercase; font-weight:600;">Multi-Agent SIEM</span>
    </div>
    ''', unsafe_allow_html=True)

    key = st.session_state.gemini_key
    is_live = key and key != "your_google_gemini_api_key_here"
    if is_live:
        st.markdown('<div class="cs-finding-row success" style="padding:8px 12px; font-size:0.8rem;">🟢 Gemini API Live</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="cs-finding-row warn" style="padding:8px 12px; font-size:0.8rem;">🟡 Demo Mode</div>', unsafe_allow_html=True)

    st.markdown('<hr style="margin: 1rem 0;">', unsafe_allow_html=True)

    pages = {
        "📊  Dashboard":      "Dashboard",
        "🔍  Live Analysis":  "Analysis",
        "📋  Report History": "History",
        "⚙️  Settings":       "Settings",
    }
    for label, page_key in pages.items():
        is_active = st.session_state.page == page_key
        if st.button(label, key=f"nav_{page_key}", use_container_width=True,
                     type="primary" if is_active else "secondary"):
            st.session_state.page = page_key
            st.rerun()

    st.markdown('''
    <div style="position:fixed; bottom:20px; left:20px;">
        <div style="font-size:0.75rem; color:#64748b; line-height:1.6;">
            BMS Institute of Technology<br>
            <span style="color:#2563eb; font-weight:600;">Group 4</span>
        </div>
    </div>
    ''', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
if st.session_state.page == "Dashboard":
    st.markdown('''
    <div class="cs-page-header">
        <h1 class="cs-page-title">Security Operations Center</h1>
        <p class="cs-page-sub">Real-time threat intelligence · Incident correlation · Multi-agent pipeline</p>
    </div>
    ''', unsafe_allow_html=True)

    db = SessionLocal()
    all_reports = db.query(IncidentReport).all()
    db.close()

    total    = len(all_reports)
    critical = sum(1 for r in all_reports if r.severity == "CRITICAL")
    high     = sum(1 for r in all_reports if r.severity == "HIGH")
    open_    = sum(1 for r in all_reports if r.status == "Open")
    avg_risk = round(sum(r.risk_score or 0 for r in all_reports) / total, 1) if total else 0

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Incidents", total)
    c2.metric("Critical", critical)
    c3.metric("High Severity", high)
    c4.metric("Open Cases", open_)
    c5.metric("Avg Risk Score", f"{avg_risk}/100")

    st.markdown('<hr>', unsafe_allow_html=True)

    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.markdown('<div style="font-weight:700; color:#475569; margin-bottom:1rem;">📈 INCIDENT RISK TREND</div>', unsafe_allow_html=True)
        if all_reports:
            df = pd.DataFrame({
                "Date": [r.timestamp.date() if r.timestamp else datetime.now().date() for r in all_reports],
                "Risk Score": [r.risk_score or 0 for r in all_reports],
                "Severity": [r.severity or "UNKNOWN" for r in all_reports]
            })
            color_map = {"CRITICAL": "#ef4444", "HIGH": "#f59e0b", "MEDIUM": "#6366f1",
                         "LOW": "#10b981", "UNKNOWN": "#94a3b8"}
            fig = px.scatter(df, x="Date", y="Risk Score", color="Severity",
                             color_discrete_map=color_map, size="Risk Score", size_max=22,
                             template="none")
            base = plotly_base_layout()
            base["yaxis"]["range"] = [0, 115]
            fig.update_layout(**base, height=260)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.markdown('<div class="cs-finding-row info">📭 No incidents yet. Run your first analysis to populate trend data.</div>', unsafe_allow_html=True)

    with col_right:
        st.markdown('<div style="font-weight:700; color:#475569; margin-bottom:1rem;">🗂️ SEVERITY BREAKDOWN</div>', unsafe_allow_html=True)
        if all_reports:
            med = sum(1 for r in all_reports if r.severity == "MEDIUM")
            low = sum(1 for r in all_reports if r.severity == "LOW")
            sev_counts = {k: v for k, v in {"CRITICAL": critical, "HIGH": high, "MEDIUM": med, "LOW": low}.items() if v > 0}
            fig2 = go.Figure(go.Pie(
                labels=list(sev_counts.keys()), values=list(sev_counts.values()), hole=0.65,
                marker=dict(colors=["#ef4444", "#f59e0b", "#6366f1", "#10b981"],
                            line=dict(color="#ffffff", width=2)),
                textfont=dict(color="#475569", size=11),
            ))
            base2 = plotly_base_layout()
            fig2.update_layout(**base2, height=260)
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.markdown('<div class="cs-finding-row info">📭 No data yet.</div>', unsafe_allow_html=True)

    st.markdown('<hr>', unsafe_allow_html=True)
    st.markdown('<div style="font-weight:700; color:#475569; margin-bottom:1rem;">🕒 RECENT INCIDENTS</div>', unsafe_allow_html=True)

    if all_reports:
        recent = sorted(all_reports, key=lambda r: r.timestamp or datetime.min, reverse=True)[:10]
        rows = []
        for r in recent:
            rows.append({
                "ID": f"#{r.id}",
                "Timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M") if r.timestamp else "—",
                "Title": r.title or "Untitled",
                "Severity": r.severity or "—",
                "Risk Score": f"{r.risk_score or 0}/100",
                "IOCs": r.ioc_count or 0,
                "Status": r.status or "Open"
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("No incidents recorded yet.")

    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("Launch New Analysis", use_container_width=True):
        st.session_state.page = "Analysis"
        st.rerun()


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: LIVE ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "Analysis":
    st.markdown('''
    <div class="cs-page-header">
        <h1 class="cs-page-title">Live Threat Analysis</h1>
        <p class="cs-page-sub">Feed raw security data to the agent pipeline</p>
    </div>
    ''', unsafe_allow_html=True)

    use_demo = st.toggle("Load sample data to demo capabilities", value=False)

    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown('<div style="font-weight:700; color:#475569; margin-bottom:0.5rem;">📧 EMAIL / PHISHING CONTENT</div>', unsafe_allow_html=True)
        email_input = st.text_area("Email", value=SAMPLE_EMAIL if use_demo else "", height=180, label_visibility="collapsed")
        
    with col_b:
        st.markdown('<div style="font-weight:700; color:#475569; margin-bottom:0.5rem;">📜 SECURITY LOG DATA</div>', unsafe_allow_html=True)
        log_input = st.text_area("Logs", value=SAMPLE_LOG if use_demo else "", height=180, label_visibility="collapsed")
        
    st.markdown('<div style="font-weight:700; color:#475569; margin:1rem 0 0.5rem;">🌐 IP ADDRESSES TO INVESTIGATE</div>', unsafe_allow_html=True)
    manual_ips = st.text_input("IPs", value=SAMPLE_IPS if use_demo else "", label_visibility="collapsed", placeholder="e.g. 103.45.67.89, 185.220.101.1")
    incident_title = st.text_input("Incident Title (optional)", placeholder="e.g. SSH brute-force + phishing campaign")

    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("Run Full Agent Pipeline", type="primary", use_container_width=True):
        if not email_input.strip() and not log_input.strip() and not manual_ips.strip():
            st.error("Please provide inputs.")
        else:
            st.markdown('<hr>', unsafe_allow_html=True)
            sa, sb, sc, sd = st.empty(), st.empty(), st.empty(), st.empty()

            def render_step(ph, icon, name, status, desc):
                cls = status
                st_text = {"waiting":"Waiting...","running":"Processing...","done":"Complete ✓"}.get(status, "")
                ph.markdown(f'''
                <div class="cs-agent-step {cls}">
                    <div class="cs-agent-icon">{icon}</div>
                    <div>
                        <div class="cs-agent-name">{name}</div>
                        <div class="cs-agent-status">{st_text} — {desc}</div>
                    </div>
                </div>
                ''', unsafe_allow_html=True)

            render_step(sa, "📧", "Email Agent", "running", "Detecting phishing")
            render_step(sb, "📜", "Log Agent", "waiting", "Extracting patterns")
            render_step(sc, "🌐", "IP Agent", "waiting", "Threat intelligence")
            render_step(sd, "🧠", "Correlation Agent", "waiting", "LLM Synthesis")

            prog = st.progress(0, text="Initializing pipeline...")

            email_agent = EmailAgent()
            email_results = email_agent.analyze(email_input)
            render_step(sa, "📧", "Email Agent", "done", f"{len(email_results.get('extracted_urls',[]))} URLs")
            render_step(sb, "📜", "Log Agent", "running", "Extracting patterns")
            prog.progress(25, text="Email Agent complete.")

            log_agent = LogAgent()
            log_results = log_agent.analyze(log_input)
            render_step(sb, "📜", "Log Agent", "done", f"{log_results.get('total_failed_logins',0)} failed logins")
            render_step(sc, "🌐", "IP Agent", "running", "Threat intelligence")
            prog.progress(50, text="Log Agent complete.")

            all_ips = set()
            ip_pat = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}')
            all_ips.update(ip_pat.findall(email_input))
            all_ips.update(log_results.get("all_ips_found", []))
            all_ips.update([i.strip() for i in manual_ips.split(",") if i.strip()])
            ip_agent = IPAgent()
            ip_results = ip_agent.analyze(list(all_ips))
            render_step(sc, "🌐", "IP Agent", "done", f"{len(ip_results)} IPs checked")
            render_step(sd, "🧠", "Correlation Agent", "running", "LLM Synthesis")
            prog.progress(75, text="IP Agent complete.")

            corr_agent = CorrelationAgent(api_key=st.session_state.gemini_key)
            corr_results = corr_agent.analyze(email_results, ip_results, log_results)
            render_step(sd, "🧠", "Correlation Agent", "done", "Report generated")
            prog.progress(100, text="Pipeline complete.")

            try:
                db = SessionLocal()
                report = IncidentReport(
                    title=incident_title or f"Incident — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                    severity=corr_results.get("severity", "UNKNOWN"),
                    risk_score=corr_results.get("risk_score", 0),
                    email_data=json.dumps(email_results),
                    ip_data=json.dumps(ip_results),
                    log_data=json.dumps(log_results),
                    final_analysis=corr_results.get("report", ""),
                    ioc_count=corr_results.get("ioc_count", 0),
                    status="Open"
                )
                db.add(report); db.commit(); db.refresh(report); db.close()
            except Exception as e:
                st.warning(f"DB Error: {e}")

            st.markdown('<hr>', unsafe_allow_html=True)
            st.markdown('<h3>📊 Analysis Results</h3>', unsafe_allow_html=True)
            
            r1, r2, r3, r4 = st.columns(4)
            r1.metric("Overall Severity", corr_results.get("severity", "UNKNOWN"))
            r2.metric("Risk Score", f"{corr_results.get('risk_score', 0)}/100")
            r3.metric("IOCs Found", corr_results.get("ioc_count", 0))
            r4.metric("IPs Checked", len(ip_results))

            t1, t2, t3 = st.tabs(["📧 Email Findings", "📜 Log Findings", "🌐 IP Findings"])
            with t1:
                st.write(email_results)
            with t2:
                st.write(log_results)
            with t3:
                st.write(ip_results)

            st.markdown('<hr>', unsafe_allow_html=True)
            st.markdown('<h3>🧠 Correlation Report</h3>', unsafe_allow_html=True)
            st.markdown(corr_results.get("report", ""))


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: REPORT HISTORY & SETTINGS
# ═══════════════════════════════════════════════════════════════════════════════
elif st.session_state.page == "History":
    st.markdown('<h1 class="cs-page-title">Incident Report History</h1>', unsafe_allow_html=True)
    db = SessionLocal()
    all_reports = db.query(IncidentReport).order_by(IncidentReport.timestamp.desc()).all()
    db.close()
    for report in all_reports:
        with st.expander(f"#{report.id} — {report.title} ({report.severity})"):
            st.markdown(report.final_analysis)

elif st.session_state.page == "Settings":
    st.markdown('<h1 class="cs-page-title">Settings</h1>', unsafe_allow_html=True)
    with st.form("settings"):
        new_gemini = st.text_input("Gemini API Key", type="password")
        if st.form_submit_button("Save"):
            st.session_state.gemini_key = new_gemini
            st.success("Saved!")
