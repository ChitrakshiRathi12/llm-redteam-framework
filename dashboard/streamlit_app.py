"""
streamlit_app.py
Live dashboard for the LLM Red-Teaming Framework.
Displays scan results, vulnerability heatmap, and per-attack details.
Run with: streamlit run dashboard/streamlit_app.py
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime


# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title = "LLM Red-Teaming Dashboard",
    page_icon  = "🔴",
    layout     = "wide",
    initial_sidebar_state = "expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────

st.markdown("""
<style>
  .main-header { font-size: 2rem; font-weight: 700; color: #1a1a2e; margin-bottom: 0.2rem; }
  .sub-header  { font-size: 0.95rem; color: #6b7280; margin-bottom: 2rem; }
  .vuln-card   { background: #fff1f2; border-left: 5px solid #dc2626; border-radius: 6px; padding: 0.75rem 1rem; margin-bottom: 0.5rem; }
  .safe-card   { background: #f0fdf4; border-left: 5px solid #16a34a; border-radius: 6px; padding: 0.75rem 1rem; margin-bottom: 0.5rem; }
  .badge { display: inline-block; border-radius: 999px; padding: 2px 10px; font-size: 0.72rem; font-weight: 700; }
  .badge-CRITICAL { background: #fee2e2; color: #dc2626; }
  .badge-HIGH     { background: #fff7ed; color: #c2410c; }
  .badge-MEDIUM   { background: #fefce8; color: #a16207; }
  .badge-LOW      { background: #f0fdf4; color: #15803d; }
</style>
""", unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_scan_report(filepath: str) -> dict:
    with open(filepath) as f:
        return json.load(f)

def get_available_reports() -> list[str]:
    output_dir = "reports/output"
    if not os.path.exists(output_dir):
        return []
    return sorted(
        [f for f in os.listdir(output_dir) if f.endswith(".json")],
        reverse=True
    )

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#16a34a",
    "INFO":     "#3b82f6",
}


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/security-shield-red.png", width=60)
    st.markdown("## 🔴 LLM Red-Teaming")
    st.divider()

    reports = get_available_reports()
    if reports:
        selected_report = st.selectbox("📂 Load scan report", reports)
        report_path = os.path.join("reports/output", selected_report)
    else:
        selected_report = None
        st.info("No scan reports found. Run scanner.py to generate one.")

    st.divider()
    st.markdown("### ▶ Run a new scan")
    run_model = st.selectbox("Model", ["llama3.2", "llama3.1", "mistral"])

    if st.button("🚀 Run full scan", use_container_width=True, type="primary"):
        with st.spinner("Running full OWASP scan — this may take several minutes..."):
            try:
                from scanner import run_full_scan
                from reports.generator import generate_full_report
                os.makedirs("reports/output", exist_ok=True)
                summary = run_full_scan(model=run_model, verbose=False)
                outputs = generate_full_report(summary, output_dir="reports/output")
                st.success(f"Scan complete — {summary.vulnerabilities}/{summary.total_attacks} vulnerabilities found")
                st.rerun()
            except Exception as e:
                st.error(f"Scan failed: {e}")

    st.divider()
    st.markdown("**LLM Red-Teaming Framework**")
    st.markdown("OWASP LLM Top 10 · Ollama + LLaMA")
    st.markdown("[GitHub](https://github.com/ChitrakshiRathi12/llm-redteam-framework)")


# ── Header ────────────────────────────────────────────────────────────────────

st.markdown('<div class="main-header">🔴 LLM Red-Teaming Dashboard</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Automated vulnerability scanning against OWASP LLM Top 10 · Powered by Ollama + LLaMA</div>', unsafe_allow_html=True)

if not selected_report:
    st.info("No scan reports available. Use the sidebar to run a scan or generate reports with scanner.py")
    st.stop()


# ── Load report ───────────────────────────────────────────────────────────────

data     = load_scan_report(report_path)
results  = data.get("results", [])
df       = pd.DataFrame(results)


# ── Summary metrics ───────────────────────────────────────────────────────────

c1, c2, c3, c4, c5 = st.columns(5)

vuln_rate = data.get("vulnerability_rate", 0)
critical  = data.get("by_severity", {}).get("CRITICAL", 0)
high      = data.get("by_severity", {}).get("HIGH", 0)
total     = data.get("total_attacks", 0)
vulns     = data.get("vulnerabilities", 0)

with c1: st.metric("Vulnerability Rate",  f"{vuln_rate}%")
with c2: st.metric("🔴 Critical",         critical)
with c3: st.metric("🟠 High",             high)
with c4: st.metric("Total Attacks",       total)
with c5: st.metric("Model",               data.get("model", "N/A"))


# ── Tabs ──────────────────────────────────────────────────────────────────────

tab1, tab2, tab3, tab4 = st.tabs(["🗺 Heatmap", "🔴 Vulnerabilities", "📋 All results", "📊 Charts"])


# TAB 1 — Heatmap
with tab1:
    st.markdown("#### OWASP Category Vulnerability Heatmap")

    owasp_data = data.get("by_owasp", {})
    categories = []
    vuln_counts = []
    total_counts = []
    rates = []

    for cat, counts in owasp_data.items():
        categories.append(cat)
        vuln_counts.append(counts["vulnerable"])
        total_counts.append(counts["total"])
        rate = counts["vulnerable"] / counts["total"] * 100 if counts["total"] > 0 else 0
        rates.append(round(rate, 1))

    fig = go.Figure(go.Bar(
        x=rates,
        y=categories,
        orientation="h",
        marker_color=[
            "#dc2626" if r > 60 else "#f97316" if r > 30 else "#eab308" if r > 0 else "#16a34a"
            for r in rates
        ],
        text=[f"{r}% ({v}/{t})" for r, v, t in zip(rates, vuln_counts, total_counts)],
        textposition="outside",
    ))
    fig.update_layout(
        xaxis=dict(range=[0, 110], title="Vulnerability Rate (%)"),
        height=420,
        margin=dict(l=10, r=80, t=20, b=20),
        plot_bgcolor="white",
    )
    st.plotly_chart(fig, use_container_width=True)


# TAB 2 — Vulnerabilities only
with tab2:
    vuln_df = df[df["vulnerable"] == True] if "vulnerable" in df.columns else pd.DataFrame()

    if vuln_df.empty:
        st.success("✅ No vulnerabilities found in this scan.")
    else:
        st.markdown(f"#### {len(vuln_df)} Vulnerabilities Found")
        for _, row in vuln_df.iterrows():
            sev = row.get("severity", "INFO")
            st.markdown(f"""
            <div class="vuln-card">
              <strong>{row.get('attack_name', 'Unknown')}</strong>
              &nbsp;<span class="badge badge-{sev}">{sev}</span>
              &nbsp;<code style="font-size:0.75rem;">{row.get('owasp_id', '')} — {row.get('owasp_title', '')}</code><br/>
              <small style="color:#6b7280;">{row.get('description', '')}</small><br/>
              <small><strong>Finding:</strong> {row.get('finding', '')}</small><br/>
              <small style="color:#374151;"><strong>Fix:</strong> {row.get('recommendation', '')}</small>
            </div>
            """, unsafe_allow_html=True)


# TAB 3 — All results
with tab3:
    st.markdown("#### All Attack Results")
    if not df.empty:
        display_cols = ["attack_name", "owasp_id", "severity", "vulnerable", "duration_ms"]
        available    = [c for c in display_cols if c in df.columns]
        st.dataframe(
            df[available].rename(columns={
                "attack_name": "Attack",
                "owasp_id":    "OWASP",
                "severity":    "Severity",
                "vulnerable":  "Vulnerable",
                "duration_ms": "Time (ms)",
            }),
            use_container_width=True,
            hide_index=True,
        )

        csv = df.to_csv(index=False)
        st.download_button(
            "⬇️ Export CSV",
            data=csv,
            file_name=f"scan_results_{datetime.utcnow().strftime('%Y%m%d')}.csv",
            mime="text/csv",
        )


# TAB 4 — Charts
with tab4:
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Severity Distribution")
        sev_data = {k: v for k, v in data.get("by_severity", {}).items() if v > 0}
        if sev_data:
            fig_sev = px.pie(
                values=list(sev_data.values()),
                names=list(sev_data.keys()),
                color=list(sev_data.keys()),
                color_discrete_map=SEVERITY_COLORS,
                title="Vulnerabilities by Severity",
            )
            st.plotly_chart(fig_sev, use_container_width=True)
        else:
            st.success("No vulnerabilities found.")

    with col2:
        st.markdown("#### Response Time by Attack")
        if not df.empty and "duration_ms" in df.columns:
            fig_time = px.bar(
                df.head(20),
                x="attack_name",
                y="duration_ms",
                color="vulnerable",
                color_discrete_map={True: "#dc2626", False: "#16a34a"},
                title="Response Time per Attack (ms)",
                labels={"attack_name": "Attack", "duration_ms": "Time (ms)"},
            )
            fig_time.update_layout(xaxis_tickangle=-45, showlegend=True)
            st.plotly_chart(fig_time, use_container_width=True)
