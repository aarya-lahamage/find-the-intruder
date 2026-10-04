import os

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from detector import SEV_ORDER, analyze, load_logs

SAMPLE = os.path.join("data", "auth_logs.csv")
SEV_COLOR = {"low": "#3b82f6", "medium": "#f59e0b", "high": "#f97316", "critical": "#ef4444"}

st.set_page_config(page_title="Find the Intruder", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.step{border-left:4px solid var(--c);background:#131a2a;padding:10px 14px;margin:8px 0;border-radius:6px}
.step b{color:var(--c)} .step small{color:#8b98a9}
.banner{background:linear-gradient(90deg,#3b0d12,#131a2a);border:1px solid #ef4444;border-radius:10px;padding:16px 20px;margin-bottom:12px}
.banner h3{margin:0 0 6px 0;color:#ff6b6b}
</style>""", unsafe_allow_html=True)

st.title("🛡️ Find the Intruder")
st.caption("Log ingestion -> detection rules -> correlated incident timeline -> attack story")

# ---------- load data ----------
with st.sidebar:
    st.header("Log source")
    up = st.file_uploader("Upload auth log (CSV)", type=["csv"])
    st.caption("Columns: timestamp, user, ip, country, event, resource, bytes")
    if st.button("Regenerate sample log"):
        import generate_logs
        generate_logs.main(SAMPLE)

try:
    if up is not None:
        df = load_logs(up)
    else:
        if not os.path.exists(SAMPLE):
            import generate_logs
            os.makedirs("data", exist_ok=True)
            generate_logs.main(SAMPLE)
        df = load_logs(SAMPLE)
except Exception as e:
    st.error(f"Could not read log file: {e}")
    st.stop()

alerts, ips, incidents = analyze(df)

c = st.columns(5)
c[0].metric("Events analysed", f"{len(df):,}")
c[1].metric("Failed logins", f"{(df.event == 'login_failed').sum():,}")
c[2].metric("Alerts raised", len(alerts))
c[3].metric("Suspicious IPs", len(ips))
c[4].metric("Incidents", len(incidents))

if not incidents:
    st.success("No correlated incident found in this log.")

# ---------- incidents ----------
for inc in incidents:
    st.markdown(f"""<div class="banner"><h3>🚨 INCIDENT - {inc.ip} (risk {inc.score}/100)</h3>
    {inc.story}</div>""", unsafe_allow_html=True)

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Attack timeline")
        for a in inc.timeline:
            col = SEV_COLOR[a["severity"]]
            st.markdown(f"""<div class="step" style="--c:{col}"><b>{a['stage']}</b>
            &nbsp;<small>{a['time']:%d %b %H:%M:%S} - {a['severity'].upper()}</small><br>{a['detail']}</div>""",
                        unsafe_allow_html=True)
    with right:
        st.subheader("Activity: normal vs attacker")
        d = df.set_index("timestamp")
        normal = d[d.ip != inc.ip].resample("1h").size()
        bad = d[d.ip == inc.ip].resample("1h").size()
        fig = go.Figure()
        fig.add_bar(x=normal.index, y=normal.values, name="normal", marker_color="#3b82f6")
        fig.add_bar(x=bad.index, y=bad.values, name=inc.ip, marker_color="#ef4444")
        fig.update_layout(barmode="stack", height=340, margin=dict(l=0, r=0, t=10, b=0),
                          paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                          legend=dict(orientation="h"))
        st.plotly_chart(fig, use_container_width=True)

    with st.expander("Evidence - raw events from this IP"):
        ev = df[df.ip == inc.ip]
        st.dataframe(ev[ev.event != "login_failed"], use_container_width=True, hide_index=True)
        st.caption(f"+ {(ev.event == 'login_failed').sum()} failed login events (hidden)")

    report = f"# Incident report - {inc.ip}\n\nRisk score: {inc.score}/100\n\n{inc.story}\n\n## Timeline\n" + \
        "\n".join(f"- {a['time']:%Y-%m-%d %H:%M:%S} [{a['stage']}] {a['detail']}" for a in inc.timeline)
    st.download_button("Download incident report (.md)", report, file_name=f"incident_{inc.ip}.md")

# ---------- IP risk + all alerts ----------
st.subheader("IP risk scores")
if len(ips):
    st.dataframe(ips[["ip", "score", "level", "alerts", "users", "rules"]], hide_index=True,
                 use_container_width=True,
                 column_config={"score": st.column_config.ProgressColumn("risk", min_value=0, max_value=100, format="%d")})

st.subheader("All alerts")
f1, f2 = st.columns([2, 3])
sev = f1.multiselect("Severity", list(SEV_ORDER), default=list(SEV_ORDER))
q = f2.text_input("Search IP / user / text")
rows = [a for a in alerts if a["severity"] in sev and
        (not q or q.lower() in f"{a['ip']} {a['user']} {a['detail']}".lower())]
if rows:
    st.dataframe(pd.DataFrame(rows)[["time", "severity", "stage", "ip", "user", "detail"]],
                 hide_index=True, use_container_width=True)
else:
    st.info("No alerts match the filters.")
