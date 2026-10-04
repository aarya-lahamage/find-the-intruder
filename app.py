"""Find the Intruder - SOC war room. Run: streamlit run app.py
Every number on screen is computed from the loaded log by detector.py (no hard-coded metrics)."""
import html
import json
import os
import time

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from detector import (RULES, SEV_ORDER, STAGE_ORDER, MITRE, analyze, default_params, incident_to_dict,
                      incident_to_markdown, load_logs, mitre_url, score_timeline, Params)

SAMPLE = os.path.join("data", "auth_logs.csv")
SEV_COLOR = {"low": "#5AA9FF", "medium": "#F5A524", "high": "#FF8A3D", "critical": "#FF4D5E"}
STATUSES = ["open", "investigating", "contained", "resolved"]
SCENARIOS = ["Full attack (sample log)", "Brute force only (login never succeeds)", "Clean traffic (no attacker)"]
EVENT_COLOR = {"login_failed": "#FF8A3D", "login_success": "#34D399", "file_download": "#5AA9FF",
               "privilege_change": "#FF4D5E", "log_cleared": "#C084FC"}
E = html.escape
ISO3 = dict(p.split(":") for p in (
    "IN:IND US:USA GB:GBR DE:DEU FR:FRA RU:RUS CN:CHN NL:NLD BR:BRA JP:JPN CA:CAN AU:AUS SG:SGP IE:IRL "
    "SE:SWE UA:UKR RO:ROU TR:TUR KR:KOR ID:IDN VN:VNM IR:IRN KP:PRK PL:POL ES:ESP IT:ITA ZA:ZAF MX:MEX "
    "AE:ARE HK:HKG PK:PAK BD:BGD NG:NGA EG:EGY CH:CHE BY:BLR KZ:KAZ AR:ARG").split())

st.set_page_config(page_title="Find the Intruder", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@500;700&family=Space+Grotesk:wght@500;700&display=swap');
html, body, [class*="css"] {font-family:'IBM Plex Sans',sans-serif; font-size:16px;}
.stApp {background:#070B14; color:#E6EDF7;}
.block-container {padding-top:1.2rem; max-width:1500px;}
h1,h2,h3,h4 {font-family:'Space Grotesk',sans-serif !important; letter-spacing:-.01em; color:#E6EDF7;}
section[data-testid="stSidebar"] {background:#0A101D; border-right:1px solid #1C2A44;}
.mono {font-family:'JetBrains Mono',monospace;}
.hero {display:flex; flex-wrap:wrap; gap:18px; align-items:center; justify-content:space-between;
  padding:20px 26px; border:1px solid #1C2A44; border-radius:14px; margin-bottom:14px;
  background:linear-gradient(100deg,#0E1B33 0%,#0A1222 55%,#070B14 100%); border-top:3px solid #22D3EE;}
.brand {font-family:'Space Grotesk'; font-size:34px; font-weight:700; letter-spacing:.04em;}
.sub {color:#8A9BB8; font-size:15px; margin-top:2px;}
.threat {display:flex; gap:14px; align-items:center; padding:10px 22px; border-radius:12px;
  border:1px solid var(--c); background:rgba(255,255,255,.02);}
.threat b {font-family:'Space Grotesk'; font-size:32px; color:var(--c); display:block; line-height:1.05;}
.threat small, .hstat small {color:#8A9BB8; letter-spacing:.12em; font-size:11px;}
.hstat b {display:block; font-family:'Space Grotesk'; font-size:26px; line-height:1.1;}
.hstat b.m {font-family:'JetBrains Mono'; font-size:15px; font-weight:500; padding-top:6px;}
.dot {width:16px; height:16px; border-radius:50%; background:var(--c); display:inline-block;}
.dot.pulse {animation:pulse 1.6s infinite;}
@keyframes pulse {0% {box-shadow:0 0 0 0 rgba(255,77,94,.7);} 70% {box-shadow:0 0 0 16px rgba(255,77,94,0);}
  100% {box-shadow:0 0 0 0 rgba(255,77,94,0);}}
@media (prefers-reduced-motion: reduce) {.dot.pulse {animation:none;}}
.kpi {background:#0E1626; border:1px solid #1C2A44; border-radius:12px; padding:14px 16px; height:100%;
  border-bottom:3px solid var(--c,#22D3EE);}
.kpi .v {font-family:'Space Grotesk'; font-size:34px; font-weight:700; line-height:1.1;}
.kpi .l {color:#8A9BB8; font-size:14px; margin-top:2px;}
.badge {display:inline-block; padding:3px 12px; border-radius:12px; font-size:13px; font-weight:700;
  margin-right:6px; color:#070B14;}
.card {background:#0E1626; border:1px solid #1C2A44; border-radius:12px; padding:14px 18px; margin-bottom:10px;}
.card h4 {margin:0 0 8px;} .card li {margin:5px 0; color:#D5DEF0;}
.observed {border-left:4px solid #5AA9FF;} .inferred {border-left:4px solid #F5A524;}
.inc {border:1px solid #FF4D5E; border-radius:14px; padding:16px 22px; margin:6px 0 12px;
  background:linear-gradient(90deg,#34111A 0%,#0E1626 70%);}
.inc h3 {margin:0 0 8px; color:#FFD7DB;}
.chain {display:flex; gap:6px; margin:8px 0 14px; flex-wrap:wrap;}
.chain div {flex:1; min-width:130px; padding:10px 8px; border-radius:8px; border:1px solid #1C2A44;
  background:#0A1222; color:#4F6288; font-size:14px; text-align:center;}
.chain div.on {background:#34111A; border-color:#FF4D5E; color:#FFD7DB; font-weight:600;}
.chain div.now {box-shadow:0 0 0 2px #22D3EE;}
.step {border-left:4px solid var(--c); background:#0E1626; padding:10px 14px; margin:7px 0; border-radius:6px;}
.step b {color:var(--c);} .step small {color:#8A9BB8;}
.mt {display:inline-block; margin:2px 6px 2px 0; padding:2px 10px; border-radius:6px; border:1px solid #22D3EE;
  color:#22D3EE !important; text-decoration:none; font-size:13px; font-family:'JetBrains Mono',monospace;}
.mt b {color:#E6EDF7;}
.stTabs [data-baseweb="tab-list"] {gap:4px; border-bottom:1px solid #1C2A44;}
.stTabs [data-baseweb="tab"] {height:46px; padding:0 16px; font-weight:600; font-size:15px; color:#8A9BB8;}
.stTabs [aria-selected="true"] {color:#22D3EE !important;}
</style>""", unsafe_allow_html=True)


# ------------------------------------------------------------------ helpers
def kpi(col, label, value, color="#E6EDF7", edge="#22D3EE"):
    col.markdown(f'<div class="kpi" style="--c:{edge}"><div class="v" style="color:{color}">{value}</div>'
                 f'<div class="l">{label}</div></div>', unsafe_allow_html=True)


def badge(text, color):
    return f'<span class="badge" style="background:{color}">{E(str(text))}</span>'


def mitre_chip(tid, name):
    return f'<a class="mt" href="{mitre_url(tid)}" target="_blank"><b>{E(tid)}</b> {E(name)}</a>'


def theme(fig, h=320):
    fig.update_layout(height=h, margin=dict(l=8, r=8, t=44, b=8), paper_bgcolor="rgba(0,0,0,0)",
                      plot_bgcolor="rgba(0,0,0,0)", font=dict(family="IBM Plex Sans", color="#C5D1E6", size=14),
                      title_font=dict(family="Space Grotesk", size=18, color="#E6EDF7"),
                      legend=dict(orientation="h", y=-0.18),
                      colorway=["#22D3EE", "#FF8A3D", "#5AA9FF", "#F5A524", "#C084FC", "#34D399"])
    fig.update_xaxes(gridcolor="#16233B", zerolinecolor="#16233B")
    fig.update_yaxes(gridcolor="#16233B", zerolinecolor="#16233B")
    return fig


def score_color(s):
    return SEV_COLOR["critical"] if s >= 70 else SEV_COLOR["high"] if s >= 40 else SEV_COLOR["low"]


def threat_level(active, ips):
    if any(i.severity == "critical" for i in active):
        return "CRITICAL", SEV_COLOR["critical"]
    if active:
        return "HIGH", SEV_COLOR["high"]
    if len(ips) and int(ips.score.max()) >= 40:
        return "ELEVATED", SEV_COLOR["medium"]
    return "NORMAL", "#34D399"


def apply_scenario(df, name):
    """Demo scenarios are derived from the real log, then run through the real pipeline."""
    if name == SCENARIOS[0]:
        return df
    ips = analyze(df)[1]
    if ips.empty:
        return df
    atk = ips.iloc[0].ip
    if name == SCENARIOS[2]:
        return df[df.ip != atk]
    return df[(df.ip != atk) | (df.event == "login_failed")]


def chain_html(stages, now=None):
    return '<div class="chain">' + "".join(
        f'<div class="{"on" if s in stages else ""}{" now" if s == now else ""}">{s}</div>'
        for s in STAGE_ORDER) + "</div>"


def gauge(value, title, key, h=230):
    fig = go.Figure(go.Indicator(mode="gauge+number", value=value, title={"text": title},
                                 number={"font": {"family": "Space Grotesk", "size": 46}},
                                 gauge={"axis": {"range": [0, 100]}, "bar": {"color": score_color(value)},
                                        "bgcolor": "#0E1626", "bordercolor": "#1C2A44"}))
    st.plotly_chart(theme(fig, h), use_container_width=True, key=key)


def sankey(sub):
    labels, colors, idx, src, tgt, val = [], [], {}, [], [], []

    def node(k, label, color):
        if k not in idx:
            idx[k] = len(labels)
            labels.append(label)
            colors.append(color)
        return idx[k]

    ip = sub.ip.iloc[0]
    uc = sub.user.value_counts()
    u = sub.user.where(sub.user.isin(uc.index[:8]), f"+{max(0, len(uc) - 8)} other accounts")
    node(("ip", ip), ip, "#FF4D5E")
    for name, n in u.value_counts().items():
        src.append(node(("ip", ip), ip, ""))
        tgt.append(node(("u", name), name, "#5AA9FF"))
        val.append(int(n))
    for (name, ev), n in sub.assign(u=u).groupby(["u", "event"]).size().items():
        src.append(node(("u", name), name, ""))
        tgt.append(node(("e", ev), ev, EVENT_COLOR.get(ev, "#8A9BB8")))
        val.append(int(n))
    act = sub[sub.event.isin(["file_download", "privilege_change", "log_cleared"])]
    top = act.resource.value_counts().index[:6]
    for (ev, res), n in act.assign(res=act.resource.where(act.resource.isin(top), "other resources")) \
            .groupby(["event", "res"]).size().items():
        src.append(node(("e", ev), ev, ""))
        tgt.append(node(("r", ev, res), res or "(none)", "#22D3EE"))
        val.append(int(n))
    fig = go.Figure(go.Sankey(node=dict(label=labels, color=colors, pad=18, thickness=18),
                              link=dict(source=src, target=tgt, value=val, color="rgba(138,155,184,.25)")))
    return theme(fig, 520)


# ------------------------------------------------------------------ sidebar / data
dp = default_params()
PKEYS = {"p_brute": dp.brute_threshold, "p_spray": dp.spray_users, "p_inc": dp.incident_threshold,
         "p_exfil": dp.exfil_mb}
for k, v in PKEYS.items():
    st.session_state.setdefault(k, v)


def reset_params():
    for k, v in PKEYS.items():
        st.session_state[k] = v


with st.sidebar:
    st.markdown("### 🛰️ Log source")
    up = st.file_uploader("Upload log (CSV)", type=["csv"])
    st.caption("Columns: timestamp, user, ip, country, event, resource, bytes")
    scenario = st.selectbox("Demo scenario", SCENARIOS)
    if st.button("Regenerate sample log"):
        import generate_logs
        generate_logs.main(SAMPLE)
    st.divider()
    st.markdown("### 🎚️ Detection lab")
    st.caption("Move a slider: the real detection pipeline re-runs on the loaded log.")
    st.slider("Brute force: failed logins on one account", 3, 30, key="p_brute")
    st.slider("Password spray: distinct accounts from one IP", 2, 15, key="p_spray")
    st.slider("Data exfil: MB per user per hour", 10, 1000, step=10, key="p_exfil")
    st.slider("Incident threshold (risk score)", 30, 100, key="p_inc")
    st.button("Reset to defaults", on_click=reset_params)

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
    st.error(f"Could not read the log file: {e}. Check that it has the columns listed in the sidebar.")
    st.stop()

meta = dict(df.attrs)
df = apply_scenario(df, scenario)
params = Params(brute_threshold=st.session_state.p_brute, spray_users=st.session_state.p_spray,
                exfil_mb=st.session_state.p_exfil, incident_threshold=st.session_state.p_inc,
                brute_window_min=dp.brute_window_min, spray_window_min=dp.spray_window_min,
                unseen_min_history=dp.unseen_min_history, unseen_max_prior_ips=dp.unseen_max_prior_ips)
alerts, ips, incidents = analyze(df, params)
flag_ips = set(ips.ip)
for k in ("total_rows", "dropped_rows", "duplicate_rows"):
    meta.setdefault(k, 0)
with st.sidebar:
    if params != dp:
        _a, _, _i = analyze(df, dp)
        st.info(f"vs defaults: alerts {len(alerts)} (default {len(_a)}), incidents {len(incidents)} "
                f"(default {len(_i)})")
    st.divider()
    st.markdown("### 🧾 Data quality")
    st.write(f"Rows read: **{meta['total_rows']:,}**")
    st.write(f"Malformed rows dropped: **{meta['dropped_rows']}**")
    st.write(f"Duplicate rows (kept): **{meta['duplicate_rows']}**")
    st.caption("Rule-based and explainable. No machine learning is used.")

# ------------------------------------------------------------------ war-room header + KPIs
active = [i for i in incidents if st.session_state.get(f"status_{i.id}", "open") != "resolved"]
crit = [i for i in active if i.severity == "critical"]
lvl, lcol = threat_level(active, ips)
susp_events = len({e for a in alerts for e in a["evidence"]})
st.markdown(f"""<div class="hero">
<div><div class="brand">🛡️ FIND THE INTRUDER</div>
<div class="sub">SOC war room · {len(df):,} raw events → correlated incidents, evidence and an explainable risk score</div></div>
<div class="threat" style="--c:{lcol}"><span class="dot{' pulse' if lvl == 'CRITICAL' else ''}" style="--c:{lcol}"></span>
<div><small>THREAT LEVEL</small><b>{lvl}</b></div></div>
<div class="hstat"><small>ACTIVE INCIDENTS</small><b>{len(active)}</b></div>
<div class="hstat"><small>LOG WINDOW</small><b class="m">{df.timestamp.min():%d %b %H:%M} → {df.timestamp.max():%d %b %H:%M}</b></div>
</div>""", unsafe_allow_html=True)
c = st.columns(6)
kpi(c[0], "Events analysed", f"{len(df):,}")
kpi(c[1], "Suspicious events", f"{susp_events:,}", "#F5A524", "#F5A524")
kpi(c[2], "Alerts", len(alerts), edge="#5AA9FF")
kpi(c[3], "Suspicious IPs", len(ips), "#FF8A3D", "#FF8A3D")
kpi(c[4], "Active incidents", len(active), "#FF4D5E" if active else "#34D399", "#FF4D5E" if active else "#34D399")
kpi(c[5], "Critical incidents", len(crit), "#FF4D5E" if crit else "#34D399", "#FF4D5E" if crit else "#34D399")
st.write("")

tabs = st.tabs(["Overview", "Attack replay", "Incidents", "Attack flow", "Geo & time", "Investigate",
                "Alerts", "Log explorer", "Before vs after"])

# ------------------------------------------------------------------ overview
with tabs[0]:
    l, r = st.columns([3, 2])
    with l:
        h = df.assign(hour=df.timestamp.dt.floor("h"),
                      source=df.ip.map(lambda x: "flagged IP" if x in flag_ips else "normal"))
        h = h.groupby(["hour", "source"]).size().reset_index(name="events")
        fig = px.bar(h, x="hour", y="events", color="source", title="Events per hour",
                     color_discrete_map={"normal": "#2F5E9E", "flagged IP": "#FF4D5E"})
        st.plotly_chart(theme(fig), use_container_width=True, key="ov_hour")
    with r:
        if alerts:
            sv = pd.Series([a["severity"] for a in alerts]).value_counts().reset_index()
            sv.columns = ["severity", "alerts"]
            fig = px.pie(sv, names="severity", values="alerts", hole=.6, title="Alert severity",
                         color="severity", color_discrete_map=SEV_COLOR)
            st.plotly_chart(theme(fig), use_container_width=True, key="ov_sev")
        else:
            st.info("No alerts in this log.")
    l, r = st.columns(2)
    with l:
        if alerts:
            t = pd.Series([a["mitre"] for a in alerts]).value_counts().reset_index()
            t.columns = ["technique", "alerts"]
            fig = px.bar(t, x="alerts", y="technique", orientation="h", title="MITRE ATT&CK techniques detected")
            fig.update_traces(marker_color="#22D3EE")
            fig.update_yaxes(autorange="reversed", title="")
            st.plotly_chart(theme(fig), use_container_width=True, key="ov_mitre")
    with r:
        if alerts:
            f = df[df.event == "login_failed"].assign(hour=lambda d: d.timestamp.dt.floor("h"))
            f = f.groupby("hour").size().reset_index(name="failed logins")
            fig = px.area(f, x="hour", y="failed logins", title="Failed logins over time (spikes = attacks)")
            fig.update_traces(line_color="#FF4D5E", fillcolor="rgba(255,77,94,.25)")
            st.plotly_chart(theme(fig), use_container_width=True, key="ov_fail")
    l, r = st.columns(2)
    with l:
        st.subheader("Suspicious IP ranking")
        if len(ips):
            st.dataframe(ips[["ip", "score", "level", "alerts", "users", "rules"]], hide_index=True,
                         use_container_width=True, column_config={"score": st.column_config.ProgressColumn(
                             "risk", min_value=0, max_value=100, format="%d")})
        else:
            st.success("No suspicious IPs.")
    with r:
        st.subheader("Suspicious users and high-risk accounts")
        by_user = {}
        for a in alerts:
            by_user.setdefault(a["user"], set()).add(a["rule"])
        rows = [{"user": u, "risk": min(100, sum(RULES[x][0] for x in rs)),
                 "high-risk": "possible takeover" if "success_after_bf" in rs else "",
                 "detections": ", ".join(sorted(rs))} for u, rs in by_user.items()]
        if rows:
            st.dataframe(pd.DataFrame(rows).sort_values("risk", ascending=False), hide_index=True,
                         use_container_width=True, column_config={"risk": st.column_config.ProgressColumn(
                             "risk", min_value=0, max_value=100, format="%d")})
        else:
            st.success("No suspicious users.")

# ------------------------------------------------------------------ attack replay (showpiece)
with tabs[1]:
    cand = list(dict.fromkeys([i.ip for i in incidents] + list(ips.ip)))
    if not cand:
        st.info("No suspicious IP in this log, so there is nothing to replay.")
    else:
        who = st.selectbox("Replay IP", cand, key="rp_ip")
        sub = df[df.ip == who].sort_values("timestamp", kind="stable")
        N = len(sub)
        tl = score_timeline(alerts, who)
        s1, s2 = st.columns([5, 1])
        pos = s1.slider("Replay position (events of this IP)", 1, N, N, key=f"rp_pos_{who}") if N > 1 else 1
        play = s2.button("▶ Play", use_container_width=True)
        st.caption("Alerts are stamped at the first event of their pattern. Score points come from the same "
                   "rules as the risk score (each rule once, plus the multi-stage bonus).")

        def draw(n, key):
            cur = sub.timestamp.iloc[n - 1]
            done = tl[tl.time <= cur]
            score = int(done.score.iloc[-1]) if len(done) else 0
            seen_stages = set(done.stage)
            done_sub = sub.iloc[:n]
            m = st.columns(5)
            kpi(m[0], "Replay time", f"{cur:%H:%M:%S}", edge="#22D3EE")
            kpi(m[1], "Events replayed", f"{n}/{N}")
            kpi(m[2], "Failed logins", int((done_sub.event == "login_failed").sum()), "#FF8A3D", "#FF8A3D")
            kpi(m[3], "Alerts so far", len(done), "#F5A524", "#F5A524")
            kpi(m[4], "Downloaded", f"{done_sub.bytes.sum() / 1048576:,.0f} MB", edge="#5AA9FF")
            g, mid, fd = st.columns([2, 3, 3])
            with g:
                gauge(score, "Risk score now", f"rp_g_{key}", 250)
            with mid:
                st.markdown("**Kill chain reached**" + chain_html(seen_stages,
                            done.stage.iloc[-1] if len(done) else None), unsafe_allow_html=True)
                techs = {}
                for a in alerts:
                    if a["ip"] == who and a["time"] <= cur:
                        techs[a["mitre_id"]] = a["mitre_name"]
                st.markdown("**ATT&CK techniques so far**<br>" + ("".join(mitre_chip(k, v) for k, v in techs.items())
                            or '<span style="color:#8A9BB8">none yet</span>'), unsafe_allow_html=True)
            with fd:
                st.markdown("**Detections fired**")
                if done.empty:
                    st.caption("Nothing flagged yet.")
                for _, r_ in done.tail(5).iloc[::-1].iterrows():
                    st.markdown(f'<div class="step" style="--c:{SEV_COLOR[RULES[r_.rule][1]]}">'
                                f'<b>+{r_.points}</b> {E(r_.label)} <small>{r_.time:%H:%M:%S} · now {r_.score}/100</small>'
                                f'</div>', unsafe_allow_html=True)
            if len(tl):
                fig = go.Figure(go.Scatter(x=tl.time, y=tl.score, mode="lines+markers", line_shape="hv",
                                           line=dict(color="#FF4D5E", width=3), name="risk score"))
                fig.add_shape(type="line", x0=cur, x1=cur, y0=0, y1=1, yref="paper",
                              line=dict(color="#22D3EE", width=2, dash="dot"))
                fig.update_yaxes(range=[0, 105], title="risk score")
                fig.update_layout(title="Risk score build-up (cyan line = replay position)", showlegend=False)
                st.plotly_chart(theme(fig, 260), use_container_width=True, key=f"rp_c_{key}")

        if play:
            frames = sorted({round(1 + i * (N - 1) / (min(N, 40) - 1)) for i in range(min(N, 40))}) if N > 1 else [1]
            ph = st.empty()
            for f in frames:
                with ph.container():
                    draw(f, f"p{f}")
                time.sleep(0.2)
        else:
            draw(pos, "s")

# ------------------------------------------------------------------ incidents
with tabs[2]:
    if not incidents:
        st.success("No correlated incident in this log. Individual alerts, if any, are on the Alerts tab.")
    for inc in incidents:
        col = SEV_COLOR[inc.severity]
        st.markdown(f'<div class="inc"><h3>{inc.id} · {E(inc.title)}</h3>'
                    f'{badge(inc.severity.upper(), col)}{badge("confidence: " + inc.confidence, "#8A9BB8")}'
                    f'<span style="color:#B7C4DC">first seen {inc.start:%d %b %H:%M} | last seen {inc.end:%H:%M} | '
                    f'{inc.event_count} evidence events | {len(inc.related_users)} accounts involved</span></div>',
                    unsafe_allow_html=True)
        g, m = st.columns([1, 2])
        with g:
            gauge(inc.score, "Risk score", f"g_{inc.id}")
            st.selectbox("Status", STATUSES, key=f"status_{inc.id}")
        with m:
            present = {a["stage"] for a in inc.timeline}
            st.markdown("<b>Attack chain reached</b>" + chain_html(present), unsafe_allow_html=True)
            st.markdown("<b>MITRE ATT&CK</b><br>" + "".join(mitre_chip(t["id"], t["name"]) for t in inc.mitre),
                        unsafe_allow_html=True)
            pts = [(r.split(" ", 1)[0], r.split(" ", 1)[1]) for r in inc.reasons if r.startswith("+")]
            if pts:
                fig = px.bar(x=[int(p[0]) for p in pts], y=[p[1] for p in pts], orientation="h",
                             title="Why this score (points per reason)")
                fig.update_traces(marker_color=col)
                fig.update_yaxes(autorange="reversed", title="")
                fig.update_xaxes(title="points")
                st.plotly_chart(theme(fig, 250), use_container_width=True, key=f"w_{inc.id}")
            for r_ in inc.reasons:
                if not r_.startswith("+"):
                    st.caption(r_)
        o, i_ = st.columns(2)
        o.markdown('<div class="card observed"><h4>Observed evidence (from the logs)</h4><ul>' +
                   "".join(f"<li>{E(x)}</li>" for x in inc.observed) + "</ul></div>", unsafe_allow_html=True)
        i_.markdown(f'<div class="card inferred"><h4>Inferred attack sequence (our interpretation)</h4>'
                    f'<p style="color:#D5DEF0">{E(inc.story)}</p>'
                    f'<small style="color:#8A9BB8">Inferred from correlated events; it suggests, it does not prove.</small></div>',
                    unsafe_allow_html=True)
        st.subheader("Timeline")
        for a in inc.timeline:
            st.markdown(f'<div class="step" style="--c:{SEV_COLOR[a["severity"]]}"><b>{a["stage"]}</b> '
                        f'<small>{a["time"]:%d %b %H:%M:%S} | {a["severity"]} | confidence {a["confidence"]}</small> '
                        f'{mitre_chip(a["mitre_id"], a["mitre_name"])}<br>{E(a["detail"])}<br>'
                        f'<small>Why it matters: {E(a["reason"])}</small></div>', unsafe_allow_html=True)
        d = df.set_index("timestamp")
        fig = go.Figure()
        for name, mask, colr in (("other IPs", d.ip != inc.ip, "#2F5E9E"), (inc.ip, d.ip == inc.ip, "#FF4D5E")):
            s = d[mask].resample("1h").size()
            fig.add_bar(x=s.index, y=s.values, name=name, marker_color=colr)
        fig.update_layout(barmode="stack", title="Activity: normal vs attacker")
        st.plotly_chart(theme(fig, 280), use_container_width=True, key=f"a_{inc.id}")
        with st.expander(f"Evidence: {inc.event_count} log rows (with the reason each row matters)"):
            ev = inc.evidence[["timestamp", "user", "event", "resource", "bytes", "why"]]
            only = st.checkbox("Hide failed logins", key=f"hf_{inc.id}")
            st.dataframe(ev[ev.event != "login_failed"] if only else ev, use_container_width=True, hide_index=True)
        st.markdown('<div class="card"><h4>Recommended actions</h4><ul>' +
                    "".join(f"<li>{E(x)}</li>" for x in inc.recommendations) + "</ul></div>", unsafe_allow_html=True)
        status = st.session_state.get(f"status_{inc.id}", "open")
        d1, d2, d3 = st.columns(3)
        d1.download_button("Report (.md)", incident_to_markdown(inc, status), file_name=f"{inc.id}.md",
                           key=f"dlm_{inc.id}", use_container_width=True)
        d2.download_button("Incident (.json)", json.dumps(incident_to_dict(inc, status), indent=2),
                           file_name=f"{inc.id}.json", key=f"dlj_{inc.id}", use_container_width=True)
        d3.download_button("Evidence (.csv)", inc.evidence.to_csv(index_label="row"),
                           file_name=f"{inc.id}_evidence.csv", key=f"dlc_{inc.id}", use_container_width=True)
        st.divider()

# ------------------------------------------------------------------ attack flow
with tabs[3]:
    fcand = list(dict.fromkeys([i.ip for i in incidents] + list(ips.ip)))
    if not fcand:
        st.info("No suspicious IP in this log, so there is no attack flow to draw.")
    else:
        fip = st.selectbox("Source IP", fcand, key="flow_ip")
        fsub = df[df.ip == fip]
        st.caption("Width = number of real log events: IP → accounts touched → action → resource.")
        st.plotly_chart(sankey(fsub), use_container_width=True, key="flow")

# ------------------------------------------------------------------ geo & time
with tabs[4]:
    cs = df.groupby("country").agg(events=("event", "size"),
                                   failed=("event", lambda s: int((s == "login_failed").sum())),
                                   success=("event", lambda s: int((s == "login_success").sum()))).reset_index()
    cs["iso"] = cs.country.map(lambda x: x if len(x) == 3 else ISO3.get(x.upper()))
    mapped = cs.dropna(subset=["iso"])
    l, r = st.columns([3, 2])
    with l:
        if len(mapped):
            fig = px.choropleth(mapped, locations="iso", color="failed", hover_name="country",
                                hover_data={"iso": False, "events": True, "success": True, "failed": True},
                                color_continuous_scale=[[0, "#16233B"], [1, "#FF4D5E"]],
                                title="Failed logins by country")
            fig.update_geos(bgcolor="rgba(0,0,0,0)", landcolor="#101A2E", showcountries=True,
                            countrycolor="#1C2A44", showframe=False, projection_type="natural earth",
                            showocean=True, oceancolor="#070B14", lakecolor="#070B14")
            fig.update_layout(coloraxis_colorbar=dict(title="failed"))
            st.plotly_chart(theme(fig, 420), use_container_width=True, key="geo")
        else:
            st.info("Country codes in this log could not be placed on the map. See the table.")
        if len(cs) > len(mapped):
            st.caption("Not on the map (unknown code): " + ", ".join(cs[cs.iso.isna()].country))
    with r:
        st.dataframe(cs.drop(columns="iso").sort_values("failed", ascending=False), hide_index=True,
                     use_container_width=True)
    fl = df[df.event == "login_failed"]
    if fl.empty:
        st.info("No failed logins in this log.")
    else:
        pv = fl.assign(day=fl.timestamp.dt.strftime("%d %b"), hr=fl.timestamp.dt.hour) \
            .pivot_table(index="hr", columns="day", values="event", aggfunc="size", fill_value=0)
        pv = pv.reindex(range(24), fill_value=0)
        days = sorted(pv.columns, key=lambda x: pd.to_datetime(x + " 2000", format="%d %b %Y"))
        fig = go.Figure(go.Heatmap(z=pv[days].values, x=days, y=list(pv.index), colorscale=
                                   [[0, "#0E1626"], [.01, "#2A3A1F"], [.4, "#F5A524"], [1, "#FF4D5E"]],
                                   colorbar=dict(title="failed")))
        fig.update_yaxes(title="hour of day", dtick=2, autorange="reversed")
        fig.update_xaxes(title="day", type="category")
        fig.update_layout(title="Failed-login heatmap (hour × day)")
        st.plotly_chart(theme(fig, 420), use_container_width=True, key="heat")

# ------------------------------------------------------------------ investigate
with tabs[5]:
    mode = st.radio("Investigate by", ["IP address", "User"], horizontal=True)
    if mode == "IP address":
        order = list(ips.ip) + sorted(set(df.ip) - flag_ips)
        who_i = st.selectbox("IP", order[:300])
        sub_i = df[df.ip == who_i]
        rel = [a for a in alerts if a["ip"] == who_i]
    else:
        order = list(dict.fromkeys([a["user"] for a in alerts] + sorted(set(df.user))))
        who_i = st.selectbox("User", order)
        sub_i = df[df.user == who_i]
        rel = [a for a in alerts if a["user"] == who_i]
    c = st.columns(5)
    kpi(c[0], "Events", len(sub_i))
    kpi(c[1], "Failed logins", int((sub_i.event == "login_failed").sum()), "#FF8A3D", "#FF8A3D")
    kpi(c[2], "Successful logins", int((sub_i.event == "login_success").sum()), edge="#34D399")
    kpi(c[3], "Downloaded", f"{sub_i.bytes.sum() / 1048576:,.0f} MB", edge="#5AA9FF")
    kpi(c[4], "Alerts", len(rel), "#FF4D5E" if rel else "#34D399", "#FF4D5E" if rel else "#34D399")
    st.write("")
    if len(sub_i):
        st.caption(f"Countries: {', '.join(sorted(set(sub_i.country)))} | IPs: {sub_i.ip.nunique()} | "
                   f"Users: {sub_i.user.nunique()} | {sub_i.timestamp.min():%d %b %H:%M} to {sub_i.timestamp.max():%d %b %H:%M}")
        fig = px.scatter(sub_i, x="timestamp", y="event", color="event", title="Event timeline",
                         color_discrete_map=EVENT_COLOR)
        st.plotly_chart(theme(fig, 260), use_container_width=True, key="inv_tl")
    for a in rel:
        st.markdown(f'<div class="step" style="--c:{SEV_COLOR[a["severity"]]}"><b>{E(a["label"])}</b> '
                    f'<small>{a["time"]:%d %b %H:%M:%S}</small> {mitre_chip(a["mitre_id"], a["mitre_name"])}'
                    f'<br>{E(a["detail"])}</div>', unsafe_allow_html=True)
    st.dataframe(sub_i.tail(500), use_container_width=True, hide_index=True)

# ------------------------------------------------------------------ alerts
with tabs[6]:
    f1, f2, f3, f4 = st.columns([2, 2, 2, 3])
    sev = f1.multiselect("Severity", list(SEV_ORDER), default=list(SEV_ORDER))
    techs_all = sorted({a["mitre"] for a in alerts})
    tech = f2.multiselect("MITRE technique", techs_all, default=techs_all)
    conf = f3.multiselect("Confidence", ["high", "medium", "low"], default=["high", "medium", "low"])
    q = f4.text_input("Search IP / user / text")
    rows = [a for a in alerts if a["severity"] in sev and a["mitre"] in tech and a["confidence"] in conf and
            (not q or q.lower() in f"{a['ip']} {a['user']} {a['detail']}".lower())]
    st.caption(f"{len(rows)} of {len(alerts)} alerts")
    if rows:
        st.dataframe(pd.DataFrame(rows)[["id", "time", "severity", "confidence", "stage", "mitre", "ip", "user",
                                         "detail"]], hide_index=True, use_container_width=True)
        pick = st.selectbox("Show supporting events for alert", [a["id"] for a in rows])
        a = next(x for x in rows if x["id"] == pick)
        st.markdown(f"**Why it matters:** {a['reason']}")
        st.markdown(mitre_chip(a["mitre_id"], a["mitre_name"]) + f' tactic: {E(a["mitre_tactic"])}',
                    unsafe_allow_html=True)
        st.dataframe(df.loc[[i for i in a["evidence"] if i in df.index]], use_container_width=True, hide_index=True)
    else:
        st.info("No alerts match the filters.")

# ------------------------------------------------------------------ log explorer
with tabs[7]:
    e1, e2, e3 = st.columns(3)
    ev_sel = e1.multiselect("Event type", sorted(df.event.unique()), default=sorted(df.event.unique()))
    co_sel = e2.multiselect("Country", sorted(df.country.unique()), default=sorted(df.country.unique()))
    only_flag = e3.checkbox("Only flagged IPs")
    t1, t2, t3 = st.columns([2, 2, 3])
    user_q = t1.text_input("User contains")
    ip_q = t2.text_input("IP contains")
    rng = t3.date_input("Date range", (df.timestamp.min().date(), df.timestamp.max().date()))
    v = df[df.event.isin(ev_sel) & df.country.isin(co_sel)]
    if only_flag:
        v = v[v.ip.isin(flag_ips)]
    if user_q:
        v = v[v.user.str.contains(user_q, case=False, regex=False)]
    if ip_q:
        v = v[v.ip.str.contains(ip_q, regex=False)]
    if isinstance(rng, tuple) and len(rng) == 2:
        v = v[(v.timestamp.dt.date >= rng[0]) & (v.timestamp.dt.date <= rng[1])]
    st.caption(f"{len(v):,} of {len(df):,} events (showing first 1,000)")
    st.dataframe(v.head(1000), use_container_width=True, hide_index=True)
    st.download_button("Download filtered events (.csv)", v.to_csv(index=False), file_name="filtered_events.csv")

# ------------------------------------------------------------------ before vs after
with tabs[8]:
    st.subheader("From thousands of events to one story")
    fig = go.Figure(go.Funnel(y=["Raw log events", "Suspicious events", "Alerts", "Incidents"],
                              x=[len(df), susp_events, len(alerts), len(incidents)],
                              marker={"color": ["#2F5E9E", "#F5A524", "#FF8A3D", "#FF4D5E"]}, textinfo="value"))
    st.plotly_chart(theme(fig, 320), use_container_width=True, key="funnel")
    b, a = st.columns(2)
    with b:
        st.markdown("**Before: what an analyst sees in the raw log**")
        if incidents:
            raw = df[df.ip == incidents[0].ip].sort_values("timestamp")
            st.dataframe(raw[["timestamp", "user", "ip", "event", "resource"]].head(15), hide_index=True,
                         use_container_width=True)
            st.caption(f"First 15 of {len(raw)} events from one IP. Each looks small on its own.")
        else:
            st.dataframe(df.sample(min(15, len(df)), random_state=1)[["timestamp", "user", "ip", "event"]],
                         hide_index=True, use_container_width=True)
    with a:
        st.markdown("**After: one correlated incident**")
        if incidents:
            i = incidents[0]
            st.markdown(f'<div class="inc"><h3>{E(i.title)}</h3>{badge(i.severity.upper(), SEV_COLOR[i.severity])}'
                        f'Risk {i.score}/100 | user {E(i.user)} | IP {E(i.ip)}</div>', unsafe_allow_html=True)
            seq = " > ".join(dict.fromkeys(x["label"] for x in i.timeline if x["rule"] != "off_hours"))
            st.markdown(f"**Attack sequence:** {seq}")
            st.info(i.story)
        else:
            st.success("No incident in this scenario. Switch the demo scenario in the sidebar to compare.")