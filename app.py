"""Find the Intruder - SOC analyst console. Run: streamlit run app.py
All figures are computed from the loaded log by detector.py and correlation.py."""
import html
import json
import os
import time
from contextlib import contextmanager

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from correlation import find_campaigns, impossible_travel
from detector import (MITRE, RULE_INFO, RULES, SEV_ORDER, STAGE_ORDER, Params, analyze, default_params,
                      incident_to_dict, incident_to_markdown, load_logs, mitre_url, score_timeline)

SINGLE = os.path.join("data", "auth_logs.csv")
MULTI = os.path.join("data", "auth_logs_multi.csv")
SAMPLES = {"Multi-actor sample": MULTI, "Single-intruder sample": SINGLE}
CASE_FILE = os.path.join("data", "case_state.json")
SEV_COLOR = {"low": "#8B9BB0", "medium": "#F5C451", "high": "#FF9248", "critical": "#FF5C5C"}
EVENT_COLOR = {"login_failed": "#FF9248", "login_success": "#3DDC84", "file_download": "#4DA3FF",
               "privilege_change": "#FF5C5C", "log_cleared": "#B794F6"}
STATUSES = ["open", "investigating", "contained", "resolved"]
SCENARIOS = ["Full sample log", "Brute force only (no successful login)", "Benign traffic only (attacker removed)"]
SPEEDS = {"Slow": 0.4, "Normal": 0.2, "Fast": 0.08}
TEXT, MUTED, GRID, LINE = "#E8EEF6", "#A9B8CC", "#1A2433", "#26344A"
NEUTRAL = "#3A4B66"
ISO3 = dict(p.split(":") for p in (
    "IN:IND US:USA GB:GBR DE:DEU FR:FRA RU:RUS CN:CHN NL:NLD BR:BRA JP:JPN CA:CAN AU:AUS SG:SGP IE:IRL "
    "SE:SWE UA:UKR RO:ROU TR:TUR KR:KOR ID:IDN VN:VNM IR:IRN KP:PRK PL:POL ES:ESP IT:ITA ZA:ZAF MX:MEX "
    "AE:ARE HK:HKG PK:PAK BD:BGD NG:NGA EG:EGY CH:CHE BY:BLR KZ:KAZ AR:ARG").split())

st.set_page_config(page_title="Find the Intruder", layout="wide")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');
:root {--bg:#070B11; --panel:#0F1620; --panel2:#152030; --head:#182740; --line:#26344A; --muted:#A9B8CC;
  --text:#E8EEF6; --accent:#4DA3FF;}
.stApp {background:radial-gradient(900px 420px at 0% -5%, #12315A 0%, transparent 60%),
  radial-gradient(800px 380px at 100% 0%, #2A1530 0%, transparent 55%), var(--bg); color:var(--text);}
html, body, [class*="st-"], button, input, textarea {font-family:Inter,"Segoe UI",system-ui,sans-serif;}
.block-container {padding-top:1rem; padding-bottom:3rem; max-width:1480px;}
[data-testid="stAppDeployButton"], #MainMenu, footer {display:none !important;}
header[data-testid="stHeader"] {background:transparent;}
section[data-testid="stSidebar"] {background:linear-gradient(180deg,#0A1019,#070B11); border-right:1px solid var(--line);}
p, li {font-size:14px; line-height:1.65;}

/* SECTION PANELS: card + filled header strip + number chip */
[data-testid="stVerticalBlockBorderWrapper"] {background:linear-gradient(180deg,#111B28,#0D141D);
  border:1px solid var(--line) !important; border-radius:14px; padding:0 18px 16px !important;
  box-shadow:0 6px 24px rgba(0,0,0,.35); margin-bottom:6px;}
.ph {display:flex; align-items:center; gap:14px; margin:0 -18px 16px; padding:13px 18px;
  background:linear-gradient(90deg,#1A2D4A,#131E2E 70%); border-bottom:1px solid var(--line);
  border-radius:13px 13px 0 0;}
.chip {flex:none; min-width:34px; height:34px; border-radius:9px; display:grid; place-items:center;
  font-family:"JetBrains Mono",Consolas,monospace; font-size:13px; font-weight:600; color:#fff;
  background:linear-gradient(135deg,#4DA3FF,#2F6FE0); box-shadow:0 0 14px rgba(77,163,255,.45);}
.ptxt {display:flex; flex-direction:column; gap:2px;}
.pt {font-size:16px; font-weight:700; letter-spacing:.01em; color:#fff; line-height:1.2;}
.ps {font-size:12.5px; color:var(--muted);}

/* top bar */
.topbar {display:flex; justify-content:space-between; align-items:center; gap:20px; padding:18px 24px;
  margin-bottom:16px; border:1px solid var(--line); border-radius:16px;
  background:linear-gradient(100deg,#13294A 0%,#0F1823 55%,#1D1428 100%); box-shadow:0 8px 30px rgba(0,0,0,.4);}
.brandwrap {display:flex; align-items:center; gap:16px;}
.logo {width:46px; height:46px; border-radius:12px; border:2px solid var(--accent); position:relative;
  background:#0B1A2E; flex:none; box-shadow:0 0 22px rgba(77,163,255,.5);}
.logo:before {content:""; position:absolute; inset:10px; border-radius:50%; border:2px solid var(--accent);}
.logo:after {content:""; position:absolute; left:18px; top:18px; width:8px; height:8px; border-radius:50%;
  background:#FF5C5C; box-shadow:0 0 10px #FF5C5C;}
.brand {font-size:26px; font-weight:800; letter-spacing:-.01em; line-height:1.1;}
.brand small {display:block; font-size:13px; font-weight:400; color:var(--muted); margin-top:5px; letter-spacing:0;}
.pills {display:flex; gap:10px; flex-wrap:wrap; justify-content:flex-end;}
.pill {border:1px solid var(--line); background:rgba(15,22,32,.8); border-radius:20px; padding:6px 14px;
  font-size:12px; color:var(--muted); font-variant-numeric:tabular-nums;}
.pill b {color:var(--text); font-weight:600;}
.dot {display:inline-block; width:8px; height:8px; border-radius:50%; background:var(--d,#3DDC84);
  box-shadow:0 0 8px var(--d,#3DDC84); margin-right:8px;}

/* banner */
.banner {border:1px solid var(--line); border-left:6px solid var(--c); border-radius:12px; padding:16px 22px;
  margin:4px 0 16px; background:linear-gradient(90deg, color-mix(in srgb, var(--c) 16%, #0F1620), #0F1620 75%);
  box-shadow:0 0 28px color-mix(in srgb, var(--c) 18%, transparent);}
.banner .bl {font-size:11.5px; font-weight:800; text-transform:uppercase; letter-spacing:.12em; color:var(--c); margin-bottom:5px;}
.banner .bt {font-size:15.5px; line-height:1.55;}

/* kpi tiles */
.kpis {display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:14px; margin:0 0 18px;}
.kpi {position:relative; overflow:hidden; background:linear-gradient(180deg,#131E2C,#0E1620); border:1px solid var(--line);
  border-radius:14px; padding:16px 18px 14px; transition:transform .15s, border-color .15s;}
.kpi:before {content:""; position:absolute; left:0; right:0; top:0; height:4px;
  background:linear-gradient(90deg,var(--k,#3A4B66),transparent);}
.kpi:hover {transform:translateY(-3px); border-color:var(--k,#3A4B66);}
.kl {font-size:11px; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); font-weight:600;}
.kv {font-size:34px; font-weight:800; margin-top:6px; line-height:1.05; font-variant-numeric:tabular-nums;}
.ks {font-size:12px; color:var(--muted); margin-top:7px;}
.side-label {font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:.12em; color:#9FB4D0;
  margin:22px 0 8px; padding-top:16px; border-top:1px solid var(--line);}
.side-label.first {border-top:none; padding-top:0; margin-top:4px;}

/* item cards */
.card {display:flex; align-items:center; gap:22px; background:linear-gradient(90deg,#16233A,#111A27);
  border:1px solid var(--line); border-left:6px solid var(--c); border-radius:12px; padding:18px 22px; margin-bottom:12px;
  box-shadow:0 0 22px color-mix(in srgb, var(--c) 14%, transparent);}
.card.hero {padding:24px 28px; margin-bottom:16px;
  background:linear-gradient(90deg, color-mix(in srgb, var(--c) 15%, #101A28), #101A28 70%);}
.card-body {flex:1; min-width:0;}
.card-top {display:flex; justify-content:space-between; align-items:center;}
.card-title {font-size:17px; font-weight:700; margin:8px 0 7px;}
.hero .card-title {font-size:25px; font-weight:800; margin:10px 0 10px;}
.card-text {font-size:13px; color:#B9C6D6; margin:8px 0 2px; line-height:1.6;}
.meta {font-size:12.5px; color:var(--muted);}
.meta span {margin-right:22px; display:inline-block;} .meta b {color:var(--text); font-weight:600;}
.mono {font-family:"JetBrains Mono",Consolas,monospace; font-size:12px; color:var(--muted);}
.ring {width:82px; height:82px; border-radius:50%; flex:none; display:grid; place-items:center;
  background:conic-gradient(var(--c) calc(var(--p) * 1%), #1F2C40 0); box-shadow:0 0 20px color-mix(in srgb, var(--c) 40%, transparent);}
.ring i {width:62px; height:62px; border-radius:50%; background:#0F1824; display:grid; place-items:center;
  font-style:normal; font-size:23px; font-weight:800; font-variant-numeric:tabular-nums;}
.ringlabel {font-size:10px; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); text-align:center; margin-top:6px;}
.ringbox {display:flex; flex-direction:column; align-items:center; flex:none;}
.sev {display:inline-block; padding:0 10px; border:1px solid; border-radius:5px; font-size:11px; font-weight:700;
  letter-spacing:.08em; line-height:21px;}
.tech {font-family:"JetBrains Mono",Consolas,monospace; font-size:12px; border:1px solid #34476A; background:#16233A;
  padding:3px 9px; border-radius:5px; margin:0 6px 5px 0; color:var(--text) !important; text-decoration:none; display:inline-block;}
.tech:hover {border-color:var(--accent); box-shadow:0 0 10px rgba(77,163,255,.35);}

/* kill chain */
.chain {display:flex; flex-wrap:wrap; align-items:center; gap:8px; margin:4px 0 14px;}
.stage {padding:9px 16px; border:1px solid var(--line); border-radius:8px; font-size:12.5px; color:#5A6B85; background:#0B1119;}
.stage.on {color:#fff; background:linear-gradient(135deg,#1F4C86,#173A67); border-color:#4DA3FF; font-weight:700;
  box-shadow:0 0 14px rgba(77,163,255,.4);}
.arrow {color:#46587A; font-size:16px;}

/* timeline */
.tl {margin:8px 0 4px 10px; border-left:2px solid var(--line);}
.tl-item {position:relative; padding:0 0 18px 26px;}
.tl-item:before {content:""; position:absolute; left:-8px; top:3px; width:14px; height:14px; border-radius:50%;
  background:var(--c); border:3px solid #0F1620; box-shadow:0 0 10px var(--c);}
.tl-time {font-family:"JetBrains Mono",Consolas,monospace; font-size:12px; color:var(--muted);}
.tl-detail {font-size:13.5px; margin-top:4px; line-height:1.55;}

/* streamlit widgets */
div[data-baseweb="tab-list"] {gap:8px; padding:6px; background:#0D141D; border:1px solid var(--line); border-radius:14px; margin-bottom:14px;}
button[data-baseweb="tab"] {font-size:13.5px; font-weight:600; padding:9px 18px; border-radius:10px; color:var(--muted); background:transparent;}
button[data-baseweb="tab"]:hover {color:#fff; background:#16233A;}
button[data-baseweb="tab"][aria-selected="true"] {color:#fff; background:linear-gradient(135deg,#2563C9,#1B48A0);
  box-shadow:0 0 16px rgba(77,163,255,.45);}
div[data-baseweb="tab-highlight"], div[data-baseweb="tab-border"] {display:none !important;}
[data-testid="stDataFrame"] {border:1px solid var(--line); border-radius:10px; overflow:hidden;}
div[data-testid="stExpander"] {border:1px solid var(--line); border-radius:10px; background:var(--panel);}
.stButton>button, .stDownloadButton>button {border-radius:9px; font-size:13px; font-weight:600; border:1px solid #34476A;
  background:linear-gradient(180deg,#1A2A44,#142036);}
.stButton>button:hover, .stDownloadButton>button:hover {border-color:var(--accent); color:#fff; box-shadow:0 0 14px rgba(77,163,255,.35);}
</style>""", unsafe_allow_html=True)

# ---- dark-theme fixes: no white strip, readable text, safe icon font, big highlighted section tabs ----
st.markdown("""
<style>
/* white strip / background */
:root {color-scheme: dark;}
html, body {background:#070B11 !important;}
.stApp {background-color:#070B11 !important;}
[data-testid="stAppViewContainer"], [data-testid="stMain"], [data-testid="stSidebarContent"],
[data-testid="stSidebarUserContent"] {background:transparent !important;}
[data-testid="stBottom"], [data-testid="stBottom"] > div, [data-testid="stBottomBlockContainer"],
[data-testid="stToolbar"], [data-testid="stDecoration"] {background:#070B11 !important;}

/* readable text */
[data-testid="stMarkdownContainer"] p, [data-testid="stMarkdownContainer"] li {color:#E8EEF6;}
[data-testid="stWidgetLabel"] p, label p {color:#D5E0EE !important; font-size:13.5px !important; font-weight:600;}
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p {color:#A9B8CC !important;
  font-size:13px !important; opacity:1 !important;}
.stCheckbox label p, .stRadio label p {color:#E8EEF6 !important;}
input, textarea, [data-baseweb="select"] * {color:#E8EEF6 !important;}
[data-baseweb="select"] > div, [data-baseweb="input"] > div, textarea
  {background-color:#0F1824 !important; border-color:#34476A !important;}
[data-baseweb="popover"] ul, [data-baseweb="popover"] li {background:#0F1824 !important; color:#E8EEF6 !important;}
.stage {color:#9FB2CE;} .arrow {color:#7C90B0;}
.ps, .ks, .meta, .tl-time, .mono, .ringlabel {color:#A9B8CC;}

/* keep Inter for text but do NOT break Streamlit's icon font */
span[data-testid="stIconMaterial"], [data-testid="stExpanderToggleIcon"] *,
.material-symbols-rounded, .material-icons {font-family:"Material Symbols Rounded" !important;}

/* big, clearly highlighted section tabs */
div[data-baseweb="tab-list"] {gap:10px; padding:10px; background:linear-gradient(180deg,#101A28,#0B121B);
  border:1px solid #2F4263; border-radius:16px; box-shadow:0 6px 22px rgba(0,0,0,.45);}
button[data-baseweb="tab"] {flex:1 1 auto; justify-content:center; height:auto !important;
  padding:14px 18px !important; border:1px solid #2A3B57 !important; border-radius:12px !important;
  background:#0F1824 !important; color:#C9D6E6 !important;}
button[data-baseweb="tab"] p {font-size:16.5px !important; font-weight:700 !important; color:inherit !important; margin:0;}
button[data-baseweb="tab"]:hover {background:#17263D !important; border-color:#4DA3FF !important; color:#fff !important;}
button[data-baseweb="tab"][aria-selected="true"] {background:linear-gradient(135deg,#2F7BFF,#1B48A0) !important;
  color:#fff !important; border-color:#8CC2FF !important;
  box-shadow:0 0 22px rgba(77,163,255,.6), inset 0 -3px 0 #BFE0FF;}

/* section title bar shown at the top of every tab */
.sec {display:flex; align-items:center; gap:16px; padding:18px 24px; margin:6px 0 18px;
  border:1px solid #2F4263; border-left:8px solid #4DA3FF; border-radius:14px;
  background:linear-gradient(90deg,#16294A,#0F1823 80%);}
.sec-ico {font-size:30px; line-height:1;}
.sec-t {font-size:24px; font-weight:800; color:#fff; line-height:1.15;}
.sec-s {font-size:13.5px; color:#A9B8CC; margin-top:3px;}
</style>""", unsafe_allow_html=True)


def section_header(icon, title, sub):
    """Big title bar at the top of a tab so each section is clearly highlighted."""
    st.markdown(f'<div class="sec"><div class="sec-ico">{icon}</div><div><div class="sec-t">'
                f'{html.escape(title)}</div><div class="sec-s">{html.escape(sub)}</div></div></div>',
                unsafe_allow_html=True)


# ------------------------------------------------------------------ case state (persisted)
def _read_cases():
    try:
        with open(CASE_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


if "cases" not in st.session_state:
    st.session_state.cases = _read_cases()
CASES = st.session_state.cases


def save_cases():
    try:
        os.makedirs(os.path.dirname(CASE_FILE), exist_ok=True)
        with open(CASE_FILE, "w", encoding="utf-8") as fh:
            json.dump(CASES, fh, indent=2)
    except OSError:
        st.session_state["case_save_failed"] = True


def on_status(ip):
    CASES.setdefault(ip, {})["status"] = st.session_state[f"status_{ip}"]
    save_cases()


def on_notes(ip):
    CASES.setdefault(ip, {})["notes"] = st.session_state[f"notes_{ip}"]
    save_cases()


def status_of(inc):
    return st.session_state.get(f"status_{inc.ip}", CASES.get(inc.ip, {}).get("status", "open"))


# ------------------------------------------------------------------ helpers
_N = {"i": 0}


def tab_start():
    _N["i"] = 0


@contextmanager
def panel(title, sub=""):
    """Bordered card with a filled, numbered header strip. Everything in the `with` block is inside the card."""
    _N["i"] += 1
    with st.container(border=True):
        s = f'<span class="ps">{html.escape(sub)}</span>' if sub else ""
        st.markdown(f'<div class="ph"><span class="chip">{_N["i"]:02d}</span><span class="ptxt">'
                    f'<span class="pt">{html.escape(title)}</span>{s}</span></div>', unsafe_allow_html=True)
        yield


def side_label(text, first=False):
    st.markdown(f'<div class="side-label{" first" if first else ""}">{html.escape(text)}</div>',
                unsafe_allow_html=True)


def kpis(items):
    """Stat tiles. items = [(label, value[, css_color[, sub_text]])]."""
    cells = ""
    for it in items:
        color = it[2] if len(it) > 2 and it[2] else None
        sub = it[3] if len(it) > 3 else ""
        k = f' style="--k:{color}"' if color else ""
        v = f' style="color:{color}"' if color else ""
        s = f'<div class="ks">{html.escape(str(sub))}</div>' if sub else ""
        cells += (f'<div class="kpi"{k}><div class="kl">{html.escape(str(it[0]))}</div>'
                  f'<div class="kv"{v}>{html.escape(str(it[1]))}</div>{s}</div>')
    st.markdown(f'<div class="kpis">{cells}</div>', unsafe_allow_html=True)


def sev_badge(sev):
    c = SEV_COLOR.get(sev, MUTED)
    return f'<span class="sev" style="color:{c};border-color:{c};background:{c}26">{sev.upper()}</span>'


def technique_links(items):
    return " ".join(f'<a class="tech" href="{mitre_url(i)}" target="_blank">{i} {html.escape(n)}</a>'
                    for i, n in items)


def kill_chain(present):
    parts = [f'<span class="stage{" on" if s in present else ""}">{s}</span>' for s in STAGE_ORDER]
    return '<div class="chain">' + '<span class="arrow">&rsaquo;</span>'.join(parts) + "</div>"


def timeline_html(tl):
    items = ""
    for a in tl:
        c = SEV_COLOR[a["severity"]]
        items += (f'<div class="tl-item" style="--c:{c}"><div class="tl-time">{a["time"]:%d %b %H:%M:%S}'
                  f' &nbsp;|&nbsp; {html.escape(a["stage"])} &nbsp;|&nbsp; {a["mitre_id"]}</div>'
                  f'<div class="tl-detail">{html.escape(a["detail"])}</div></div>')
    return f'<div class="tl">{items}</div>'


def incident_card(inc, hero=False):
    c = SEV_COLOR[inc.severity]
    chips = technique_links([(t["id"], t["name"]) for t in inc.mitre])
    return (f'<div class="card{" hero" if hero else ""}" style="--c:{c}"><div class="card-body">'
            f'<div class="card-top"><span class="mono">{inc.id} &nbsp;|&nbsp; {html.escape(status_of(inc))}</span>'
            f'{sev_badge(inc.severity)}</div>'
            f'<div class="card-title">{html.escape(inc.title)}</div>'
            f'<div class="meta"><span>Source <b>{html.escape(inc.ip)}</b></span>'
            f'<span>Account <b>{html.escape(inc.user)}</b></span>'
            f'<span>First seen <b>{inc.start:%d %b %H:%M}</b></span>'
            f'<span>Last seen <b>{inc.end:%H:%M}</b></span>'
            f'<span>Confidence <b>{inc.confidence}</b></span>'
            f'<span>Evidence rows <b>{inc.event_count}</b></span></div>'
            f'<div style="margin-top:12px">{chips}</div></div>'
            f'<div class="ringbox"><div class="ring" style="--c:{c};--p:{inc.score}"><i>{inc.score}</i></div>'
            f'<div class="ringlabel">risk</div></div></div>')


def campaign_card(c):
    col = SEV_COLOR[c["severity"]]
    return (f'<div class="card" style="--c:{col}"><div class="card-body"><div class="card-top">'
            f'<span class="mono">{c["id"]} &nbsp;|&nbsp; cross-IP correlation</span>'
            f'{sev_badge(c["severity"])}</div>'
            f'<div class="card-title">Distributed credential attack from {len(c["ips"])} source IPs</div>'
            f'<div class="meta"><span>Countries <b>{html.escape(", ".join(c["countries"]))}</b></span>'
            f'<span>Failed logins <b>{c["failures"]}</b></span>'
            f'<span>Accounts targeted <b>{len(c["accounts"])}</b></span>'
            f'<span>First seen <b>{c["start"]:%d %b %H:%M}</b></span></div>'
            f'<div class="card-text">{html.escape(c["summary"])}</div></div>'
            f'<div class="ringbox"><div class="ring" style="--c:{col};--p:100"><i>{len(c["ips"])}</i></div>'
            f'<div class="ringlabel">source IPs</div></div></div>')


def banner(incidents, active, campaigns, travel):
    """Status line built only from the detection results."""
    if incidents:
        top = max(incidents, key=lambda i: i.score)
        color = SEV_COLOR[top.severity]
        label = "Attention required" if active else "All incidents resolved"
        text = (f"{len(active)} open incident(s) of {len(incidents)}. Highest risk: {top.id} from "
                f"{top.ip} (risk {top.score}/100, {top.severity}).")
    else:
        color, label = "#3DDC84", "No incident above threshold"
        text = "No source IP reached the incident threshold in this view."
    if campaigns:
        text += f" {len(campaigns)} cross-IP campaign(s) found."
    if travel:
        text += f" {len(travel)} impossible-travel lead(s) to verify."
    return (f'<div class="banner" style="--c:{color}"><div class="bl">{html.escape(label)}</div>'
            f'<div class="bt">{html.escape(text)}</div></div>')


def style(fig, h=300):
    fig.update_layout(height=h, margin=dict(l=6, r=6, t=22, b=6), paper_bgcolor="rgba(0,0,0,0)",
                      plot_bgcolor="rgba(0,0,0,0)", font=dict(color=TEXT, size=12), title_font_size=13,
                      title_x=0, legend=dict(orientation="h", y=-0.2, title_text=""),
                      hoverlabel=dict(bgcolor="#182740", bordercolor="#34476A", font_color=TEXT),
                      colorway=["#4DA3FF", "#FF9248", "#3DDC84", "#F5C451", "#B794F6"])
    fig.update_xaxes(gridcolor=GRID, zerolinecolor=GRID, linecolor=LINE)
    fig.update_yaxes(gridcolor=GRID, zerolinecolor=GRID, linecolor=LINE)
    return fig


def dur(td):
    s = int(td.total_seconds())
    return f"{s // 3600}h {s % 3600 // 60}m" if s >= 3600 else f"{s // 60}m {s % 60}s"


def apply_scenario(df, name):
    """Demo views are derived from the real log and then run through the real pipeline."""
    if name == SCENARIOS[0]:
        return df
    ips = analyze(df)[1]
    if ips.empty:
        return df
    attacker = ips.iloc[0].ip
    if name == SCENARIOS[2]:
        return df[df.ip != attacker]
    return df[(df.ip != attacker) | (df.event == "login_failed")]


def summary_text(inc, df):
    """Plain-language summary built only from log values and detections. Hedged wording."""
    ipdf = df[df.ip == inc.ip]
    fails = ipdf[ipdf.event == "login_failed"]
    by = {a["rule"]: a for a in inc.timeline}
    text = f"Between {inc.start:%d %b %H:%M} and {inc.end:%H:%M}, `{inc.ip}` ({ipdf.country.iloc[0]}) "
    if len(fails):
        text += f"produced {len(fails)} failed logins against {fails.user.nunique()} account(s)."
    else:
        text += "showed suspicious activity."
    if "success_after_bf" in by:
        text += f" The same IP then logged in as `{inc.user}`, so that account may be compromised."
    later = [RULE_INFO[r][0] for r in ("priv_esc", "sensitive_access", "data_exfil", "log_tamper") if r in by]
    if later:
        text += " Afterwards it shows: " + ", ".join(later) + "."
    return text + f" Risk {inc.score}/100, confidence {inc.confidence}."


def impact_table(inc, df):
    """Impact facts, all computed from the attacker IP's log rows."""
    ipdf = df[df.ip == inc.ip]
    fails = ipdf[ipdf.event == "login_failed"]
    by = {a["rule"]: a for a in inc.timeline}
    to_login = "n/a"
    if "success_after_bf" in by and len(fails):
        to_login = dur(by["success_after_bf"]["time"] - fails.timestamp.min())
    mb = ipdf[ipdf.event == "file_download"].bytes.sum() / 1048576
    rows = [("Accounts with failed logins", fails.user.nunique()),
            ("Accounts logged into", ipdf[ipdf.event == "login_success"].user.nunique()),
            ("First failure to successful login", to_login),
            ("Activity span", dur(inc.end - inc.start)),
            ("Data downloaded", f"{mb:,.0f} MB"),
            ("Privilege change observed", "yes" if "priv_esc" in by else "no"),
            ("Log clearing observed", "yes" if "log_tamper" in by else "no")]
    return pd.DataFrame([(k, str(v)) for k, v in rows], columns=["Measure", "Value"])


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
    for name, n in u.value_counts().items():
        src.append(node(("ip", ip), ip, "#FF5C5C"))
        tgt.append(node(("u", name), name, "#4DA3FF"))
        val.append(int(n))
    for (name, ev), n in sub.assign(u=u).groupby(["u", "event"]).size().items():
        src.append(node(("u", name), name, "#4DA3FF"))
        tgt.append(node(("e", ev), ev, EVENT_COLOR.get(ev, MUTED)))
        val.append(int(n))
    act = sub[sub.event.isin(["file_download", "privilege_change", "log_cleared"])]
    top = act.resource.value_counts().index[:6]
    for (ev, res), n in act.assign(res=act.resource.where(act.resource.isin(top), "other resources")) \
            .groupby(["event", "res"]).size().items():
        src.append(node(("e", ev), ev, EVENT_COLOR.get(ev, MUTED)))
        tgt.append(node(("r", ev, res), res or "(none)", "#5A6B85"))
        val.append(int(n))
    fig = go.Figure(go.Sankey(node=dict(label=labels, color=colors, pad=16, thickness=16),
                              link=dict(source=src, target=tgt, value=val, color="rgba(139,155,176,.25)")))
    return style(fig, 440)


# ------------------------------------------------------------------ sidebar and data
dp = default_params()
PKEYS = {"p_brute": dp.brute_threshold, "p_spray": dp.spray_users, "p_inc": dp.incident_threshold,
         "p_exfil": dp.exfil_mb}
for k, v in PKEYS.items():
    st.session_state.setdefault(k, v)


def reset_params():
    for k, v in PKEYS.items():
        st.session_state[k] = v


with st.sidebar:
    side_label("Log source", first=True)
    src_name = st.selectbox("Log source", list(SAMPLES), label_visibility="collapsed")
    with st.expander("Upload a log (CSV)"):
        up = st.file_uploader("Log file", type=["csv"], label_visibility="collapsed")
        st.caption("Columns: timestamp, user, ip, country, event, resource, bytes")
    if st.button("Regenerate selected sample"):
        import generate_logs
        generate_logs.main(SAMPLES[src_name], extended=(SAMPLES[src_name] == MULTI))
    side_label("Scenario view")
    scenario = st.selectbox("Scenario view", SCENARIOS, label_visibility="collapsed")
    side_label("Detection thresholds")
    st.caption("Changing a value re-runs the detection pipeline on the loaded log.")
    st.slider("Brute force: failed logins on one account", 3, 30, key="p_brute")
    st.slider("Password spray: distinct accounts from one IP", 2, 15, key="p_spray")
    st.slider("Data exfiltration: MB per user per hour", 10, 1000, step=10, key="p_exfil")
    st.slider("Incident threshold (risk score)", 30, 100, key="p_inc")
    st.button("Reset to defaults", on_click=reset_params)

try:
    if up is not None:
        df = load_logs(up)
        source_label = up.name
    else:
        path = SAMPLES[src_name]
        if not os.path.exists(path):
            import generate_logs
            generate_logs.main(path, extended=(path == MULTI))
        df = load_logs(path)
        source_label = src_name
except Exception as e:
    st.error(f"Could not read the log file: {e}. Required columns: timestamp, user, ip, country, event, "
             f"resource, bytes.")
    st.stop()

meta = {k: df.attrs.get(k, 0) for k in ("total_rows", "dropped_rows", "duplicate_rows")}
df = apply_scenario(df, scenario)
if df.empty:
    st.warning("No events left in this view.")
    st.stop()

params = Params(brute_threshold=st.session_state.p_brute, spray_users=st.session_state.p_spray,
                exfil_mb=st.session_state.p_exfil, incident_threshold=st.session_state.p_inc,
                brute_window_min=dp.brute_window_min, spray_window_min=dp.spray_window_min,
                unseen_min_history=dp.unseen_min_history, unseen_max_prior_ips=dp.unseen_max_prior_ips)


@st.cache_data(show_spinner=False)
def run_pipeline(data, p):
    """Detection + correlation, cached so replay/notes/filter clicks do not re-run the whole analysis."""
    a, i, inc = analyze(data, p)
    return a, i, inc, find_campaigns(data, alerts=a), impossible_travel(data)


alerts, ips, incidents, campaigns, travel = run_pipeline(df, params)
for _inc in incidents:  # severity bands: >=90 critical, >=65 high, otherwise medium
    _inc.severity = "critical" if _inc.score >= 90 else "high" if _inc.score >= 65 else "medium"
flag_ips = set(ips.ip)

with st.sidebar:
    if params != dp:
        a0, _, i0 = analyze(df, dp)
        st.caption(f"Default thresholds would give {len(a0)} alerts and {len(i0)} incident(s); "
                   f"current settings give {len(alerts)} and {len(incidents)}.")
    side_label("Data quality")
    st.caption(f"Source: {source_label}  \n"
               f"Rows read: {meta['total_rows']:,}  \n"
               f"Malformed rows dropped: {meta['dropped_rows']}  \n"
               f"Duplicate rows (kept): {meta['duplicate_rows']}")
    st.caption("Rule-based detection. No machine learning.")
    if st.session_state.get("case_save_failed"):
        st.caption("Could not write data/case_state.json. Status and notes last only for this session.")

# ------------------------------------------------------------------ header
active = [i for i in incidents if status_of(i) != "resolved"]
top_sev = max((i.severity for i in active), key=SEV_ORDER.get, default="none")
susp_events = len({e for a in alerts for e in a["evidence"]})
dcol = SEV_COLOR.get(top_sev, "#3DDC84") if active else "#3DDC84"

st.markdown(
    '<div class="topbar"><div class="brandwrap"><div class="logo"></div>'
    '<div class="brand">Find the Intruder<small>SOC triage console for authentication and access logs</small>'
    '</div></div><div class="pills">'
    f'<div class="pill"><span class="dot" style="--d:{dcol}"></span>Analysis complete</div>'
    f'<div class="pill">Source <b>{html.escape(source_label)}</b></div>'
    f'<div class="pill">Window <b>{df.timestamp.min():%d %b %H:%M}</b> to <b>{df.timestamp.max():%d %b %H:%M}</b></div>'
    '</div></div>', unsafe_allow_html=True)
kpis([("Events", f"{len(df):,}", "#4DA3FF", "in the selected view"),
      ("Alerts", len(alerts), "#B794F6", f"{susp_events:,} events referenced"),
      ("Suspicious IPs", len(ips), "#F5C451", f"{len(incidents)} above threshold"),
      ("Open incidents", len(active), SEV_COLOR["high"] if active else NEUTRAL, f"{len(incidents) - len(active)} resolved"),
      ("Campaigns", len(campaigns), SEV_COLOR["medium"] if campaigns else NEUTRAL, "cross-IP"),
      ("Highest open severity", top_sev.upper(), SEV_COLOR.get(top_sev, NEUTRAL), "among open incidents")])

tabs = st.tabs(["📊 Overview", "🚨 Incidents", "▶️ Replay", "🔔 Alerts", "🔗 Correlation", "🔎 Investigate",
                "🌍 Geo & time", "📜 Log search", "🧭 Methodology"])

# ------------------------------------------------------------------ overview
with tabs[0]:
    tab_start()
    section_header("📊", "Overview", "Threat status, incident queue and activity at a glance")
    st.markdown(banner(incidents, active, campaigns, travel), unsafe_allow_html=True)

    with panel("Incident queue", "Source IPs whose risk score crossed the incident threshold"):
        if incidents:
            st.markdown("".join(incident_card(i) for i in incidents), unsafe_allow_html=True)
        else:
            st.info("No incident above the current threshold. Individual alerts, if any, are on the Alerts tab.")

    if campaigns:
        with panel("Cross-IP campaigns", "Several IPs working together; reported apart from the per-IP score"):
            st.markdown("".join(campaign_card(c) for c in campaigns), unsafe_allow_html=True)
            st.caption("Details are on the Correlation tab.")

    with panel("Event activity", "Volume over time and alert severity mix"):
        l, r = st.columns([2, 1])
        h = df.assign(hour=df.timestamp.dt.floor("h"),
                      source=df.ip.map(lambda x: "flagged IP" if x in flag_ips else "other IPs"))
        h = h.groupby(["hour", "source"]).size().reset_index(name="events")
        fig = px.bar(h, x="hour", y="events", color="source",
                     color_discrete_map={"other IPs": "#2B4C7E", "flagged IP": "#FF5C5C"})
        l.caption("Events per hour")
        l.plotly_chart(style(fig, 270), use_container_width=True, key="ov_hour")
        r.caption("Alerts by severity")
        if alerts:
            sc = pd.Series([a["severity"] for a in alerts]).value_counts()
            sc = sc.reindex([s for s in ("critical", "high", "medium", "low") if s in sc.index])
            fig = go.Figure(go.Pie(labels=[s.upper() for s in sc.index], values=sc.values, hole=0.62,
                                   marker=dict(colors=[SEV_COLOR[s] for s in sc.index],
                                               line=dict(color="#0F1620", width=2)),
                                   sort=False, textinfo="value"))
            r.plotly_chart(style(fig, 270), use_container_width=True, key="ov_sev")
        else:
            r.caption("No alerts.")

    with panel("Failed login analysis", "When failures happened and which accounts were hit"):
        l, r = st.columns(2)
        f = df[df.event == "login_failed"].assign(hour=lambda d: d.timestamp.dt.floor("h"))
        l.caption("Failed logins per hour")
        if len(f):
            f = f.groupby("hour").size().reset_index(name="failed logins")
            fig = px.bar(f, x="hour", y="failed logins")
            fig.update_traces(marker_color="#FF9248")
            l.plotly_chart(style(fig, 250), use_container_width=True, key="ov_fail")
        else:
            l.caption("No failed logins in this log.")
        r.caption("Most targeted accounts")
        tg = df[df.event == "login_failed"].user.value_counts().head(8).reset_index()
        if len(tg):
            tg.columns = ["account", "failed logins"]
            fig = px.bar(tg, x="failed logins", y="account", orientation="h")
            fig.update_traces(marker_color="#FF9248")
            fig.update_yaxes(autorange="reversed", title="")
            r.plotly_chart(style(fig, 250), use_container_width=True, key="ov_target")
        else:
            r.caption("No failed logins.")

    with panel("Detections by ATT&CK technique", "Number of alerts mapped to each technique"):
        if alerts:
            t = pd.Series([a["mitre"] for a in alerts]).value_counts().reset_index()
            t.columns = ["technique", "alerts"]
            fig = px.bar(t, x="alerts", y="technique", orientation="h")
            fig.update_traces(marker_color="#4DA3FF")
            fig.update_yaxes(autorange="reversed", title="")
            st.plotly_chart(style(fig, 60 + 32 * len(t)), use_container_width=True, key="ov_mitre")
        else:
            st.caption("No detections.")

    with panel("Suspicious sources", "Every source IP with at least one alert, ranked by risk"):
        if len(ips):
            st.dataframe(ips[["ip", "score", "level", "alerts", "users", "rules"]], hide_index=True,
                         use_container_width=True, column_config={
                             "score": st.column_config.ProgressColumn("risk", min_value=0, max_value=100,
                                                                      format="%d")})
            ioc = ips[ips.score >= params.incident_threshold][["ip", "score", "level", "rules", "users"]]
            st.download_button("Export blocklist candidates (.csv)", ioc.to_csv(index=False),
                               file_name="ioc_blocklist.csv", disabled=ioc.empty)
            st.caption("Blocklist candidates are IPs at or above the incident threshold.")
        else:
            st.caption("No suspicious IPs.")

# ------------------------------------------------------------------ incidents
with tabs[1]:
    tab_start()
    section_header("🚨", "Incidents", "Summary, attack chain, timeline, evidence and response for one incident")
    if not incidents:
        st.info("No correlated incident in this log.")
    else:
        n_sel = 0
        if len(incidents) > 1:
            n_sel = st.selectbox("Incident", range(len(incidents)),
                                 format_func=lambda n: f"{incidents[n].id}  {incidents[n].ip}  risk {incidents[n].score}")
        inc = incidents[n_sel]

        head, stat = st.columns([5, 1])
        head.markdown(incident_card(inc, hero=True), unsafe_allow_html=True)
        stat.selectbox("Status", STATUSES, index=STATUSES.index(status_of(inc)), key=f"status_{inc.ip}",
                       on_change=on_status, args=(inc.ip,))

        with panel("Summary", "Plain-language description built from the log values"):
            st.markdown(summary_text(inc, df))

        o, i_ = st.columns(2)
        with o:
            with panel("Observed in the log", "Facts taken directly from the data"):
                st.markdown("\n".join(f"- {x}" for x in inc.observed))
        with i_:
            with panel("Inferred sequence", "Interpretation, not proof"):
                st.markdown(inc.story)

        with panel("Attack chain and ATT&CK techniques", "Kill-chain stages seen from this IP are highlighted"):
            st.markdown(kill_chain({a["stage"] for a in inc.timeline}), unsafe_allow_html=True)
            st.markdown(technique_links([(t["id"], t["name"]) for t in inc.mitre]), unsafe_allow_html=True)
            st.caption("ATT&CK mapping is best-fit: the log shows what happened, not the attacker's tooling.")

        l, r = st.columns(2)
        with l:
            with panel("Incident timeline", "Detections in the order they happened"):
                st.markdown(timeline_html(inc.timeline), unsafe_allow_html=True)
        with r:
            with panel("Risk score breakdown", "Points added by each rule"):
                pts = [(x.split(" ", 1)[0], x.split(" ", 1)[1]) for x in inc.reasons if x.startswith("+")]
                if pts:
                    fig = px.bar(x=[int(p[0]) for p in pts], y=[p[1] for p in pts], orientation="h")
                    fig.update_traces(marker_color=SEV_COLOR[inc.severity])
                    fig.update_yaxes(autorange="reversed", title="")
                    fig.update_xaxes(title="points")
                    st.plotly_chart(style(fig, 60 + 36 * len(pts)), use_container_width=True,
                                    key=f"w_{inc.id}")
                for x in inc.reasons:
                    if not x.startswith("+"):
                        st.caption(x)
            with panel("Impact", "Measured from this IP's log rows"):
                st.dataframe(impact_table(inc, df), hide_index=True, use_container_width=True)

        with panel("Evidence", "The exact log rows behind this incident, with the reason each was included"):
            hide_fail = st.checkbox("Hide failed logins", key=f"hf_{inc.id}")
            ev = inc.evidence[["timestamp", "user", "event", "resource", "bytes", "why"]]
            st.dataframe(ev[ev.event != "login_failed"] if hide_fail else ev, hide_index=True,
                         use_container_width=True)

        with panel("Recommended actions", "Containment and follow-up steps"):
            st.markdown("\n".join(f"- {x}" for x in inc.recommendations))

        with panel("Analyst notes", "Saved to data/case_state.json and added to the report"):
            st.text_area("Notes", value=CASES.get(inc.ip, {}).get("notes", ""), key=f"notes_{inc.ip}",
                         on_change=on_notes, args=(inc.ip,), height=110, label_visibility="collapsed")

        with panel("Export", "Report, structured incident and raw evidence"):
            report = incident_to_markdown(inc, status_of(inc))
            notes = CASES.get(inc.ip, {}).get("notes", "").strip()
            if notes:
                report += "\n\n## Analyst notes\n" + notes
            d1, d2, d3 = st.columns(3)
            d1.download_button("Report (.md)", report, file_name=f"{inc.id}.md", key=f"dlm_{inc.id}",
                               use_container_width=True)
            d2.download_button("Incident (.json)", json.dumps(incident_to_dict(inc, status_of(inc)), indent=2),
                               file_name=f"{inc.id}.json", key=f"dlj_{inc.id}", use_container_width=True)
            d3.download_button("Evidence (.csv)", inc.evidence.to_csv(index_label="row"),
                               file_name=f"{inc.id}_evidence.csv", key=f"dlc_{inc.id}",
                               use_container_width=True)

# ------------------------------------------------------------------ replay
with tabs[2]:
    tab_start()
    section_header("▶️", "Replay", "Watch the attack unfold and the risk score build up")
    cand = list(dict.fromkeys([i.ip for i in incidents] + list(ips.ip)))
    if not cand:
        st.info("No suspicious IP in this log, so there is nothing to replay.")
    else:
        with panel("Attack replay", "Step through one source IP's events and watch the risk score build"):
            st.caption("The score uses the same rules as the incident score: each rule counts once, plus the "
                       "multi-stage bonus. An alert is stamped at the first event of its pattern.")
            who = st.selectbox("Source IP", cand, key="rp_ip")
            sub = df[df.ip == who].sort_values("timestamp", kind="stable")
            N = len(sub)
            tl = score_timeline(alerts, who)
            c1, c2, c3 = st.columns([5, 1.4, 1])
            pos = c1.slider("Position (event number)", 1, N, N, key=f"rp_pos_{who}") if N > 1 else 1
            speed = c2.selectbox("Speed", list(SPEEDS), index=1)
            c3.write("")
            play = c3.button("Play", use_container_width=True)

        def draw(n, key):
            tab_start()
            _N["i"] = 1
            cur = sub.timestamp.iloc[n - 1]
            done = tl[tl.time <= cur]
            score = int(done.score.iloc[-1]) if len(done) else 0
            seen = sub.iloc[:n]
            kpis([("Time", f"{cur:%H:%M:%S}", "#4DA3FF"), ("Events", f"{n} / {N}", "#B794F6"),
                  ("Failed logins", int((seen.event == "login_failed").sum()), "#FF9248"),
                  ("Risk score", f"{score} / 100", SEV_COLOR["critical"] if score >= 70 else "#4DA3FF"),
                  ("Downloaded", f"{seen.bytes.sum() / 1048576:,.0f} MB", "#3DDC84")])
            with panel("Stages and techniques reached so far"):
                st.markdown(kill_chain(set(done.stage)), unsafe_allow_html=True)
                techs = {a["mitre_id"]: a["mitre_name"] for a in alerts
                         if a["ip"] == who and a["time"] <= cur}
                st.markdown(technique_links(list(techs.items())) if techs else
                            f'<span style="color:{MUTED}">No ATT&CK technique matched yet.</span>',
                            unsafe_allow_html=True)
            l, r = st.columns([3, 2])
            with l:
                with panel("Risk score over time", "Dotted line marks the replay position"):
                    if len(tl):
                        fig = go.Figure(go.Scatter(x=tl.time, y=tl.score, mode="lines+markers",
                                                   line_shape="hv", line=dict(color="#FF5C5C", width=2)))
                        fig.add_shape(type="line", x0=cur, x1=cur, y0=0, y1=1, yref="paper",
                                      line=dict(color="#4DA3FF", width=1.5, dash="dot"))
                        fig.update_yaxes(range=[0, 105], title="risk score")
                        st.plotly_chart(style(fig, 260), use_container_width=True, key=f"rp_c_{key}")
            with r:
                with panel("Detections so far"):
                    if len(done):
                        shown = done[["time", "label", "points", "score"]].rename(
                            columns={"time": "Time", "label": "Detection", "points": "Points",
                                     "score": "Score"})
                        st.dataframe(shown.iloc[::-1], hide_index=True, use_container_width=True,
                                     column_config={"Time": st.column_config.DatetimeColumn(
                                         "Time", format="HH:mm:ss")})
                    else:
                        st.caption("No detection fired yet.")

        if play and N > 1:
            frames = sorted({round(1 + i * (N - 1) / (min(N, 40) - 1)) for i in range(min(N, 40))})
            slot = st.empty()
            for f_ in frames:
                with slot.container():
                    draw(f_, f"p{f_}")
                time.sleep(SPEEDS[speed])
        else:
            draw(pos, "s")

# ------------------------------------------------------------------ alerts
with tabs[3]:
    tab_start()
    section_header("🔔", "Alerts", "Every detection with its ATT&CK technique and evidence")
    with panel("Alert queue", "Filter by severity, technique, confidence or free text"):
        f1, f2, f3, f4 = st.columns([2, 3, 2, 3])
        sev = f1.multiselect("Severity", list(SEV_ORDER), default=list(SEV_ORDER))
        techs_all = sorted({a["mitre"] for a in alerts})
        tech = f2.multiselect("ATT&CK technique", techs_all, default=techs_all)
        conf = f3.multiselect("Confidence", ["high", "medium", "low"], default=["high", "medium", "low"])
        q = f4.text_input("Search IP, user or text")
        rows = [a for a in alerts if a["severity"] in sev and a["mitre"] in tech and a["confidence"] in conf
                and (not q or q.lower() in f"{a['ip']} {a['user']} {a['detail']}".lower())]
        st.caption(f"{len(rows)} of {len(alerts)} alerts")
        if rows:
            st.dataframe(pd.DataFrame(rows)[["id", "time", "severity", "confidence", "stage", "mitre", "ip",
                                             "user", "detail"]], hide_index=True, use_container_width=True)
        else:
            st.info("No alerts match the filters.")
    if rows:
        with panel("Alert detail", "Why the alert fired and the log rows it is based on"):
            a = next(x for x in rows if x["id"] == st.selectbox("Alert", [x["id"] for x in rows]))
            st.markdown(f"{sev_badge(a['severity'])} &nbsp; "
                        f"{technique_links([(a['mitre_id'], a['mitre_name'])])} "
                        f"&nbsp; tactic: {html.escape(a['mitre_tactic'])}", unsafe_allow_html=True)
            st.markdown(f"**Why it matters:** {a['reason']}")
            st.caption("Evidence rows")
            st.dataframe(df.loc[[i for i in a["evidence"] if i in df.index]], hide_index=True,
                         use_container_width=True)

# ------------------------------------------------------------------ correlation
with tabs[4]:
    tab_start()
    section_header("🔗", "Correlation", "Cross-IP campaigns and impossible travel")
    with panel("Distributed credential attacks", "Source IPs that fail against the same accounts at the same time"):
        st.caption("IPs are linked when they fail logins against at least 2 of the same accounts within "
                   "30 minutes of each other. A campaign needs at least 3 linked IPs.")
        if not campaigns:
            st.info("No cross-IP campaign found in this log.")
    for c in campaigns:
        with panel(f"{c['id']}  |  {len(c['ips'])} source IPs", ", ".join(c["countries"])):
            st.markdown(campaign_card(c), unsafe_allow_html=True)
            m = pd.DataFrame(c["members"]).rename(columns={
                "ip": "Source IP", "country": "Country", "failures": "Failed logins", "accounts": "Accounts",
                "first": "First", "last": "Last", "own_alert": "Own brute force/spray alert"})
            st.dataframe(m, hide_index=True, use_container_width=True, column_config={
                "First": st.column_config.DatetimeColumn("First", format="DD MMM, HH:mm:ss"),
                "Last": st.column_config.DatetimeColumn("Last", format="DD MMM, HH:mm:ss")})
            st.caption("Accounts targeted from more than one IP: " + (", ".join(c["common"]) or "none"))
            hits = [s for s in c["successes"] if s["targeted"]]
            if hits:
                st.caption("Successful logins from campaign IPs on targeted accounts")
                st.dataframe(pd.DataFrame(hits)[["time", "ip", "user"]], hide_index=True,
                             use_container_width=True,
                             column_config={"time": st.column_config.DatetimeColumn(
                                 "time", format="DD MMM, HH:mm:ss")})
            with st.expander(f"Evidence rows for {c['id']} ({len(c['evidence'])})"):
                st.dataframe(df.loc[[i for i in c["evidence"] if i in df.index]], hide_index=True,
                             use_container_width=True)

    with panel("Impossible travel", "Same account, two countries, within 2 hours"):
        st.caption("Based on the country field of the log only, so a VPN or a shared account can also cause "
                   "this. Treat each row as a lead to verify.")
        if travel:
            st.dataframe(pd.DataFrame(travel)[["user", "from_country", "from_ip", "from_time", "to_country",
                                               "to_ip", "to_time", "gap_min"]], hide_index=True,
                         use_container_width=True, column_config={
                             "from_time": st.column_config.DatetimeColumn("from_time", format="DD MMM, HH:mm"),
                             "to_time": st.column_config.DatetimeColumn("to_time", format="DD MMM, HH:mm"),
                             "gap_min": st.column_config.NumberColumn("gap (min)")})
        else:
            st.info("No impossible travel found.")

# ------------------------------------------------------------------ investigate
with tabs[5]:
    tab_start()
    section_header("🔎", "Investigate", "Everything the log holds on one IP or account")
    with panel("Investigate an entity", "Pick a source IP or an account to see everything the log holds on it"):
        mode = st.radio("Investigate by", ["IP address", "User"], horizontal=True)
        if mode == "IP address":
            who_i = st.selectbox("IP address", (list(ips.ip) + sorted(set(df.ip) - flag_ips))[:300])
            sub_i = df[df.ip == who_i]
            rel = [a for a in alerts if a["ip"] == who_i]
        else:
            who_i = st.selectbox("User", list(dict.fromkeys([a["user"] for a in alerts]
                                                            + sorted(set(df.user)))))
            sub_i = df[df.user == who_i]
            rel = [a for a in alerts if a["user"] == who_i]
    kpis([("Events", len(sub_i), "#4DA3FF"), ("Failed logins", int((sub_i.event == "login_failed").sum()), "#FF9248"),
          ("Successful logins", int((sub_i.event == "login_success").sum()), "#3DDC84"),
          ("Downloaded", f"{sub_i.bytes.sum() / 1048576:,.0f} MB", "#B794F6"), ("Alerts", len(rel), "#FF5C5C")])
    if len(sub_i):
        with panel("Event timeline", f"Countries: {', '.join(sorted(set(sub_i.country)))}  |  "
                                      f"IPs: {sub_i.ip.nunique()}  |  Users: {sub_i.user.nunique()}  |  "
                                      f"{sub_i.timestamp.min():%d %b %H:%M} to {sub_i.timestamp.max():%d %b %H:%M}"):
            fig = px.scatter(sub_i, x="timestamp", y="event", color="event", color_discrete_map=EVENT_COLOR)
            st.plotly_chart(style(fig, 240), use_container_width=True, key="inv_tl")
        if mode == "IP address":
            with panel("Activity flow", "Source IP to accounts to actions to resources; width is event count"):
                st.plotly_chart(sankey(sub_i), use_container_width=True, key="flow")
    if rel:
        with panel("Alerts for this entity"):
            st.dataframe(pd.DataFrame(rel)[["id", "time", "severity", "mitre", "detail"]], hide_index=True,
                         use_container_width=True)
    with panel("Raw events", "Last 500 rows"):
        st.dataframe(sub_i.tail(500), hide_index=True, use_container_width=True)

# ------------------------------------------------------------------ geo and time
with tabs[6]:
    tab_start()
    section_header("🌍", "Geo & time", "Where and when the failed logins happened")
    cs = df.groupby("country").agg(events=("event", "size"),
                                   failed=("event", lambda s: int((s == "login_failed").sum())),
                                   success=("event", lambda s: int((s == "login_success").sum()))).reset_index()
    cs["iso"] = cs.country.map(lambda x: x if len(x) == 3 else ISO3.get(x.upper()))
    mapped = cs.dropna(subset=["iso"])
    with panel("Failed logins by country", "Country is the value recorded in the log; no IP geolocation lookup"):
        l, r = st.columns([3, 2])
        with l:
            if len(mapped):
                fig = px.choropleth(mapped, locations="iso", color="failed", hover_name="country",
                                    hover_data={"iso": False, "events": True, "success": True, "failed": True},
                                    color_continuous_scale=[[0, "#1A2433"], [1, "#FF5C5C"]])
                fig.update_geos(bgcolor="rgba(0,0,0,0)", landcolor="#141D2A", showcountries=True,
                                countrycolor="#2B3A52", showframe=False, projection_type="natural earth",
                                showocean=True, oceancolor="#070B11", lakecolor="#070B11")
                fig.update_layout(coloraxis_colorbar=dict(title="failed"))
                st.plotly_chart(style(fig, 380), use_container_width=True, key="geo")
            else:
                st.info("Country codes in this log could not be placed on the map. See the table.")
            if len(cs) > len(mapped):
                st.caption("Not on the map (unknown code): " + ", ".join(cs[cs.iso.isna()].country))
        r.dataframe(cs.drop(columns="iso").sort_values("failed", ascending=False), hide_index=True,
                    use_container_width=True)

    with panel("Failed logins by hour and date", "Dark cells are quiet hours; bright red marks bursts"):
        fl = df[df.event == "login_failed"]
        if fl.empty:
            st.info("No failed logins in this log.")
        else:
            pv = fl.assign(day=fl.timestamp.dt.strftime("%Y-%m-%d"), hr=fl.timestamp.dt.hour) \
                .pivot_table(index="hr", columns="day", values="event", aggfunc="size", fill_value=0) \
                .reindex(range(24), fill_value=0)
            days = sorted(pv.columns)
            fig = go.Figure(go.Heatmap(z=pv[days].values, x=days, y=list(pv.index),
                                       colorscale=[[0, "#141D2A"], [1, "#FF5C5C"]],
                                       colorbar=dict(title="failed")))
            fig.update_yaxes(title="hour of day", dtick=2, autorange="reversed")
            fig.update_xaxes(title="date", type="category")
            st.plotly_chart(style(fig, 380), use_container_width=True, key="heat")

# ------------------------------------------------------------------ log search
with tabs[7]:
    tab_start()
    section_header("📜", "Log search", "Filter and export the raw events")
    with panel("Filters", "Narrow the raw log by event, country, user, IP and date"):
        e1, e2, e3 = st.columns(3)
        ev_sel = e1.multiselect("Event type", sorted(df.event.unique()), default=sorted(df.event.unique()))
        co_sel = e2.multiselect("Country", sorted(df.country.unique()), default=sorted(df.country.unique()))
        only_flag = e3.checkbox("Flagged IPs only")
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
    with panel("Results", f"{len(v):,} of {len(df):,} events (first 1,000 shown)"):
        st.dataframe(v.head(1000), hide_index=True, use_container_width=True)
        st.download_button("Export filtered events (.csv)", v.to_csv(index=False),
                           file_name="filtered_events.csv")

# ------------------------------------------------------------------ methodology
with tabs[8]:
    tab_start()
    section_header("🧭", "Methodology", "Rules, scoring and known limits")
    thr = {"brute_force": f">= {params.brute_threshold} failures on one account in {params.brute_window_min} min",
           "password_spray": f">= {params.spray_users} accounts from one IP in {params.spray_window_min} min",
           "success_after_bf": "successful login from an IP that showed an attack pattern",
           "new_geo": "successful login from a country that is not the user's usual one",
           "unseen_ip": f"new IP in the user's usual country; user has >= {params.unseen_min_history} earlier "
                        f"logins and <= {params.unseen_max_prior_ips} earlier IPs",
           "off_hours": "00:00-05:00 activity for a user who is normally never active then",
           "priv_esc": "any privilege_change event",
           "sensitive_access": "download of finance, HR, secrets, database or backup style paths",
           "data_exfil": f">= {params.exfil_mb} MB downloaded by one user in an hour",
           "log_tamper": "any log_cleared event"}
    with panel("Detection rules", "Current thresholds reflect the sidebar sliders"):
        st.dataframe(pd.DataFrame([{"Rule": k, "Detects": RULE_INFO[k][0], "Trigger": thr[k],
                                    "Stage": RULES[k][2], "Severity": RULES[k][1], "Points": RULES[k][0],
                                    "ATT&CK": f"{MITRE[k][0]} {MITRE[k][1]}"} for k in RULES]),
                     hide_index=True, use_container_width=True)
    with panel("Risk score", "How a number between 0 and 100 is produced"):
        st.markdown(f"""
The score is per source IP. Each distinct rule that fired adds its points once. Ten more points are added when
three or more kill-chain stages appear from the same IP, and the total is capped at 100. An IP becomes an
incident at {params.incident_threshold} points or more. The anomaly rules (unusual country, unseen IP,
off-hours) are worth 10 points each, so anomalies alone never reach the threshold. Every point is listed with
its reason on the incident page.
""")
    with panel("Cross-IP correlation", "Two checks that run outside the per-IP score"):
        st.markdown("""
**Campaign detection** links source IPs that failed logins against at least 2 of the same accounts within
30 minutes of each other, and reports a campaign when 3 or more IPs are linked. It exists because an attacker
can keep every IP under the per-IP thresholds. **Impossible travel** lists successful logins by one account
from two different countries within 2 hours. Both report the log rows they used. Their results are shown on
the Correlation tab and are not added to the risk score.
""")
    with panel("Limitations", "What this tool does not do"):
        st.markdown("""
- Thresholds are tuned for this log schema and volume. Other environments need re-tuning with the sliders.
- Not detected, because this data does not support it: credential stuffing and reconnaissance or scanning.
- Country comes from the log's own country field. There is no IP geolocation lookup and no distance calculation.
- ATT&CK mapping is best-fit. A log shows what happened, not the attacker's exact tooling or channel.
- Incidents are built per source IP. Attacks spread over several IPs are reported as campaigns, but a campaign
  does not raise the score of its member IPs.
- Campaign linking compares every pair of IPs that failed on 2 or more accounts, which is fine for one log
  file but would need indexing for very large logs.
- Analysis runs in memory on one file. It is not a streaming system.
- The attack story is an interpretation of correlated events, not proof.
""")