"""Detection engine: rules -> alerts -> per-IP risk score -> incident timeline + story."""
from dataclasses import dataclass

import pandas as pd

REQUIRED_COLS = ["timestamp", "user", "ip", "country", "event", "resource", "bytes"]

# rule -> (weight, severity, kill-chain stage)
RULES = {
    "brute_force":      (40, "high",     "Initial Access"),
    "success_after_bf": (30, "critical", "Credential Access"),
    "new_geo":          (10, "low",      "Anomaly"),
    "off_hours":        (10, "medium",   "Anomaly"),
    "priv_esc":         (20, "critical", "Privilege Escalation"),
    "data_exfil":       (25, "critical", "Exfiltration"),
    "log_tamper":       (15, "critical", "Defense Evasion"),
}
SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
INCIDENT_THRESHOLD = 70


def load_logs(src) -> pd.DataFrame:
    df = pd.read_csv(src)
    missing = [c for c in REQUIRED_COLS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns: {', '.join(missing)}")
    if df.empty:
        raise ValueError("Log file is empty")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    df["resource"] = df["resource"].fillna("")
    df["bytes"] = pd.to_numeric(df["bytes"], errors="coerce").fillna(0).astype(int)
    return df.sort_values("timestamp").reset_index(drop=True)


def _alert(rule, ip, user, time, detail, n=1):
    w, sev, stage = RULES[rule]
    return {"rule": rule, "severity": sev, "stage": stage, "ip": ip, "user": user,
            "time": time, "detail": detail, "weight": w, "count": n}


def _fmt_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def detect(df: pd.DataFrame) -> list[dict]:
    alerts = []

    # --- brute force / password spray: >=10 failures from one IP inside 10 minutes
    fails = df[df.event == "login_failed"]
    bf_ips = {}
    for ip, g in fails.groupby("ip"):
        s = g.set_index("timestamp").sort_index()["user"]
        roll = s.rolling("10min").count()
        if roll.max() >= 10:
            first = roll[roll >= 10].index[0]
            start = g.timestamp.min()
            users = g.user.nunique()
            kind = "password spray" if users >= 3 else "brute force"
            bf_ips[ip] = start
            alerts.append(_alert("brute_force", ip, g.user.mode()[0], start,
                                 f"{len(g)} failed logins from {ip} against {users} account(s) "
                                 f"({kind}); threshold hit at {first:%H:%M:%S}", len(g)))

    # --- successful login right after brute force
    succ = df[df.event == "login_success"]
    compromised = {}
    for ip, start in bf_ips.items():
        hit = succ[(succ.ip == ip) & (succ.timestamp >= start)]
        if not hit.empty:
            r = hit.iloc[0]
            compromised[ip] = r.user
            alerts.append(_alert("success_after_bf", ip, r.user, r.timestamp,
                                 f"Account '{r.user}' logged in successfully from {ip} "
                                 f"after the failed attempts - likely compromised"))

    # --- login from a country that is not the user's usual one
    usual = succ.groupby("user")["country"].agg(lambda s: s.mode()[0])
    for (user, ip, country), g in succ.groupby(["user", "ip", "country"]):
        if user in usual and country != usual[user]:
            alerts.append(_alert("new_geo", ip, user, g.timestamp.min(),
                                 f"'{user}' logged in from {country} (usually {usual[user]})", len(g)))

    # --- off-hours (00:00-05:00) activity for users who normally never do that
    off = df.timestamp.dt.hour < 5
    base = df.event.isin(["login_success", "file_download"])  # baseline ignores failed-login noise
    off_share = off[base].groupby(df.user[base]).mean()
    for (user, ip), g in df[off & df.event.isin(["login_success", "file_download",
                                                    "privilege_change", "log_cleared"])].groupby(["user", "ip"]):
        if off_share.get(user, 0) < 0.05:
            alerts.append(_alert("off_hours", ip, user, g.timestamp.min(),
                                 f"{len(g)} off-hours event(s) for '{user}' (normally active 09-19h)", len(g)))

    # --- privilege change / log clearing
    for _, r in df[df.event == "privilege_change"].iterrows():
        alerts.append(_alert("priv_esc", r.ip, r.user, r.timestamp,
                             f"Privilege change by '{r.user}': {r.resource}"))
    for _, r in df[df.event == "log_cleared"].iterrows():
        alerts.append(_alert("log_tamper", r.ip, r.user, r.timestamp,
                             f"Log file cleared by '{r.user}': {r.resource}"))

    # --- data exfiltration: >=200 MB downloaded by one user/IP within an hour
    dl = df[df.event == "file_download"].copy()
    dl["hour"] = dl.timestamp.dt.floor("h")
    for (user, ip, hour), g in dl.groupby(["user", "ip", "hour"]):
        total = g.bytes.sum()
        if total >= 200 * 1024 * 1024:
            big = g.sort_values("bytes", ascending=False).iloc[0]
            alerts.append(_alert("data_exfil", ip, user, g.timestamp.min(),
                                 f"'{user}' downloaded {_fmt_bytes(total)} in {len(g)} files "
                                 f"(largest: {big.resource})", len(g)))

    return sorted(alerts, key=lambda a: a["time"])


def score_ips(alerts: list[dict]) -> pd.DataFrame:
    rows = {}
    for a in alerts:
        r = rows.setdefault(a["ip"], {"ip": a["ip"], "rules": set(), "score": 0, "alerts": 0, "users": set()})
        if a["rule"] not in r["rules"]:
            r["score"] += a["weight"]
            r["rules"].add(a["rule"])
        r["alerts"] += 1
        r["users"].add(a["user"])
    out = pd.DataFrame([{**r, "score": min(100, r["score"]),
                         "rules": ", ".join(sorted(r["rules"])),
                         "users": ", ".join(sorted(r["users"]))} for r in rows.values()])
    if out.empty:
        return pd.DataFrame(columns=["ip", "score", "level", "alerts", "rules", "users"])
    out["level"] = pd.cut(out.score, [-1, 39, 69, 100], labels=["low", "high", "critical"]).astype(str)
    return out.sort_values("score", ascending=False).reset_index(drop=True)


@dataclass
class Incident:
    ip: str
    score: int
    start: pd.Timestamp
    end: pd.Timestamp
    user: str
    timeline: list
    story: str


def build_incidents(df, alerts, ip_scores) -> list[Incident]:
    incidents = []
    for _, row in ip_scores[ip_scores.score >= INCIDENT_THRESHOLD].iterrows():
        tl = [a for a in alerts if a["ip"] == row.ip and a["rule"] != "new_geo"]
        if not tl:
            continue
        victim = next((a["user"] for a in tl if a["rule"] == "success_after_bf"), tl[0]["user"])
        incidents.append(Incident(row.ip, int(row.score), tl[0]["time"], tl[-1]["time"],
                                  victim, tl, make_story(row.ip, victim, tl, df)))
    return incidents


def make_story(ip, victim, tl, df) -> str:
    country = df.loc[df.ip == ip, "country"].iloc[0]
    by = {a["rule"]: a for a in tl}
    parts = [f"At {tl[0]['time']:%H:%M} on {tl[0]['time']:%d %b}, {ip} ({country}) began attacking the login service"]
    if "brute_force" in by:
        parts[0] += f" with {by['brute_force']['count']} failed attempts."
    else:
        parts[0] += "."
    if "success_after_bf" in by:
        parts.append(f"It then logged in as '{victim}' at {by['success_after_bf']['time']:%H:%M:%S}.")
    if "priv_esc" in by:
        parts.append("The attacker escalated privileges to superadmin.")
    if "data_exfil" in by:
        parts.append(by["data_exfil"]["detail"].replace(f"'{victim}' downloaded", "Sensitive data was exfiltrated:") + ".")
    if "log_tamper" in by:
        parts.append("Finally, logs were cleared to hide the trail.")
    parts.append("Recommended: block the IP, reset the account, rotate secrets, audit downloaded files.")
    return " ".join(parts)


def analyze(df):
    alerts = detect(df)
    ips = score_ips(alerts)
    return alerts, ips, build_incidents(df, alerts, ips)
