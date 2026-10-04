"""Detection engine: rules -> alerts -> per-IP risk score -> incident (timeline, evidence, story).

Everything here is rule-based and explainable: every alert carries the exact log rows
that triggered it, and every risk-score point is listed with the reason it was added.
No machine learning is used.
"""
import json
import re
from collections import Counter
from dataclasses import dataclass, field

import pandas as pd

REQUIRED_COLS = ["timestamp", "user", "ip", "country", "event", "resource", "bytes"]

# rule -> (weight, severity, kill-chain stage)
RULES = {
    "brute_force":      (40, "high",     "Initial Access"),
    "password_spray":   (25, "high",     "Initial Access"),
    "success_after_bf": (30, "critical", "Credential Access"),
    "new_geo":          (10, "low",      "Anomaly"),
    "unseen_ip":        (10, "low",      "Anomaly"),
    "off_hours":        (10, "medium",   "Anomaly"),
    "priv_esc":         (20, "critical", "Privilege Escalation"),
    "sensitive_access": (15, "high",     "Collection"),
    "data_exfil":       (25, "critical", "Exfiltration"),
    "log_tamper":       (15, "critical", "Defense Evasion"),
}
# human label, why it matters, base confidence
RULE_INFO = {
    "brute_force":      ("repeated failed logins on one account",
                         "Many failures against one account in minutes is typical password guessing.", "high"),
    "password_spray":   ("one IP failing against many accounts",
                         "One source trying many usernames quickly is typical password spraying.", "high"),
    "success_after_bf": ("successful login after an attack pattern",
                         "A login that follows a burst of failures from the same IP may be a guessed password.", "high"),
    "new_geo":          ("login from an unusual country",
                         "The user normally logs in from a different country.", "low"),
    "unseen_ip":        ("login from an IP this user never used before",
                         "A known user suddenly appears from a new address (same country). Often harmless "
                         "(new device or network), so it is a weak signal on its own.", "low"),
    "off_hours":        ("off-hours activity",
                         "Activity between 00:00 and 05:00 for a user who is normally never active then.", "low"),
    "priv_esc":         ("privilege change",
                         "A role or privilege change is a common step after an account is taken over.", "medium"),
    "sensitive_access": ("access to sensitive resources",
                         "Finance, HR, secrets, database or backup files were downloaded.", "medium"),
    "data_exfil":       ("large data download",
                         "A very large volume of data left in a short time.", "high"),
    "log_tamper":       ("log clearing",
                         "Clearing logs is a defense-evasion technique used to hide activity.", "high"),
}
# rule -> (MITRE ATT&CK technique id, technique name, ATT&CK tactic).
# Best-fit mapping: the log shows WHAT happened, not the exact attacker tooling or channel.
MITRE = {
    "brute_force":      ("T1110",     "Brute Force",                    "Credential Access"),
    "password_spray":   ("T1110.003", "Password Spraying",              "Credential Access"),
    "success_after_bf": ("T1078",     "Valid Accounts",                 "Initial Access"),
    "new_geo":          ("T1078",     "Valid Accounts",                 "Initial Access"),
    "unseen_ip":        ("T1078",     "Valid Accounts",                 "Initial Access"),
    "off_hours":        ("T1078",     "Valid Accounts",                 "Initial Access"),
    "priv_esc":         ("T1098",     "Account Manipulation",           "Persistence"),
    "sensitive_access": ("T1005",     "Data from Local System",         "Collection"),
    "data_exfil":       ("T1041",     "Exfiltration Over C2 Channel",   "Exfiltration"),
    "log_tamper":       ("T1070",     "Indicator Removal",              "Defense Evasion"),
}
SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
INCIDENT_THRESHOLD = 70
CHAIN_BONUS = 10  # added when 3+ different kill-chain stages come from the same IP
STAGE_ORDER = ["Initial Access", "Credential Access", "Privilege Escalation", "Collection",
               "Exfiltration", "Defense Evasion"]

BRUTE_THRESHOLD, BRUTE_WINDOW = 10, pd.Timedelta(minutes=10)    # failures on one account
SPRAY_USERS, SPRAY_WINDOW = 5, pd.Timedelta(minutes=15)         # distinct accounts from one IP
EXFIL_BYTES = 200 * 1024 * 1024                                 # per user/IP/hour
UNSEEN_MIN_HISTORY = 5       # earlier successful logins a user needs before "new IP" means something
UNSEEN_MAX_PRIOR_IPS = 2     # users who already rotate through many IPs are skipped (false-positive guard)
SENSITIVE_PATTERNS = ["/secrets", "/finance", "/hr/", "payroll", ".sql", ".db", "backup",
                      "passwd", "shadow", "id_rsa", ".pem"]
_SENSITIVE_RE = "|".join(re.escape(p) for p in SENSITIVE_PATTERNS)


# --------------------------------------------------------------------------- parameters
@dataclass(frozen=True)
class Params:
    """Adjustable detection thresholds. Defaults reproduce the original behaviour."""
    brute_threshold: int = 10
    brute_window_min: int = 10
    spray_users: int = 5
    spray_window_min: int = 15
    exfil_mb: int = 200
    incident_threshold: int = 70
    unseen_min_history: int = 5
    unseen_max_prior_ips: int = 2


def default_params() -> Params:
    """Built from the module constants at call time, so the defaults can never drift."""
    return Params(
        brute_threshold=BRUTE_THRESHOLD,
        brute_window_min=int(BRUTE_WINDOW.total_seconds() // 60),
        spray_users=SPRAY_USERS,
        spray_window_min=int(SPRAY_WINDOW.total_seconds() // 60),
        exfil_mb=EXFIL_BYTES // (1024 * 1024),
        incident_threshold=INCIDENT_THRESHOLD,
        unseen_min_history=UNSEEN_MIN_HISTORY,
        unseen_max_prior_ips=UNSEEN_MAX_PRIOR_IPS,
    )


# --------------------------------------------------------------------------- ingestion
def load_logs(src) -> pd.DataFrame:
    """Read and clean a log CSV. Bad rows are dropped and counted (see df.attrs), never invented."""
    df = pd.read_csv(src)
    missing = [c for c in REQUIRED_COLS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns: {', '.join(missing)}")
    if df.empty:
        raise ValueError("Log file is empty")
    total = len(df)

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    for col in ("user", "ip", "event"):
        s = df[col].astype("string").str.strip()
        df[col] = s.where(s != "", pd.NA).astype(object)
    bad = df[["timestamp", "user", "ip", "event"]].isna().any(axis=1)
    df = df[~bad].copy()
    if df.empty:
        raise ValueError("No valid log rows (every row has a bad timestamp or a missing user/ip/event)")

    df["country"] = df["country"].fillna("??").astype(str)
    df["resource"] = df["resource"].fillna("").astype(str)
    df["bytes"] = pd.to_numeric(df["bytes"], errors="coerce").fillna(0).astype("int64")
    df = df.sort_values("timestamp", kind="stable").reset_index(drop=True)
    df.attrs["total_rows"] = total
    df.attrs["dropped_rows"] = int(bad.sum())
    df.attrs["duplicate_rows"] = int(df.duplicated().sum())  # reported, not removed
    return df


# --------------------------------------------------------------------------- alerts
def _alert(rule, ip, user, time, detail, n=1, evidence=(), confidence=None):
    w, sev, stage = RULES[rule]
    label, reason, base_conf = RULE_INFO[rule]
    m_id, m_name, m_tactic = MITRE[rule]
    return {"rule": rule, "label": label, "severity": sev, "stage": stage, "ip": ip,
            "user": str(user), "time": time, "detail": detail, "weight": w, "count": n,
            "confidence": confidence or base_conf, "reason": reason,
            "mitre_id": m_id, "mitre_name": m_name, "mitre_tactic": m_tactic,
            "mitre": f"{m_id} {m_name}",
            "evidence": [int(i) for i in evidence]}


def mitre_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def _fmt_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def _burst(ts, users, window, threshold, distinct):
    """Sliding window over sorted timestamps.

    Returns (first_pos, last_pos) of the burst, or None. A row "qualifies" when the window
    ending at it holds >= threshold events (or >= threshold distinct users if distinct=True).
    """
    cnt, lo, qual, starts = Counter(), 0, [], {}
    for i, t in enumerate(ts):
        cnt[users[i]] += 1
        while t - ts[lo] > window:
            cnt[users[lo]] -= 1
            if cnt[users[lo]] == 0:
                del cnt[users[lo]]
            lo += 1
        metric = len(cnt) if distinct else i - lo + 1
        if metric >= threshold:
            qual.append(i)
            starts[i] = lo
    return (starts[qual[0]], qual[-1]) if qual else None


def detect(df: pd.DataFrame, params=None) -> list[dict]:
    p = params or default_params()
    brute_window = pd.Timedelta(minutes=max(1, p.brute_window_min))
    spray_window = pd.Timedelta(minutes=max(1, p.spray_window_min))
    brute_n = max(1, p.brute_threshold)
    spray_n = max(1, p.spray_users)
    exfil_bytes = max(1, p.exfil_mb) * 1024 * 1024

    alerts = []
    if df.empty:
        return alerts
    fails = df[df.event == "login_failed"].sort_values("timestamp", kind="stable")
    succ = df[df.event == "login_success"].sort_values("timestamp", kind="stable")

    attack_start, attack_ev, targeted = {}, {}, {}

    def remember(ip, ev):
        attack_start[ip] = min(attack_start.get(ip, ev.timestamp.min()), ev.timestamp.min())
        attack_ev.setdefault(ip, set()).update(ev.index)
        targeted.setdefault(ip, set()).update(ev.user)

    # --- brute force: >=N failures on ONE account from one IP inside the window
    for (ip, user), g in fails.groupby(["ip", "user"]):
        b = _burst(g.timestamp.tolist(), g.user.tolist(), brute_window, brute_n, False)
        if b:
            ev = g.iloc[b[0]:b[1] + 1]
            remember(ip, ev)
            alerts.append(_alert("brute_force", ip, user, ev.timestamp.min(),
                                 f"{len(ev)} failed logins against '{user}' from {ip} within "
                                 f"{p.brute_window_min} min (brute force)", len(ev), ev.index))

    # --- password spray: >=N DIFFERENT accounts failing from one IP inside the window
    for ip, g in fails.groupby("ip"):
        b = _burst(g.timestamp.tolist(), g.user.tolist(), spray_window, spray_n, True)
        if b:
            ev = g.iloc[b[0]:b[1] + 1]
            remember(ip, ev)
            alerts.append(_alert("password_spray", ip, ev.user.mode()[0], ev.timestamp.min(),
                                 f"{len(ev)} failed logins across {ev.user.nunique()} different accounts "
                                 f"from {ip} (password spray)", len(ev), ev.index))

    # --- successful login right after an attack pattern from the same IP
    for ip, start in attack_start.items():
        hit = succ[(succ.ip == ip) & (succ.timestamp >= start)]
        if not hit.empty:
            r = hit.iloc[0]
            conf = "high" if r.user in targeted[ip] else "medium"
            alerts.append(_alert("success_after_bf", ip, r.user, r.timestamp,
                                 f"Account '{r.user}' logged in successfully from {ip} after the failed "
                                 f"attempts - possible compromise", 1,
                                 sorted(attack_ev[ip]) + [r.name], conf))

    # --- login from a country that is not the user's usual one
    if not succ.empty:
        usual = succ.groupby("user")["country"].agg(lambda s: s.mode()[0])
        for (user, ip, country), g in succ.groupby(["user", "ip", "country"]):
            if user in usual and country != usual[user]:
                alerts.append(_alert("new_geo", ip, user, g.timestamp.min(),
                                     f"'{user}' logged in from {country} (usually {usual[user]})",
                                     len(g), g.index))

    # --- unseen IP for this user (same country as the user's history, so it never overlaps new_geo)
    if not succ.empty:
        for user, g in succ.groupby("user"):
            first_seen = g.groupby("ip")["timestamp"].min().sort_values(kind="stable")
            for ip, t0 in first_seen.items():
                prior = g[g.timestamp < t0]
                if len(prior) < p.unseen_min_history:
                    continue                      # not enough history to call anything "new"
                if prior.ip.nunique() > p.unseen_max_prior_ips:
                    continue                      # user already rotates IPs: too noisy
                cur = g[g.ip == ip]
                country = cur.country.mode()[0]
                if country != prior.country.mode()[0]:
                    continue                      # different country is the new_geo rule's job
                alerts.append(_alert("unseen_ip", ip, user, t0,
                                     f"'{user}' logged in from {ip} ({country}), an IP not used in the "
                                     f"{len(prior)} earlier successful logins of this user",
                                     len(cur), cur.index))

    # --- off-hours (00:00-05:00) activity for users who normally never do that
    off = df.timestamp.dt.hour < 5
    base = df.event.isin(["login_success", "file_download"])  # baseline ignores failed-login noise
    off_share = off[base].groupby(df.user[base]).mean()
    off_events = ["login_success", "file_download", "privilege_change", "log_cleared"]
    for (user, ip), g in df[off & df.event.isin(off_events)].groupby(["user", "ip"]):
        if off_share.get(user, 0) < 0.05:
            alerts.append(_alert("off_hours", ip, user, g.timestamp.min(),
                                 f"{len(g)} off-hours event(s) for '{user}' (normally active 09-19h)",
                                 len(g), g.index))

    # --- privilege change / log clearing
    for i, r in df[df.event == "privilege_change"].iterrows():
        alerts.append(_alert("priv_esc", r.ip, r.user, r.timestamp,
                             f"Privilege change by '{r.user}': {r.resource}", 1, [i]))
    for i, r in df[df.event == "log_cleared"].iterrows():
        alerts.append(_alert("log_tamper", r.ip, r.user, r.timestamp,
                             f"Log file cleared by '{r.user}': {r.resource}", 1, [i]))

    # --- sensitive resources (finance / HR / secrets / db / backup files)
    dl = df[df.event == "file_download"].copy()
    if not dl.empty:
        sens = dl[dl.resource.str.contains(_SENSITIVE_RE, case=False, regex=True)]
        for (user, ip), g in sens.groupby(["user", "ip"]):
            alerts.append(_alert("sensitive_access", ip, user, g.timestamp.min(),
                                 f"'{user}' downloaded {len(g)} sensitive file(s): "
                                 f"{', '.join(sorted(set(g.resource))[:4])}", len(g), g.index))

        # --- data exfiltration: >=N MB downloaded by one user/IP within an hour
        dl["hour"] = dl.timestamp.dt.floor("h")
        for (user, ip, hour), g in dl.groupby(["user", "ip", "hour"]):
            total = g.bytes.sum()
            if total >= exfil_bytes:
                big = g.sort_values("bytes", ascending=False).iloc[0]
                alerts.append(_alert("data_exfil", ip, user, g.timestamp.min(),
                                     f"'{user}' downloaded {_fmt_bytes(total)} in {len(g)} files "
                                     f"(largest: {big.resource})", len(g), g.index))

    alerts = sorted(alerts, key=lambda a: a["time"])
    for n, a in enumerate(alerts, 1):
        a["id"] = f"ALR-{n:03d}"
    return alerts


# --------------------------------------------------------------------------- risk score
def score_ips(alerts: list[dict]) -> pd.DataFrame:
    """Per-IP risk score. Each distinct rule counts once; `reasons` lists every point added."""
    rows = {}
    for a in alerts:
        r = rows.setdefault(a["ip"], {"rules": {}, "alerts": 0, "users": set(), "stages": set()})
        r["rules"][a["rule"]] = r["rules"].get(a["rule"], 0) + 1
        r["alerts"] += 1
        r["users"].add(a["user"])
        r["stages"].add(a["stage"])
    out = []
    for ip, r in rows.items():
        reasons, raw = [], 0
        for rule, n in sorted(r["rules"].items(), key=lambda kv: -RULES[kv[0]][0]):
            w = RULES[rule][0]
            raw += w
            reasons.append(f"+{w} {RULE_INFO[rule][0]} ({n} alert{'s' if n > 1 else ''})")
        chain = sorted((s for s in r["stages"] if s != "Anomaly"), key=STAGE_ORDER.index)
        if len(chain) >= 3:
            raw += CHAIN_BONUS
            reasons.append(f"+{CHAIN_BONUS} multi-stage activity from one IP ({' -> '.join(chain)})")
        if raw > 100:
            reasons.append(f"score capped at 100 (raw total {raw})")
        out.append({"ip": ip, "rules": ", ".join(sorted(r["rules"])), "score": min(100, raw),
                    "alerts": r["alerts"], "users": ", ".join(sorted(r["users"])), "reasons": reasons})
    if not out:
        return pd.DataFrame(columns=["ip", "score", "level", "alerts", "rules", "users", "reasons"])
    df = pd.DataFrame(out)
    df["level"] = pd.cut(df.score, [-1, 39, 69, 100], labels=["low", "high", "critical"]).astype(str)
    return df.sort_values("score", ascending=False).reset_index(drop=True)


def score_timeline(alerts: list[dict], ip: str) -> pd.DataFrame:
    """Step-by-step build-up of one IP's risk score (used by the attack replay).

    Uses exactly the same rules as score_ips: each distinct rule counts once, plus the
    multi-stage bonus the first time 3 kill-chain stages are present. The last row's
    `score` therefore equals score_ips()'s score for that IP.
    """
    cols = ["time", "alert_id", "rule", "label", "stage", "points", "raw", "score", "note"]
    rows, seen, stages, raw, bonus_done = [], set(), set(), 0, False
    for a in sorted((x for x in alerts if x["ip"] == ip), key=lambda x: x["time"]):
        pts, note = 0, ""
        if a["rule"] not in seen:
            seen.add(a["rule"])
            pts += a["weight"]
        else:
            note = "same rule again: no extra points"
        if a["stage"] != "Anomaly":
            stages.add(a["stage"])
        if not bonus_done and len(stages) >= 3:
            bonus_done = True
            pts += CHAIN_BONUS
            note = f"includes +{CHAIN_BONUS} multi-stage bonus"
        raw += pts
        rows.append({"time": a["time"], "alert_id": a.get("id", ""), "rule": a["rule"],
                     "label": a["label"], "stage": a["stage"], "points": pts, "raw": raw,
                     "score": min(100, raw), "note": note})
    return pd.DataFrame(rows, columns=cols)


# --------------------------------------------------------------------------- incidents
@dataclass
class Incident:
    ip: str
    score: int
    start: pd.Timestamp
    end: pd.Timestamp
    user: str
    timeline: list
    story: str                      # INFERRED narrative (hedged wording)
    id: str = ""
    title: str = ""
    severity: str = ""
    confidence: str = ""
    status: str = "open"
    related_users: list = field(default_factory=list)
    related_ips: list = field(default_factory=list)
    detection_types: list = field(default_factory=list)
    event_count: int = 0
    reasons: list = field(default_factory=list)          # why the risk score is what it is
    observed: list = field(default_factory=list)         # OBSERVED facts taken from the logs
    recommendations: list = field(default_factory=list)
    mitre: list = field(default_factory=list)            # unique ATT&CK techniques seen in this incident
    evidence: pd.DataFrame = None                        # raw log rows + "why" column


def _mitre_summary(alerts) -> list:
    seen = {}
    for a in alerts:
        t = seen.setdefault(a["mitre_id"], {"id": a["mitre_id"], "name": a["mitre_name"],
                                            "tactic": a["mitre_tactic"], "url": mitre_url(a["mitre_id"]),
                                            "rules": []})
        if a["rule"] not in t["rules"]:
            t["rules"].append(a["rule"])
    return sorted(seen.values(), key=lambda t: t["id"])


def build_incidents(df, alerts, ip_scores, params=None) -> list[Incident]:
    p = params or default_params()
    incidents = []
    for _, row in ip_scores[ip_scores.score >= p.incident_threshold].iterrows():
        tl = [a for a in alerts if a["ip"] == row.ip and a["rule"] != "new_geo"]
        if not tl:
            continue
        victim = next((a["user"] for a in tl if a["rule"] == "success_after_bf"), tl[0]["user"])
        rules = [a["rule"] for a in tl]

        why = {}
        for a in tl:
            for i in a["evidence"]:
                why.setdefault(i, []).append(a["label"])
        ids = sorted(i for i in why if i in df.index)
        evidence = df.loc[ids].copy()
        evidence["why"] = ["; ".join(dict.fromkeys(why[i])) for i in ids]

        fails = df[(df.ip == row.ip) & (df.event == "login_failed")]
        related = sorted(set(fails.user) | {a["user"] for a in tl})
        severity = "critical" if row.score >= 90 else "high" if row.score >= 65 else "medium"
        n = len(incidents) + 1
        incidents.append(Incident(
            row.ip, int(row.score), tl[0]["time"], tl[-1]["time"], victim, tl,
            make_story(row.ip, victim, tl, df),
            id=f"INC-{n:03d}", title=_title(row.ip, victim, rules), severity=severity,
            confidence=_confidence(tl), related_users=related, related_ips=[row.ip],
            detection_types=sorted(set(rules)), event_count=len(evidence),
            reasons=list(row.reasons), observed=make_observed(row.ip, victim, tl, df),
            recommendations=_recommendations(rules, row.ip, victim),
            mitre=_mitre_summary(tl), evidence=evidence))
    return incidents


def _title(ip, victim, rules):
    if "success_after_bf" in rules:
        return f"Possible account compromise: '{victim}' from {ip}"
    if {"brute_force", "password_spray"} & set(rules):
        return f"Credential attack from {ip}"
    return f"Suspicious activity from {ip}"


def _confidence(tl):
    stages = {a["stage"] for a in tl} - {"Anomaly"}
    rules = {a["rule"] for a in tl}
    if len(stages) >= 3 or ("success_after_bf" in rules and rules & {"priv_esc", "data_exfil"}):
        return "high"
    return "medium" if len(stages) >= 2 else "low"


def _recommendations(rules, ip, victim):
    r = set(rules)
    recs = [f"Block {ip} at the firewall / WAF and review other activity from it."]
    if "success_after_bf" in r:
        recs.append(f"Reset the password for '{victim}', revoke its sessions/tokens and enforce MFA.")
    if "priv_esc" in r:
        recs.append("Review and roll back any role or permission changes made during the incident.")
    if r & {"data_exfil", "sensitive_access"}:
        recs.append("Audit the downloaded files, treat their contents as exposed, rotate any secrets in them.")
    if "log_tamper" in r:
        recs.append("Restore logs from backup or a central log store; the local log may be incomplete.")
    if r & {"brute_force", "password_spray"}:
        recs.append("Add lockout / rate limiting on the login endpoint and check the other targeted accounts.")
    return recs


def make_observed(ip, victim, tl, df) -> list:
    """Facts that are directly visible in the logs (no interpretation)."""
    by = {a["rule"]: a for a in tl}
    out = []
    fails = df[(df.ip == ip) & (df.event == "login_failed")]
    if len(fails):
        out.append(f"{len(fails)} failed logins from {ip} against {fails.user.nunique()} account(s), "
                   f"{fails.timestamp.min():%d %b %H:%M:%S} to {fails.timestamp.max():%H:%M:%S}.")
    if "success_after_bf" in by:
        out.append(f"Successful login as '{victim}' from {ip} at {by['success_after_bf']['time']:%H:%M:%S}.")
    for rule in ("priv_esc", "sensitive_access", "data_exfil", "log_tamper", "off_hours"):
        if rule in by:
            out.append(by[rule]["detail"] + ".")
    return out


def make_story(ip, victim, tl, df) -> str:
    """INFERRED attack sequence. Wording is deliberately hedged: the logs suggest, not prove."""
    country = df.loc[df.ip == ip, "country"].iloc[0]
    by = {a["rule"]: a for a in tl}
    fails = df[(df.ip == ip) & (df.event == "login_failed")]
    parts = [f"Likely sequence: from {tl[0]['time']:%H:%M} on {tl[0]['time']:%d %b}, {ip} ({country}) "
             f"appears to have attacked the login service"
             + (f" with {len(fails)} failed attempts." if len(fails) else ".")]
    if "success_after_bf" in by:
        parts.append(f"It then logged in as '{victim}' at {by['success_after_bf']['time']:%H:%M:%S}, "
                     f"which suggests a possible account compromise.")
    if "priv_esc" in by:
        parts.append("A privilege change followed, which may indicate privilege escalation.")
    if "data_exfil" in by or "sensitive_access" in by:
        parts.append("Sensitive or large downloads followed, possibly data theft.")
    if "log_tamper" in by:
        parts.append("Logs were then cleared, which may be an attempt to hide the activity.")
    return " ".join(parts)


# --------------------------------------------------------------------------- exports
def incident_to_dict(inc: Incident, status=None) -> dict:
    """JSON-safe export of one incident (observed and inferred parts stay separate)."""
    ev = inc.evidence.copy()
    ev.insert(0, "row", ev.index)
    ev["timestamp"] = ev["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    return {
        "id": inc.id, "title": inc.title, "severity": inc.severity, "confidence": inc.confidence,
        "status": status or inc.status, "risk_score": inc.score,
        "attacker_ip": inc.ip, "primary_account": inc.user,
        "first_seen": f"{inc.start:%Y-%m-%d %H:%M:%S}", "last_seen": f"{inc.end:%Y-%m-%d %H:%M:%S}",
        "related_users": inc.related_users, "detection_types": inc.detection_types,
        "observed": inc.observed,
        "inferred_story": inc.story,
        "mitre_techniques": inc.mitre,
        "score_reasons": inc.reasons,
        "timeline": [{"alert_id": a.get("id", ""), "time": f"{a['time']:%Y-%m-%d %H:%M:%S}",
                      "rule": a["rule"], "stage": a["stage"], "severity": a["severity"],
                      "confidence": a["confidence"], "mitre": a["mitre"], "detail": a["detail"],
                      "why_it_matters": a["reason"]} for a in inc.timeline],
        "recommendations": inc.recommendations,
        "evidence": json.loads(ev.to_json(orient="records")),
    }


def incident_to_markdown(inc: Incident, status=None) -> str:
    status = status or inc.status
    lines = [f"# {inc.id} - {inc.title}", "",
             f"Severity: {inc.severity} | Risk: {inc.score}/100 | Confidence: {inc.confidence} | "
             f"Status: {status}", "",
             f"First seen {inc.start:%Y-%m-%d %H:%M:%S}, last seen {inc.end:%Y-%m-%d %H:%M:%S}.", "",
             "## Observed (taken directly from the logs)"]
    lines += [f"- {x}" for x in inc.observed]
    lines += ["", "## Inferred sequence (our interpretation, not proof)", inc.story, "",
              "## MITRE ATT&CK techniques"]
    lines += [f"- {m['id']} {m['name']} ({m['tactic']}) - rules: {', '.join(m['rules'])}" for m in inc.mitre]
    lines += ["", "## Risk score reasons"] + [f"- {x}" for x in inc.reasons]
    lines += ["", "## Timeline"]
    lines += [f"- {a['time']:%Y-%m-%d %H:%M:%S} [{a['stage']}] ({a['mitre']}) {a['detail']}"
              for a in inc.timeline]
    lines += ["", "## Recommended actions"] + [f"- {x}" for x in inc.recommendations]
    return "\n".join(lines)


def analyze(df, params=None):
    p = params or default_params()
    alerts = detect(df, p)
    ips = score_ips(alerts)
    return alerts, ips, build_incidents(df, alerts, ips, p)