"""Tests for: adjustable Params, unseen_ip rule, MITRE mapping, score_timeline, exports."""
import io
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detector import (MITRE, RULES, Params, analyze, default_params, detect,  # noqa: E402
                      incident_to_dict, incident_to_markdown, load_logs, score_ips,
                      score_timeline)

COLS = ["timestamp", "user", "ip", "country", "event", "resource", "bytes"]
T0 = pd.Timestamp("2026-03-10 02:00:00")


def row(ts, user, ip, event, country="IN", resource="", nbytes=0):
    return [str(ts), user, ip, country, event, resource, nbytes]


def make_df(rows):
    return load_logs(io.StringIO(pd.DataFrame(rows, columns=COLS).to_csv(index=False)))


def rules_of(alerts):
    return {a["rule"] for a in alerts}


def attack_rows(ip="9.9.9.9"):
    rows = [row(T0 + pd.Timedelta(seconds=10 * i), "admin", ip, "login_failed", "RU") for i in range(12)]
    t = T0 + pd.Timedelta(minutes=5)
    rows += [
        row(t, "admin", ip, "login_success", "RU"),
        row(t + pd.Timedelta(minutes=1), "admin", ip, "privilege_change", "RU", "grant:root"),
        row(t + pd.Timedelta(minutes=2), "admin", ip, "file_download", "RU", "/finance/payroll.xlsx", 5000),
        row(t + pd.Timedelta(minutes=3), "admin", ip, "log_cleared", "RU", "/var/log/auth.log"),
    ]
    # quiet normal user in the background
    rows += [row(f"2026-03-0{d} 10:00:00", "bob", "10.0.0.2", "login_success") for d in range(1, 4)]
    return rows


# ----------------------------------------------------------------- Params
def test_default_params_match_module_constants():
    p = default_params()
    assert (p.brute_threshold, p.brute_window_min) == (10, 10)
    assert (p.spray_users, p.spray_window_min) == (5, 15)
    assert (p.exfil_mb, p.incident_threshold) == (200, 70)


def test_explicit_default_params_give_same_result_as_no_params():
    df = make_df(attack_rows())
    a1, _, i1 = analyze(df)
    a2, _, i2 = analyze(df, default_params())
    assert [a["id"] for a in a1] == [a["id"] for a in a2]
    assert [i.score for i in i1] == [i.score for i in i2]


def test_brute_force_threshold_is_adjustable():
    rows = [row(T0 + pd.Timedelta(seconds=30 * i), "carol", "7.7.7.7", "login_failed", "DE") for i in range(6)]
    df = make_df(rows)
    assert "brute_force" not in rules_of(detect(df))
    assert "brute_force" in rules_of(detect(df, Params(brute_threshold=5)))


def test_spray_threshold_is_adjustable():
    rows = [row(T0 + pd.Timedelta(seconds=20 * i), f"user{i}", "7.7.7.7", "login_failed", "DE") for i in range(3)]
    df = make_df(rows)
    assert "password_spray" not in rules_of(detect(df))
    assert "password_spray" in rules_of(detect(df, Params(spray_users=3)))


def test_exfil_threshold_is_adjustable():
    rows = [row("2026-03-10 11:00:00", "dave", "10.0.0.8", "file_download", "IN",
                "/public/report.pdf", 50 * 1024 * 1024)]
    df = make_df(rows)
    assert "data_exfil" not in rules_of(detect(df))
    assert "data_exfil" in rules_of(detect(df, Params(exfil_mb=40)))


def test_incident_threshold_is_adjustable():
    df = make_df(attack_rows())
    assert len(analyze(df)[2]) == 1
    assert len(analyze(df, Params(incident_threshold=101))[2]) == 0


# ----------------------------------------------------------------- unseen_ip
def _alice(extra, history=6):
    rows = [row(f"2026-03-0{d} 10:00:00", "alice", "10.0.0.5", "login_success") for d in range(1, history + 1)]
    return make_df(rows + extra)


def test_unseen_ip_fires_for_new_ip_same_country():
    df = _alice([row("2026-03-08 10:00:00", "alice", "10.0.0.99", "login_success", "IN")])
    alerts = detect(df)
    assert "unseen_ip" in rules_of(alerts)
    assert "new_geo" not in rules_of(alerts)
    a = next(x for x in alerts if x["rule"] == "unseen_ip")
    assert a["ip"] == "10.0.0.99" and a["user"] == "alice" and len(a["evidence"]) == 1


def test_unseen_ip_not_for_different_country_that_is_new_geo():
    df = _alice([row("2026-03-08 10:00:00", "alice", "5.5.5.5", "login_success", "DE")])
    r = rules_of(detect(df))
    assert "new_geo" in r and "unseen_ip" not in r


def test_unseen_ip_needs_enough_history():
    df = _alice([row("2026-03-05 10:00:00", "alice", "10.0.0.99", "login_success", "IN")], history=2)
    assert "unseen_ip" not in rules_of(detect(df))


def test_unseen_ip_quiet_for_known_ip():
    df = _alice([row("2026-03-08 10:00:00", "alice", "10.0.0.5", "login_success", "IN")])
    assert detect(df) == []


def test_unseen_ip_alone_is_never_an_incident():
    df = _alice([row("2026-03-08 10:00:00", "alice", "10.0.0.99", "login_success", "IN")])
    _, ips, incidents = analyze(df)
    assert incidents == [] and int(ips.score.max()) < 40


# ----------------------------------------------------------------- MITRE
def test_every_rule_has_a_mitre_mapping():
    assert set(MITRE) == set(RULES)
    for tid, name, tactic in MITRE.values():
        assert tid.startswith("T") and name and tactic


def test_alerts_carry_mitre_fields():
    alerts = detect(make_df(attack_rows()))
    by = {a["rule"]: a for a in alerts}
    assert by["brute_force"]["mitre_id"] == "T1110"
    assert by["priv_esc"]["mitre_id"] == "T1098"
    assert by["log_tamper"]["mitre_id"] == "T1070"
    assert by["success_after_bf"]["mitre"] == "T1078 Valid Accounts"


def test_password_spray_is_t1110_003():
    rows = [row(T0 + pd.Timedelta(seconds=10 * i), f"u{i}", "7.7.7.7", "login_failed", "DE") for i in range(6)]
    a = next(x for x in detect(make_df(rows)) if x["rule"] == "password_spray")
    assert a["mitre_id"] == "T1110.003" and a["mitre_name"] == "Password Spraying"


def test_incident_lists_unique_mitre_techniques():
    inc = analyze(make_df(attack_rows()))[2][0]
    ids = [m["id"] for m in inc.mitre]
    assert ids == sorted(set(ids))
    assert {"T1110", "T1078", "T1098", "T1070"} <= set(ids)
    assert all(m["url"].startswith("https://attack.mitre.org/techniques/") for m in inc.mitre)


# ----------------------------------------------------------------- score_timeline
def test_score_timeline_ends_at_score_ips_value():
    alerts = detect(make_df(attack_rows()))
    ips = score_ips(alerts)
    ip = ips.iloc[0].ip
    tl = score_timeline(alerts, ip)
    assert int(tl.score.iloc[-1]) == int(ips.iloc[0].score)


def test_score_timeline_never_decreases_and_caps_at_100():
    alerts = detect(make_df(attack_rows()))
    tl = score_timeline(alerts, "9.9.9.9")
    assert tl.score.is_monotonic_increasing
    assert tl.score.max() <= 100 and tl.raw.iloc[-1] >= tl.score.iloc[-1]


def test_score_timeline_empty_for_unknown_ip():
    tl = score_timeline(detect(make_df(attack_rows())), "1.2.3.4")
    assert tl.empty and "score" in tl.columns


# ----------------------------------------------------------------- exports
def test_incident_json_export_is_serialisable_and_separates_observed_from_inferred():
    inc = analyze(make_df(attack_rows()))[2][0]
    d = incident_to_dict(inc, status="investigating")
    text = json.dumps(d)
    assert json.loads(text)["status"] == "investigating"
    assert d["observed"] and d["inferred_story"] and d["mitre_techniques"]
    assert len(d["evidence"]) == inc.event_count
    assert d["attacker_ip"] == "9.9.9.9" and d["risk_score"] == inc.score


def test_incident_markdown_export_has_all_sections():
    inc = analyze(make_df(attack_rows()))[2][0]
    md = incident_to_markdown(inc)
    for part in ("## Observed", "## Inferred", "## MITRE ATT&CK", "## Risk score reasons",
                 "## Timeline", "## Recommended actions", "T1110"):
        assert part in md