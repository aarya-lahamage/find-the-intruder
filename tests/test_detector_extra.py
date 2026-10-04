"""Extra detector tests (kept separate so the original tests stay untouched)."""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detector import analyze, detect, load_logs, score_ips

HEADER = "timestamp,user,ip,country,event,resource,bytes\n"
LOG = os.path.join(os.path.dirname(__file__), "..", "data", "auth_logs.csv")


def logs(rows):
    """rows: list of (timestamp, user, ip, event[, resource, bytes]) -> cleaned DataFrame."""
    lines = []
    for r in rows:
        ts, user, ip, event = r[:4]
        res, size = (r[4], r[5]) if len(r) > 4 else ("", 0)
        lines.append(f"{ts},{user},{ip},IN,{event},{res},{size}")
    return load_logs(io.StringIO(HEADER + "\n".join(lines) + "\n"))


def t(sec):
    return f"2026-01-01 03:{sec // 60:02d}:{sec % 60:02d}"


def fails(user, ip, n, step=10, start=0):
    return [(t(start + i * step), user if isinstance(user, str) else user[i % len(user)], ip,
             "login_failed") for i in range(n)]


def rules(alerts):
    return {a["rule"] for a in alerts}


# ---- ingestion / robustness ------------------------------------------------
def test_malformed_timestamp_rows_are_dropped_and_counted():
    df = logs([("not-a-date", "a", "1.1.1.1", "login_failed"), (t(1), "b", "2.2.2.2", "login_success")])
    assert len(df) == 1 and df.attrs["dropped_rows"] == 1 and df.attrs["total_rows"] == 2


def test_missing_user_or_ip_rows_are_dropped_not_grouped_together():
    csv = HEADER + f"{t(1)},,1.1.1.1,IN,login_failed,,0\n{t(2)},a,,IN,login_failed,,0\n{t(3)},b,3.3.3.3,IN,login_success,,0\n"
    df = load_logs(io.StringIO(csv))
    assert list(df.user) == ["b"] and df.attrs["dropped_rows"] == 2


def test_all_rows_bad_is_rejected():
    try:
        load_logs(io.StringIO(HEADER + "bad,a,1.1.1.1,IN,login_failed,,0\n"))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_duplicate_events_are_reported_not_removed():
    row = (t(1), "a", "1.1.1.1", "login_success")
    df = logs([row, row, (t(2), "b", "2.2.2.2", "login_success")])
    assert len(df) == 3 and df.attrs["duplicate_rows"] == 1


def test_analyze_on_empty_frame_is_safe():
    df = logs([(t(1), "a", "1.1.1.1", "login_success")]).iloc[0:0]
    alerts, ips, incidents = analyze(df)
    assert alerts == [] and len(ips) == 0 and incidents == []


# ---- detection rules -------------------------------------------------------
def test_brute_force_threshold_boundary():
    assert "brute_force" not in rules(detect(logs(fails("bob", "9.9.9.9", 9))))
    assert "brute_force" in rules(detect(logs(fails("bob", "9.9.9.9", 10))))


def test_slow_failures_outside_window_do_not_trigger():
    assert detect(logs(fails("bob", "9.9.9.9", 10, step=120))) == []  # 2 min apart -> 18 min span


def test_password_spray_detected_without_brute_force():
    found = rules(detect(logs(fails(["a", "b", "c", "d", "e", "f"], "8.8.8.8", 6))))
    assert found == {"password_spray"}


def test_few_users_is_not_spray():
    assert detect(logs(fails(["a", "b", "c"], "8.8.8.8", 4))) == []


def test_success_after_attack_flags_possible_compromise_with_evidence():
    rows = fails("bob", "6.6.6.6", 12) + [(t(200), "bob", "6.6.6.6", "login_success")]
    df = logs(rows)
    a = next(x for x in detect(df) if x["rule"] == "success_after_bf")
    assert a["user"] == "bob" and a["confidence"] == "high"
    assert len(df) - 1 in a["evidence"]            # the successful login row is part of the evidence
    assert all(i in df.index for i in a["evidence"])


def test_success_from_other_ip_is_not_flagged():
    rows = fails("bob", "6.6.6.6", 12) + [(t(200), "bob", "7.7.7.7", "login_success")]
    assert "success_after_bf" not in rules(detect(logs(rows)))


def test_sensitive_access_detected_but_normal_files_are_not():
    rows = [(t(1), "a", "1.1.1.1", "file_download", "/wiki/home", 100),
            (t(2), "a", "1.1.1.1", "file_download", "/hr/employees.db", 100)]
    found = [x for x in detect(logs(rows)) if x["rule"] == "sensitive_access"]
    assert len(found) == 1 and found[0]["count"] == 1


# ---- scoring / incidents ---------------------------------------------------
def test_score_reasons_match_score_when_not_capped():
    alerts = detect(logs(fails("bob", "9.9.9.9", 12)))
    row = score_ips(alerts).iloc[0]
    points = sum(int(r.split()[0]) for r in row.reasons if r.startswith("+"))
    assert row.score == points == 40


def test_clean_activity_produces_no_score_rows():
    row = score_ips(detect(logs([(t(1), "a", "1.1.1.1", "login_success"),
                                 (t(2), "a", "1.1.1.1", "login_success")])))
    assert len(row) == 0   # nothing suspicious at all -> no row


def test_real_incident_has_all_fields_and_real_evidence():
    df = load_logs(LOG)
    inc = analyze(df)[2][0]
    assert inc.id == "INC-001" and inc.status == "open" and inc.severity == "critical"
    assert inc.confidence == "high" and inc.title.startswith("Possible account compromise")
    assert {"brute_force", "password_spray", "success_after_bf", "priv_esc", "data_exfil",
            "log_tamper", "sensitive_access"} <= set(inc.detection_types)
    assert inc.reasons and any("capped" in r for r in inc.reasons)
    assert inc.observed and inc.recommendations
    # every evidence row really exists in the source log and belongs to the attacker
    assert (inc.evidence.ip == inc.ip).all() and len(inc.evidence) == inc.event_count
    assert (inc.evidence.why != "").all()
    assert inc.start <= inc.end and "admin" in inc.related_users


def test_story_is_hedged_not_certain():
    story = analyze(load_logs(LOG))[2][0].story.lower()
    assert "likely" in story or "suggests" in story or "may" in story


def test_timeline_is_chronological():
    inc = analyze(load_logs(LOG))[2][0]
    times = [a["time"] for a in inc.timeline]
    assert times == sorted(times)
