import io
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pandas as pd
try:
    import pytest
except ImportError:
    pytest = None

from detector import analyze, load_logs

LOG = os.path.join(os.path.dirname(__file__), "..", "data", "auth_logs.csv")


def test_attacker_found_as_incident():
    alerts, ips, incidents = analyze(load_logs(LOG))
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.ip == "185.220.101.47" and inc.user == "admin" and inc.score == 100
    stages = [a["stage"] for a in inc.timeline]
    assert stages == ["Initial Access", "Credential Access", "Privilege Escalation",
                      "Exfiltration", "Defense Evasion"] or "Anomaly" in stages


def test_traveller_is_not_an_incident():
    _, ips, incidents = analyze(load_logs(LOG))
    row = ips[ips.ip == "88.198.12.9"].iloc[0]
    assert row.score < 40 and row.level == "low"
    assert all(i.ip != "88.198.12.9" for i in incidents)


def test_normal_typos_do_not_trigger_brute_force():
    alerts, _, _ = analyze(load_logs(LOG))
    assert all(not a["ip"].startswith("10.") for a in alerts)


def _raises(fn):
    try:
        fn()
    except ValueError:
        return True
    return False


def test_missing_columns_rejected():
    assert _raises(lambda: load_logs(io.StringIO("timestamp,user\n2026-01-01,a\n")))


def test_empty_file_rejected():
    assert _raises(lambda: load_logs(io.StringIO("timestamp,user,ip,country,event,resource,bytes\n")))


def test_clean_logs_produce_no_incident():
    df = load_logs(LOG)
    clean = df[df.ip != "185.220.101.47"]
    assert analyze(clean)[2] == []


if __name__ == "__main__":  # run without pytest: python tests/test_detector.py
    import inspect
    fns = [f for n, f in list(globals().items()) if n.startswith("test_") and inspect.isfunction(f)]
    for f in fns:
        f()
        print("PASS", f.__name__)
