import pandas as pd

from correlation import find_campaigns, impossible_travel

COLS = ["timestamp", "user", "ip", "country", "event", "resource", "bytes"]


def _log(rows):
    df = pd.DataFrame(rows, columns=COLS)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.sort_values("timestamp", kind="stable").reset_index(drop=True)


def _fails(ip, country, users, start):
    t0 = pd.Timestamp(start)
    return [(t0 + pd.Timedelta(minutes=2 * i), u, ip, country, "login_failed", "", 0)
            for i, u in enumerate(users)]


def _three_ips(start_b="2026-10-03 14:05"):
    return (_fails("1.1.1.1", "NL", ["admin", "priya", "rahul"], "2026-10-03 14:00")
            + _fails("2.2.2.2", "CN", ["admin", "rahul", "neha"], start_b)
            + _fails("3.3.3.3", "BR", ["admin", "priya", "neha"], "2026-10-03 14:10"))


def test_three_ips_on_shared_accounts_form_one_campaign():
    camps = find_campaigns(_log(_three_ips()))
    assert len(camps) == 1
    c = camps[0]
    assert c["id"] == "CMP-001"
    assert set(c["ips"]) == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}
    assert set(c["accounts"]) == {"admin", "priya", "rahul", "neha"}
    assert c["failures"] == 9


def test_far_apart_in_time_is_not_a_campaign():
    assert find_campaigns(_log(_three_ips(start_b="2026-10-03 20:00"))) == []


def test_single_ip_is_not_a_campaign():
    rows = _fails("1.1.1.1", "NL", ["admin", "priya", "rahul"], "2026-10-03 14:00")
    assert find_campaigns(_log(rows)) == []


def test_one_shared_account_is_not_enough():
    rows = (_fails("1.1.1.1", "NL", ["admin", "priya"], "2026-10-03 14:00")
            + _fails("2.2.2.2", "CN", ["admin", "neha"], "2026-10-03 14:05")
            + _fails("3.3.3.3", "BR", ["admin", "amit"], "2026-10-03 14:10"))
    assert find_campaigns(_log(rows)) == []


def test_success_on_targeted_account_is_reported():
    rows = _three_ips() + [("2026-10-03 14:30", "neha", "2.2.2.2", "CN", "login_success", "", 0)]
    c = find_campaigns(_log(rows))[0]
    assert c["severity"] == "high"
    assert [(s["ip"], s["user"]) for s in c["successes"] if s["targeted"]] == [("2.2.2.2", "neha")]


def test_normal_users_with_typos_are_ignored():
    rows = [("2026-10-03 10:00", u, f"10.0.0.{i}", "IN", "login_failed", "", 0)
            for i, u in enumerate(["a", "b", "c", "d"])]
    assert find_campaigns(_log(rows)) == []


def _login(ts, ip, country, user="emma"):
    return (ts, user, ip, country, "login_success", "", 0)


def test_impossible_travel_detected():
    df = _log([_login("2026-10-03 10:00", "9.9.9.9", "US"), _login("2026-10-03 10:40", "8.8.8.8", "SG")])
    r = impossible_travel(df)
    assert len(r) == 1
    assert (r[0]["from_country"], r[0]["to_country"], r[0]["gap_min"]) == ("US", "SG", 40)


def test_long_gap_or_same_country_is_not_flagged():
    far = _log([_login("2026-10-03 10:00", "9.9.9.9", "US"), _login("2026-10-03 15:00", "8.8.8.8", "DE")])
    same = _log([_login("2026-10-03 10:00", "9.9.9.9", "US"), _login("2026-10-03 10:20", "7.7.7.7", "US")])
    assert impossible_travel(far) == []
    assert impossible_travel(same) == []


def test_unknown_country_is_ignored():
    df = _log([_login("2026-10-03 10:00", "9.9.9.9", "US"), _login("2026-10-03 10:10", "8.8.8.8", "??")])
    assert impossible_travel(df) == []