"""Generate a realistic auth/server log with hidden attackers.

Usage: python generate_logs.py            -> data/auth_logs.csv        (single intruder)
       python generate_logs.py --multi    -> data/auth_logs_multi.csv  (several actors and decoys)
"""
import os
import random
import sys
from datetime import datetime, timedelta

import pandas as pd

random.seed(42)

START = datetime(2026, 10, 1, 0, 0, 0)
DAYS = 3
N_NORMAL = 5000

ATTACKER_IP = "185.220.101.47"
ATTACKER_COUNTRY = "RU"

USERS = ["admin", "priya", "rahul", "neha", "amit", "sara", "vikram", "anita", "karan", "meera",
         "john", "emma", "li", "carlos", "fatima", "arjun", "pooja", "dev", "ishaan", "tara",
         "nikhil", "zoya", "rohan", "kavya", "sameer"]
RESOURCES = ["/docs/report.pdf", "/docs/notes.txt", "/wiki/home", "/crm/leads.csv",
             "/reports/weekly.xlsx", "/tickets/export.csv", "/design/mockup.png"]


def _profile(i, user):
    country = "US" if user in ("john", "emma", "carlos") else "IN"
    ip = f"10.{i}.{random.randint(1, 250)}.{random.randint(1, 250)}"
    return {"ip": ip, "country": country}


PROFILES = {u: _profile(i, u) for i, u in enumerate(USERS, start=1)}
_STATE = random.getstate()          # add this line right after PROFILES

def main(path="data/auth_logs.csv", extended=False):
    random.setstate(_STATE)         # add as first line of main()
    ...


def _row(ts, user, ip, country, event, resource="", nbytes=0):
    return {"timestamp": ts, "user": user, "ip": ip, "country": country,
            "event": event, "resource": resource, "bytes": nbytes}


def normal_traffic():
    rows = []
    for _ in range(N_NORMAL):
        user = random.choice(USERS)
        p = PROFILES[user]
        day = random.randint(0, DAYS - 1)
        ts = START + timedelta(days=day, hours=random.randint(9, 18),
                               minutes=random.randint(0, 59), seconds=random.randint(0, 59))
        r = random.random()
        if r < 0.40:
            rows.append(_row(ts, user, p["ip"], p["country"], "login_success"))
        elif r < 0.45:
            rows.append(_row(ts, user, p["ip"], p["country"], "login_failed"))  # typos
        else:
            size = int(min(random.lognormvariate(13.5, 0.8), 8_000_000))
            rows.append(_row(ts, user, p["ip"], p["country"], "file_download",
                             random.choice(RESOURCES), size))
    return rows


def decoy_traveller():
    """Priya logs in from Germany during the day. Unusual, but harmless."""
    base = START + timedelta(days=1, hours=11)
    return [_row(base + timedelta(minutes=m), "priya", "88.198.12.9", "DE", "login_success")
            for m in (0, 25, 70)]


def attack():
    rows, t = [], START + timedelta(days=1, hours=2, minutes=14)
    # 1) brute force + password spray
    targets = ["admin"] * 52 + ["root", "test", "backup", "ubuntu", "oracle", "dev", "priya", "rahul"]
    random.shuffle(targets)
    for u in targets:
        t += timedelta(seconds=random.randint(4, 12))
        rows.append(_row(t, u, ATTACKER_IP, ATTACKER_COUNTRY, "login_failed"))
    # 2) successful login as admin
    t += timedelta(seconds=20)
    rows.append(_row(t, "admin", ATTACKER_IP, ATTACKER_COUNTRY, "login_success"))
    # 3) privilege escalation
    t += timedelta(minutes=2)
    rows.append(_row(t, "admin", ATTACKER_IP, ATTACKER_COUNTRY, "privilege_change", "role=superadmin"))
    # 4) data exfiltration
    for res, size in [("/finance/payroll.xlsx", 48_000_000), ("/hr/employees.db", 220_000_000),
                      ("/secrets/db_backup.sql", 1_200_000_000)]:
        t += timedelta(minutes=random.randint(2, 4))
        rows.append(_row(t, "admin", ATTACKER_IP, ATTACKER_COUNTRY, "file_download", res, size))
    # 5) cover tracks
    t += timedelta(minutes=5)
    rows.append(_row(t, "admin", ATTACKER_IP, ATTACKER_COUNTRY, "log_cleared", "/var/log/auth.log"))
    return rows


# ---------------------------------------------------------------- extra scenarios (multi-actor sample)
def distributed_spray():
    """Four IPs, each failing a few times on a few shared accounts. Every IP stays below the per-IP
    brute force and spray thresholds. One of them then logs in as a targeted account."""
    plan = [("45.155.205.18", "NL", ["admin", "priya", "rahul"]),
            ("103.152.220.9", "CN", ["admin", "rahul", "neha"]),
            ("177.75.40.213", "BR", ["admin", "priya", "neha"]),
            ("91.240.118.60", "UA", ["priya", "rahul", "neha"])]
    base = START + timedelta(days=2, hours=14, minutes=5)
    rows = []
    for k, (ip, country, users) in enumerate(plan):
        t = base + timedelta(minutes=7 * k)
        for u in users:
            for _ in range(2):
                t += timedelta(minutes=random.randint(3, 5), seconds=random.randint(0, 59))
                rows.append(_row(t, u, ip, country, "login_failed"))
        if ip == "103.152.220.9":
            t += timedelta(minutes=6)
            rows.append(_row(t, "neha", ip, country, "login_success"))
            t += timedelta(minutes=4)
            rows.append(_row(t, "neha", ip, country, "file_download", "/crm/leads.csv", 4_200_000))
    return rows


def lone_brute_force():
    """One IP guesses one account 14 times and never gets in."""
    t = START + timedelta(hours=16, minutes=30)
    rows = []
    for _ in range(14):
        t += timedelta(seconds=random.randint(15, 30))
        rows.append(_row(t, "sara", "198.51.100.23", "TR", "login_failed"))
    return rows


def forgotten_password():
    """A user mistypes a password a few times, then gets in from the usual IP. Harmless."""
    p = PROFILES["karan"]
    t = START + timedelta(days=1, hours=9, minutes=40)
    rows = []
    for _ in range(6):
        t += timedelta(seconds=random.randint(20, 40))
        rows.append(_row(t, "karan", p["ip"], p["country"], "login_failed"))
    t += timedelta(seconds=30)
    rows.append(_row(t, "karan", p["ip"], p["country"], "login_success"))
    return rows


def travel_pair():
    """Same user, two countries, 40 minutes apart."""
    p = PROFILES["emma"]
    t = START + timedelta(days=2, hours=10)
    return [_row(t, "emma", p["ip"], p["country"], "login_success"),
            _row(t + timedelta(minutes=40), "emma", "175.41.128.77", "SG", "login_success"),
            _row(t + timedelta(minutes=46), "emma", "175.41.128.77", "SG", "file_download",
                 "/docs/report.pdf", 2_500_000)]


def main(path="data/auth_logs.csv", extended=False):
    rows = normal_traffic() + decoy_traveller() + attack()
    if extended:
        rows += distributed_spray() + lone_brute_force() + forgotten_password() + travel_pair()
    df = pd.DataFrame(rows)
    df = df.sort_values("timestamp").reset_index(drop=True)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    df.to_csv(path, index=False)
    print(f"wrote {len(df)} events -> {path}")


if __name__ == "__main__":
    if "--multi" in sys.argv:
        main("data/auth_logs_multi.csv", extended=True)
    else:
        main()