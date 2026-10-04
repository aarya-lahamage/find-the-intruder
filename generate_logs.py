"""Generate a realistic auth/server log with a hidden attacker.

Usage: python generate_logs.py            -> data/auth_logs.csv
"""
import random
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


def main(path="data/auth_logs.csv"):
    df = pd.DataFrame(normal_traffic() + decoy_traveller() + attack())
    df = df.sort_values("timestamp").reset_index(drop=True)
    df.to_csv(path, index=False)
    print(f"wrote {len(df)} events -> {path}")


if __name__ == "__main__":
    main()
