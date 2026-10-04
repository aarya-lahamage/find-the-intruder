"""Cross-IP correlation and travel checks.

detector.py scores one source IP at a time, so an attacker who spreads a password attack over several
IPs and keeps each one under the per-IP thresholds is not caught there. The functions here look across
IPs. They are rule-based and report the exact log rows (index values of the DataFrame) they used.
"""
from collections import Counter

import pandas as pd


def find_campaigns(df, min_ips=3, min_shared_users=2, max_gap_min=30, alerts=None):
    """Group source IPs that failed logins against the same accounts at about the same time.

    Two IPs are linked when they failed against at least `min_shared_users` common accounts and
    their failure periods overlap or are at most `max_gap_min` minutes apart. Linked IPs form a
    campaign when there are at least `min_ips` of them.
    """
    fails = df[df.event == "login_failed"]
    if fails.empty:
        return []

    prof = {}
    for ip, g in fails.groupby("ip"):
        users = set(g.user)
        if len(users) >= min_shared_users:   # an IP failing on fewer accounts can never be linked
            prof[ip] = {"users": users, "start": g.timestamp.min(), "end": g.timestamp.max(),
                        "n": len(g), "idx": [int(i) for i in g.index], "country": g.country.mode()[0]}
    ips = sorted(prof)
    parent = {ip: ip for ip in ips}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    gap = pd.Timedelta(minutes=max_gap_min)
    for n, a in enumerate(ips):
        for b in ips[n + 1:]:
            pa, pb = prof[a], prof[b]
            if len(pa["users"] & pb["users"]) < min_shared_users:
                continue
            if pa["start"] > pb["end"] + gap or pb["start"] > pa["end"] + gap:
                continue
            parent[find(a)] = find(b)

    groups = {}
    for ip in ips:
        groups.setdefault(find(ip), []).append(ip)

    alerted = {a["ip"] for a in (alerts or []) if a["rule"] in ("brute_force", "password_spray")}
    succ = df[df.event == "login_success"]
    out = []
    for members in groups.values():
        if len(members) < min_ips:
            continue
        members = sorted(members, key=lambda i: prof[i]["start"])
        accounts = set().union(*(prof[i]["users"] for i in members))
        count = Counter(u for i in members for u in prof[i]["users"])
        common = sorted(u for u, c in count.items() if c >= 2)

        successes = []
        for i in members:
            hit = succ[(succ.ip == i) & (succ.timestamp >= prof[i]["start"])]
            for idx, r in hit.iterrows():
                successes.append({"ip": i, "user": r.user, "time": r.timestamp, "row": int(idx),
                                  "targeted": r.user in accounts})
        hits = [s for s in successes if s["targeted"]]

        rows = [{"ip": i, "country": prof[i]["country"], "failures": prof[i]["n"],
                 "accounts": len(prof[i]["users"]), "first": prof[i]["start"], "last": prof[i]["end"],
                 "own_alert": i in alerted} for i in members]
        start = min(prof[i]["start"] for i in members)
        end = max(prof[i]["end"] for i in members)
        countries = sorted({prof[i]["country"] for i in members})
        n_alert = sum(r["own_alert"] for r in rows)

        text = (f"{len(members)} source IPs from {len(countries)} countries failed logins against "
                f"{len(accounts)} accounts between {start:%d %b %H:%M} and {end:%H:%M}. "
                f"{len(common)} account(s) were targeted from more than one IP. "
                f"Highest failure count for a single IP: {max(r['failures'] for r in rows)}.")
        if n_alert == 0:
            text += (" No single IP reached a per-IP brute force or spray threshold, so this pattern is "
                     "only visible when the sources are correlated.")
        else:
            text += f" {n_alert} of these IPs also raised their own brute force or spray alert."
        if hits:
            text += (f" {len(hits)} successful login(s) from these IPs used targeted accounts, so those "
                     f"accounts may be compromised.")

        evidence = sorted({i for m in members for i in prof[m]["idx"]} | {s["row"] for s in hits})
        out.append({"ips": members, "members": rows, "accounts": sorted(accounts), "common": common,
                    "failures": sum(r["failures"] for r in rows), "start": start, "end": end,
                    "countries": countries, "successes": successes,
                    "severity": "high" if hits else "medium", "confidence": "high" if hits else "medium",
                    "summary": text, "evidence": evidence})

    out.sort(key=lambda c: c["start"])
    for n, c in enumerate(out, 1):
        c["id"] = f"CMP-{n:03d}"
    return out


def impossible_travel(df, max_gap_hours=2.0):
    """Successful logins by one user from two different countries within `max_gap_hours`.

    Works on the country recorded in the log only (no distance calculation), so treat results
    as leads for review: a VPN or a shared account can also produce them.
    """
    succ = df[df.event == "login_success"].sort_values("timestamp", kind="stable")
    limit = pd.Timedelta(hours=max_gap_hours)
    out = []
    for user, g in succ.groupby("user"):
        g = g.assign(prev_country=g.country.shift(), prev_ts=g.timestamp.shift(), prev_ip=g.ip.shift(),
                     prev_idx=pd.Series(g.index, index=g.index).shift())
        hit = g[g.prev_ts.notna() & (g.country != g.prev_country) & (g.country != "??")
                & (g.prev_country != "??") & ((g.timestamp - g.prev_ts) <= limit)]
        for idx, r in hit.iterrows():
            out.append({"user": user, "from_country": r.prev_country, "to_country": r.country,
                        "from_ip": r.prev_ip, "to_ip": r.ip, "from_time": r.prev_ts, "to_time": r.timestamp,
                        "gap_min": int((r.timestamp - r.prev_ts).total_seconds() // 60),
                        "evidence": [int(r.prev_idx), int(idx)]})
    out.sort(key=lambda x: x["to_time"])
    return out