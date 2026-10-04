# Find the Intruder

A rule-based SOC triage console for authentication and access logs. It ingests a log, detects attack
patterns, correlates them into incidents, scores risk with a fully itemised breakdown, and shows the exact
log rows behind every finding.

ALGOTHON'26 cybersecurity track. Team: [team name]. Members: [names].

## What it does

1. Ingests a CSV log and reports data quality (rows read, malformed rows dropped, duplicates).
2. Runs 10 detection rules and produces alerts. Each alert carries the exact log rows that triggered it.
3. Scores each source IP from 0 to 100. Every point is listed with the reason it was added.
4. Builds incidents from IPs above the threshold, with a timeline, evidence table, ATT&CK mapping,
   recommended actions, and a story that is labelled as interpretation, separate from observed facts.
5. Correlates across IPs: distributed credential attacks (campaigns) and impossible travel.
6. Lets the analyst investigate by IP or user, search the raw log, replay an attack step by step, and
   export reports (Markdown, JSON, evidence CSV, blocklist CSV).
7. Saves incident status and analyst notes to `data/case_state.json`.

Detection is rule-based. There is no machine learning.

#