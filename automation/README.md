# Log Analyzer - Automation Proof of Concept

A small, dependency-free Python tool that supports the secure IT operations workflow. It:

1. **Parses** a Linux auth log (`/var/log/auth.log`, Ubuntu/Debian/Kali syslog format).
2. **Stores** security events in a SQLite database (`events.db`) and summarises them with **SQL** queries. History is kept between runs (duplicates ignored) and events older than 90 days are purged, matching the 90-day retention in the security policy.
3. **Detects** suspicious activity: brute-force bursts, successful login after a burst, root login attempts, sudo failures, new accounts and privileged-group changes.
4. **Validates user access records** (a CSV export of accounts) against an approved-user list: unapproved accounts, excess privileges, dormant accounts (90 days), approved users with no account, invalid or future login dates.
5. **Reports** a Markdown and JSON summary with severities (SEV-1 to SEV-4) that match the escalation matrix.

**Scope:** Linux auth logs only. Windows Event Log parsing is not part of this proof of concept (Phase 2 backlog); Windows hosts are covered by the baseline checklist and manual Event Viewer review.

## Requirements
- Python 3.8 or newer (tested on 3.11 and 3.13). Standard library only - nothing to install.
- Read access to the log file. The script opens it read-only and **does not need root** (see below).

## Quick start (demo with included sample data)
```bash
cd automation
python3 log_analyzer.py \
  --log sample_data/auth.log --year 2026 \
  --users sample_data/system_users.csv \
  --approved sample_data/approved_users.csv \
  --today 2026-10-29 \
  --out reports
```
Output: report printed to the screen, plus `reports/summary_report.md`, `reports/summary_report.json` and `reports/events.db`. Output files are created owner-only (folder 0700, files 0600) because they contain account names and IP addresses. A copy of the expected report is in `sample_output/`.

### Expected output (first lines, sample data)
```
# Daily Security Log Summary
- Log lines read: **19**, security events extracted: **18**
- Findings by severity: SEV-2: 5, SEV-3: 3, SEV-4: 3
...
| SEV-3 | Brute-force attempt | 6 failed attempts from 203.0.113.45 within 17 s (02:14:01-02:14:18) | Block IP at firewall / fail2ban; review targeted accounts |
```
The report time stamp differs on every run; everything else is reproducible with `--today 2026-10-29`.

## Exit codes
| Code | Meaning | What to do |
|---|---|---|
| 0 | Run completed, no SEV-1/SEV-2 finding | Nothing |
| 1 | Run completed, at least one SEV-1/SEV-2 finding | **Alert:** review the report the same day (escalation matrix) |
| 2 | Input error (missing file, bad CSV column, bad date or option) | Fix the input; no detection was performed |
| 3 | Unexpected internal error | Report to the script owner with the message printed on stderr |

A crash or bad input therefore never looks like a detected incident.

## Run on a real system (without root)
`/var/log/auth.log` is readable by the `adm` group on Ubuntu. Create a dedicated unprivileged account and run the script as that user:
```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin loganalyzer
sudo usermod -aG adm loganalyzer          # read access to /var/log/auth.log, nothing more
sudo -u loganalyzer python3 /opt/log_analyzer/log_analyzer.py \
     --log /var/log/auth.log --out /home/loganalyzer/reports
```
Never run the parser as root: it only reads a log, so it does not need the privilege (least-privilege policy L5). Add `--users` and `--approved` to also validate access records.

## Input formats
`system_users.csv` (export from the host or directory):
```
username,groups,status,last_login
alice,sudo;developers,active,2026-10-28
```
`approved_users.csv` (owned by the access-review process):
```
username,allowed_groups
alice,sudo;developers
```
Groups are separated by `;`. Dates use `YYYY-MM-DD`. All four (respectively two) columns are required; a missing column is reported as an input error (exit 2).

Quick way to build `system_users.csv` on Linux (example, run with normal rights):
```bash
echo "username,groups,status,last_login" > system_users.csv
for u in $(awk -F: '$3>=1000 && $3<65000 {print $1}' /etc/passwd); do
  echo "$u,$(id -nG "$u" | tr ' ' ';'),active," >> system_users.csv
done
```
This fills username, groups and status; it leaves `last_login` empty because `lastlog` output varies between systems. **An empty `last_login` skips the dormant-account check for that user**; fill the column from your directory service or `last -F` if you want that check.

## Options
| Option | Default | Meaning |
|---|---|---|
| `--log` | required | path to auth log |
| `--year` | current year | syslog lines have no year. If omitted, a timestamp more than one day in the future is read as the previous year (December log read in January). Pass `--year` to override. |
| `--users`, `--approved` | none | enable access validation (use both together) |
| `--threshold` | 5 | failed attempts from one IP that count as brute force |
| `--window` | 10 | time window in minutes for the threshold |
| `--dormant-days` | 90 | days without login before an account is flagged |
| `--retention-days` | 90 | days of event history kept in the database |
| `--today` | now | reference date for dormant check, year handling and retention (reproducible demos) |
| `--out` | `reports` | output directory |

## How failed attempts are counted
OpenSSH writes two lines for one attempt against a non-existent user: `Invalid user admin from ...` and `Failed password for invalid user admin from ...`. The analyzer counts that as **one** attempt (the failed-password line); an `Invalid user` line is counted only when no matching failure follows within 10 seconds. The brute-force finding reports the densest burst (count, duration and times) and, if different, the total for the whole log.

## Example SQL on the generated database
```bash
sqlite3 reports/events.db "SELECT ip, COUNT(*) FROM events WHERE counted=1 GROUP BY ip ORDER BY 2 DESC;"
sqlite3 reports/events.db "SELECT ts, user, ip FROM events WHERE type='success_login' ORDER BY ts;"
```
`counted=1` marks events that represent one real failed attempt.

## Tests
```bash
cd automation
python3 -m unittest discover -s tests -v
```
18 tests cover: the invalid-user double count, burst reporting, year rollover, access validation (including bad CSV and future dates), exit codes for bad input and crashes, owner-only file permissions, and history/retention.

## Schedule daily (Linux cron, as the `loganalyzer` user)
```
15 6 * * * python3 /opt/log_analyzer/log_analyzer.py --log /var/log/auth.log --users /opt/exports/users.csv --approved /opt/exports/approved.csv --out /home/loganalyzer/reports >> /home/loganalyzer/run.log 2>&1
```
Check the exit code in your scheduler or wrapper: 1 means "review today", 2 and 3 mean the run failed. On Windows, automated parsing is not provided in this proof of concept.

## Troubleshooting
| Symptom | Likely cause | Fix |
|---|---|---|
| `ERROR: log file not found` (exit 2) | wrong path | check `--log` |
| `Permission denied` / `cannot read log file` (exit 2) | user not in group `adm` | `sudo usermod -aG adm loganalyzer`, log in again |
| `ERROR: ... missing required column(s)` (exit 2) | CSV header differs | use the exact headers shown above |
| `ERROR: --today must be YYYY-MM-DD` (exit 2) | wrong date format | e.g. `--today 2026-10-29` |
| 0 events extracted | log is not Debian/Ubuntu syslog format (e.g. RHEL `/var/log/secure`), or rotated/gzipped | unzip first; RHEL lines are similar but may need pattern changes |
| Dates in the wrong year | `--year` missing on an old log | pass `--year` |
| `INTERNAL ERROR` (exit 3) | unexpected bug or unreadable file content | send the message to the script owner |

## What the sample data demonstrates
- IP `203.0.113.45` makes 6 failed attempts in 17 seconds, then logs in as `ubuntu` -> SEV-3 burst and SEV-2 "successful login after brute force".
- `tempsvc` is created and added to `sudo`, and is not on the approved list -> SEV-2/SEV-3.
- `bob` is in `sudo` but only approved for `developers` -> SEV-2 excess privileges.
- `dave` inactive 150 days; `erin` approved but has no account -> SEV-4 housekeeping.

(All IPs use documentation ranges reserved for examples; all names are fictional.)

## How it works (short)
`parse_log` matches lines with a syslog regular expression and event patterns -> `store_events` loads them into SQLite (history + retention) -> `sql_summaries` runs aggregate queries for the current log -> `detect` applies rules (densest-burst search for brute force) -> `validate_access` compares account data with the approved list -> `build_report` writes the results with owner-only permissions.

## Limitations and next steps
- Only the Debian/Ubuntu `auth.log` format is parsed; rotated (`.gz`) files must be unzipped first.
- IPv6 addresses are parsed by a simple pattern.
- Windows Event Log (4624/4625/4720/4732) parsing, email/Slack alerting and a dashboard are Phase 2 items.
- Findings are indicators for human review, not proof of compromise.
