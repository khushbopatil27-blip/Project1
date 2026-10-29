#!/usr/bin/env python3
"""
log_analyzer.py - Linux auth-log parsing and user-access validation (proof of concept)

What it does
  1. Parses a Linux auth log (Ubuntu/Debian /var/log/auth.log, classic syslog format).
  2. Extracts security-relevant events into a SQLite database (queryable with SQL). The database
     keeps history between runs (duplicates are ignored) and purges events older than
     --retention-days (default 90), matching the 90-day online retention in the security policy.
  3. Detects suspicious patterns:
       - brute force: >= N failed login attempts from one IP within a time window
       - successful login from an IP that was flagged for brute force
       - root login attempts, sudo failures, account creation / privileged group changes
  4. Optionally validates user access records (CSV export of accounts) against an approved list:
       unapproved accounts, excess privileges, dormant accounts, approved users with no account,
       invalid or future last-login dates.
  5. Writes a summary report (Markdown + JSON) with severities aligned to the escalation matrix.

Exit codes
  0  run completed, no SEV-1/SEV-2 findings
  1  run completed, at least one SEV-1/SEV-2 finding (alert condition)
  2  input error (missing file, bad CSV, bad date, bad option) - nothing was detected or reported
  3  unexpected internal error - nothing was detected or reported

Only the Python 3.8+ standard library is used. The log file is opened read-only. Output files are
created with owner-only permissions (directory 0700, files 0600) because they contain account
names and source addresses.

Example
  python3 log_analyzer.py --log sample_data/auth.log --year 2026 \
      --users sample_data/system_users.csv --approved sample_data/approved_users.csv \
      --today 2026-10-29 --out reports
"""
import argparse
import csv
import hashlib
import json
import os
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

EXIT_OK, EXIT_ALERT, EXIT_INPUT, EXIT_INTERNAL = 0, 1, 2, 3


class InputError(Exception):
    """Bad user input (file, CSV content, date, option). Reported as exit code 2."""


# ---------------------------------------------------------------- parsing ---
LINE_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
PATTERNS = [
    ("failed_login", re.compile(
        r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")),
    ("invalid_user", re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")),
    ("success_login", re.compile(
        r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")),
    ("sudo_command", re.compile(
        r"(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.+)$")),
    ("sudo_failure", re.compile(
        r"(?P<user>\S+)\s*:\s*\d+ incorrect password attempts?")),
    ("user_created", re.compile(r"new user: name=(?P<user>[^,\s]+)")),
    ("group_change", re.compile(
        r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")),
]
# An "Invalid user X from IP" line and the "Failed password for invalid user X from IP" line that
# follows it describe the SAME attempt. The second one is the counted attempt; the first is only
# counted when no matching failure line follows within this many seconds.
INVALID_USER_PAIR_SECONDS = 10


def parse_line(line, year):
    """Return a dict for a relevant event, or None."""
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    try:
        ts_text = re.sub(r"\s+", " ", m.group("ts"))
        ts = datetime.strptime(f"{year} {ts_text}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    msg = m.group("msg")
    for etype, rx in PATTERNS:
        hit = rx.search(msg)
        if hit:
            d = hit.groupdict()
            return {
                "ts": ts, "host": m.group("host"), "type": etype,
                "user": d.get("user"), "ip": d.get("ip"),
                "detail": d.get("cmd") or d.get("group") or d.get("target") or "",
            }
    return None


def parse_log(path, year, reference_now, year_explicit):
    """Parse the log. Returns (events, total_lines).

    Syslog timestamps carry no year. When the year was not given explicitly, a timestamp that would
    lie more than one day in the future is assumed to belong to the previous year (a December log
    read in January). Pass --year to override.
    """
    events, total = [], 0
    seen_lines = Counter()
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError as exc:
        raise InputError(f"cannot read log file {path}: {exc}")
    with fh:
        for line in fh:
            if not line.strip():
                continue
            total += 1
            ev = parse_line(line, year)
            if not ev:
                continue
            if not year_explicit and ev["ts"] > reference_now + timedelta(days=1):
                ev = parse_line(line, year - 1) or ev
            raw = line.strip()
            seen_lines[raw] += 1
            # identical lines within one file get distinct hashes via their occurrence number
            ev["line_hash"] = hashlib.sha256(f"{raw}|{ev['ts'].year}|{seen_lines[raw]}".encode()).hexdigest()
            events.append(ev)
    mark_counted_attempts(events)
    return events, total


def mark_counted_attempts(events):
    """Set ev['counted']=1 for events that represent one real failed attempt, else 0.

    failed_login always counts. invalid_user counts only if no failed_login for the same
    (ip, user) follows within INVALID_USER_PAIR_SECONDS (otherwise it would double-count).
    """
    failures = defaultdict(list)
    for e in events:
        if e["type"] == "failed_login":
            failures[(e["ip"], e["user"])].append(e["ts"])
    window = timedelta(seconds=INVALID_USER_PAIR_SECONDS)
    for e in events:
        if e["type"] == "failed_login":
            e["counted"] = 1
        elif e["type"] == "invalid_user":
            paired = any(timedelta(0) <= t - e["ts"] <= window for t in failures.get((e["ip"], e["user"]), []))
            e["counted"] = 0 if paired else 1
        else:
            e["counted"] = 0


# ---------------------------------------------------------------- SQL ---
SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  line_hash TEXT NOT NULL UNIQUE,
  ts TEXT NOT NULL, host TEXT, type TEXT NOT NULL,
  user TEXT, ip TEXT, detail TEXT,
  counted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_type ON events(type);
CREATE INDEX IF NOT EXISTS idx_ip ON events(ip);
CREATE INDEX IF NOT EXISTS idx_ts ON events(ts);
"""


def open_db(db_path):
    existed = Path(db_path).exists()
    con = sqlite3.connect(db_path)
    if not existed:
        os.chmod(db_path, 0o600)
    con.executescript(SCHEMA)
    return con


def store_events(con, events):
    """Insert events (duplicates from earlier runs are ignored) and remember which belong to this run."""
    con.execute("CREATE TEMP TABLE current_run (line_hash TEXT PRIMARY KEY)")
    con.executemany("INSERT OR IGNORE INTO current_run VALUES (?)", [(e["line_hash"],) for e in events])
    con.executemany(
        "INSERT OR IGNORE INTO events (line_hash, ts, host, type, user, ip, detail, counted) VALUES (?,?,?,?,?,?,?,?)",
        [(e["line_hash"], e["ts"].isoformat(), e["host"], e["type"], e["user"], e["ip"], e["detail"], e["counted"])
         for e in events],
    )
    con.commit()


def purge_old(con, reference_now, retention_days):
    cutoff = (reference_now - timedelta(days=retention_days)).isoformat()
    cur = con.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
    con.commit()
    return cur.rowcount


def sql_summaries(con):
    """Aggregate queries for the report. They cover the log being analysed (this run), not all history."""
    base = "FROM events e JOIN current_run c ON c.line_hash = e.line_hash"
    top_ips = con.execute(
        f"SELECT e.ip, COUNT(*) c {base} WHERE e.counted=1 GROUP BY e.ip ORDER BY c DESC, e.ip LIMIT 5").fetchall()
    top_users = con.execute(
        f"SELECT e.user, COUNT(*) c {base} WHERE e.counted=1 GROUP BY e.user ORDER BY c DESC, e.user LIMIT 5").fetchall()
    by_type = con.execute(
        f"SELECT e.type, COUNT(*) {base} GROUP BY e.type ORDER BY 2 DESC, e.type").fetchall()
    history = con.execute("SELECT COUNT(*), MIN(ts), MAX(ts) FROM events").fetchone()
    return {"top_failed_ips": top_ips, "top_failed_users": top_users, "events_by_type": by_type,
            "history_rows": history[0], "history_from": history[1], "history_to": history[2]}


# ---------------------------------------------------------------- detection ---
def best_burst(times, window):
    """Return (count, first, last) of the densest burst of timestamps inside `window`."""
    times = sorted(times)
    best = (0, None, None)
    start = 0
    for end in range(len(times)):
        while times[end] - times[start] > window:
            start += 1
        count = end - start + 1
        if count > best[0]:
            best = (count, times[start], times[end])
    return best


def detect(events, threshold, window_min):
    findings = []
    window = timedelta(minutes=window_min)

    # 1. Brute force: >= threshold counted failed attempts from one IP inside the window
    attempts = defaultdict(list)
    for e in events:
        if e["counted"] and e["ip"]:
            attempts[e["ip"]].append(e["ts"])
    flagged = {}
    for ip, times in attempts.items():
        count, first, last = best_burst(times, window)
        if count >= threshold:
            flagged[ip] = (count, first, last, len(times))
    for ip, (count, first, last, total) in sorted(flagged.items()):
        secs = int((last - first).total_seconds())
        extra = f" ({total} in the whole log)" if total != count else ""
        findings.append({
            "severity": "SEV-3", "category": "Brute-force attempt",
            "detail": f"{count} failed attempts from {ip} within {secs} s "
                      f"({first:%H:%M:%S}-{last:%H:%M:%S}){extra}",
            "action": "Block IP at firewall / fail2ban; review targeted accounts"})

    # 2. Success after a brute-force burst from the same IP = possible compromise
    for e in events:
        if e["type"] == "success_login" and e["ip"] in flagged:
            first = flagged[e["ip"]][1]
            prior = [t for t in attempts[e["ip"]] if t <= e["ts"]]
            if prior and e["ts"] >= first:
                findings.append({
                    "severity": "SEV-2", "category": "Successful login after brute force",
                    "detail": f"User '{e['user']}' logged in from {e['ip']} at {e['ts']:%Y-%m-%d %H:%M:%S} "
                              f"after {len(prior)} failed attempts",
                    "action": "Disable account, force password reset, isolate host, escalate to Security lead"})

    # 3. Root login attempts
    root_fail = [e for e in events if e["type"] == "failed_login" and e["user"] == "root"]
    if root_fail:
        findings.append({
            "severity": "SEV-4", "category": "Root login attempts",
            "detail": f"{len(root_fail)} failed root logins; ensure PermitRootLogin no",
            "action": "Verify sshd_config hardening"})

    # 4. sudo failures
    for e in events:
        if e["type"] == "sudo_failure":
            findings.append({
                "severity": "SEV-3", "category": "sudo failure",
                "detail": f"User '{e['user']}' had incorrect sudo password attempts at {e['ts']:%H:%M:%S}",
                "action": "Confirm with user; check for account misuse"})

    # 5. Account creation and privileged group changes
    for e in events:
        if e["type"] == "user_created":
            findings.append({
                "severity": "SEV-3", "category": "New account created",
                "detail": f"Account '{e['user']}' created at {e['ts']:%Y-%m-%d %H:%M:%S}",
                "action": "Verify a ticket/approval exists"})
        if e["type"] == "group_change" and e["detail"] in ("sudo", "adm", "root", "wheel"):
            findings.append({
                "severity": "SEV-2", "category": "Privileged group change",
                "detail": f"'{e['user']}' added to group '{e['detail']}' at {e['ts']:%Y-%m-%d %H:%M:%S}",
                "action": "Verify approval; revert if unauthorised"})
    return findings


# ---------------------------------------------------------------- access validation ---
def read_csv(path, required):
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            missing = [c for c in required if c not in (reader.fieldnames or [])]
            if missing:
                raise InputError(f"{path}: missing required column(s): {', '.join(missing)} "
                                 f"(found: {', '.join(reader.fieldnames or []) or 'none'})")
            rows = []
            for n, row in enumerate(reader, start=2):
                if None in row or any(row.get(c) is None for c in required):
                    raise InputError(f"{path}: line {n} has the wrong number of fields")
                rows.append(row)
            return rows
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise InputError(f"cannot read {path}: {exc}")


def validate_access(users_csv, approved_csv, dormant_days, today):
    users = read_csv(users_csv, ["username", "groups", "status", "last_login"])
    approved = {r["username"].strip(): r for r in read_csv(approved_csv, ["username", "allowed_groups"])}
    findings = []
    seen = set()
    for u in users:
        name = u["username"].strip()
        seen.add(name)
        groups = {g.strip() for g in u["groups"].split(";") if g.strip()}
        active = u["status"].strip().lower() == "active"
        if name not in approved:
            findings.append({"severity": "SEV-2" if active else "SEV-4", "category": "Unapproved account",
                             "detail": f"'{name}' exists ({u['status'].strip()}) but is not on the approved list",
                             "action": "Disable and investigate; confirm ticket"})
            continue
        allowed_groups = {g.strip() for g in approved[name]["allowed_groups"].split(";") if g.strip()}
        extra = groups - allowed_groups
        if extra:
            sev = "SEV-2" if extra & {"sudo", "wheel", "Administrators", "root"} else "SEV-3"
            findings.append({"severity": sev, "category": "Excess privileges",
                             "detail": f"'{name}' is in unapproved group(s): {', '.join(sorted(extra))}",
                             "action": "Remove membership or document approved exception"})
        last = u["last_login"].strip()
        if active and last:
            try:
                last_dt = datetime.strptime(last, "%Y-%m-%d")
            except ValueError:
                findings.append({"severity": "SEV-4", "category": "Data quality",
                                 "detail": f"'{name}' has invalid last_login '{last}' (expected YYYY-MM-DD)",
                                 "action": "Fix record"})
                continue
            age = (today - last_dt).days
            if age < 0:
                findings.append({"severity": "SEV-4", "category": "Data quality",
                                 "detail": f"'{name}' has a last_login in the future ({last})",
                                 "action": "Check clock/export; fix record"})
            elif age > dormant_days:
                findings.append({"severity": "SEV-4", "category": "Dormant account",
                                 "detail": f"'{name}' has not logged in for {age} days",
                                 "action": "Disable per quarterly review"})
    for name in approved:
        if name not in seen:
            findings.append({"severity": "SEV-4", "category": "Approved user missing",
                             "detail": f"'{name}' is approved but has no account", "action": "Check onboarding ticket"})
    return findings


# ---------------------------------------------------------------- reporting ---
SEV_ORDER = {"SEV-1": 1, "SEV-2": 2, "SEV-3": 3, "SEV-4": 4}


def build_report(meta, sql, log_findings, access_findings):
    allf = sorted(log_findings + access_findings, key=lambda f: SEV_ORDER[f["severity"]])
    sev_counts = Counter(f["severity"] for f in allf)
    lines = [
        "# Daily Security Log Summary",
        f"_Generated {meta['generated']} - source: `{meta['log']}`_",
        "",
        "## Overview",
        f"- Log lines read: **{meta['total']}**, security events extracted: **{meta['events']}**",
        f"- Event history in database: {sql['history_rows']} rows "
        f"({(sql['history_from'] or '-')[:10]} to {(sql['history_to'] or '-')[:10]}), "
        f"retention {meta['retention_days']} days",
        "- Findings by severity: " + (", ".join(f"{k}: {sev_counts[k]}" for k in sorted(sev_counts, key=SEV_ORDER.get)) or "none"),
        "",
        "## Events by type (this log)",
        "| Type | Count |", "|---|---|",
    ] + [f"| {t} | {c} |" for t, c in sql["events_by_type"]] + [
        "",
        "_`invalid_user` lines are only counted as failed attempts when no matching failed-password line follows._",
        "",
        "## Top sources of failed attempts",
        "| IP | Failed attempts |", "|---|---|",
    ] + [f"| {ip} | {c} |" for ip, c in sql["top_failed_ips"]] + [
        "",
        "## Top targeted usernames",
        "| User | Failed attempts |", "|---|---|",
    ] + [f"| {u} | {c} |" for u, c in sql["top_failed_users"]] + [
        "",
        "## Findings (sorted by severity)",
        "| Severity | Category | Detail | Recommended action |", "|---|---|---|---|",
    ] + [f"| {f['severity']} | {f['category']} | {f['detail']} | {f['action']} |" for f in allf]
    if not allf:
        lines.append("| - | No findings | - | - |")
    lines += ["", "_Severity levels follow the escalation matrix (SEV-1 critical ... SEV-4 low)._"]
    return "\n".join(lines) + "\n", allf, sev_counts


def write_private(path, text):
    """Write a text file readable only by its owner (reports contain account names and IPs)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, 0o600)


def parse_args(argv):
    p = argparse.ArgumentParser(description="Parse Linux auth logs and validate user access records.")
    p.add_argument("--log", required=True, help="path to auth.log")
    p.add_argument("--year", type=int, help="year of log entries (syslog has none; default: current year, "
                   "with automatic previous-year handling for December logs read in January)")
    p.add_argument("--users", help="CSV export of system accounts (username,groups,status,last_login)")
    p.add_argument("--approved", help="CSV of approved users (username,allowed_groups)")
    p.add_argument("--threshold", type=int, default=5, help="failed attempts from one IP to flag (default 5)")
    p.add_argument("--window", type=int, default=10, help="time window in minutes (default 10)")
    p.add_argument("--dormant-days", type=int, default=90, help="days of inactivity to flag (default 90)")
    p.add_argument("--retention-days", type=int, default=90, help="days of event history kept in the database (default 90)")
    p.add_argument("--today", help="reference date YYYY-MM-DD for dormant check and retention (default: now)")
    p.add_argument("--out", default="reports", help="output directory (default ./reports)")
    return p.parse_args(argv)  # argparse itself exits with code 2 on bad options


def run(a):
    log_path = Path(a.log)
    if not log_path.is_file():
        raise InputError(f"log file not found: {log_path}")
    if bool(a.users) != bool(a.approved):
        raise InputError("--users and --approved must be used together")
    for opt, val in (("--threshold", a.threshold), ("--window", a.window),
                     ("--dormant-days", a.dormant_days), ("--retention-days", a.retention_days)):
        if val < 1:
            raise InputError(f"{opt} must be 1 or greater")
    if a.today:
        try:
            now = datetime.strptime(a.today, "%Y-%m-%d")
        except ValueError:
            raise InputError(f"--today must be YYYY-MM-DD, got '{a.today}'")
    else:
        now = datetime.now()
    year_explicit = a.year is not None
    year = a.year if year_explicit else now.year

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(out, 0o700)

    events, total = parse_log(log_path, year, now, year_explicit)
    access_findings = []
    if a.users:
        for f in (a.users, a.approved):
            if not Path(f).is_file():
                raise InputError(f"file not found: {f}")
        access_findings = validate_access(a.users, a.approved, a.dormant_days, now)

    con = open_db(out / "events.db")
    try:
        store_events(con, events)
        sql = sql_summaries(con)
        purged = purge_old(con, now, a.retention_days)
    finally:
        con.close()
    log_findings = detect(events, a.threshold, a.window)

    meta = {"generated": datetime.now().strftime("%Y-%m-%d %H:%M"), "log": str(log_path),
            "total": total, "events": len(events), "retention_days": a.retention_days,
            "purged_rows": purged}
    md, allf, sev_counts = build_report(meta, sql, log_findings, access_findings)
    write_private(out / "summary_report.md", md)
    write_private(out / "summary_report.json",
                  json.dumps({"meta": meta, "severity_counts": sev_counts, "findings": allf}, indent=2))
    os.chmod(out / "events.db", 0o600)

    print(md)
    print(f"Reports written to {out}/ (summary_report.md, summary_report.json, events.db) - owner-only permissions")
    return EXIT_ALERT if (sev_counts.get("SEV-1") or sev_counts.get("SEV-2")) else EXIT_OK


def main(argv=None):
    a = parse_args(argv)
    try:
        return run(a)
    except InputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except Exception as exc:  # never let a crash look like a detected incident (exit 1)
        print(f"INTERNAL ERROR ({type(exc).__name__}): {exc}", file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(main())
