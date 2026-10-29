"""Unit tests for log_analyzer.py. Run from the automation/ folder:

    python3 -m unittest discover -s tests -v

Standard library only.
"""
import contextlib
import io
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import log_analyzer as la  # noqa: E402

HERE = Path(__file__).resolve().parent.parent
SAMPLE = HERE / "sample_data"


def events_from(lines, year=2026):
    path = Path(tempfile.mkdtemp()) / "auth.log"
    path.write_text("\n".join(lines) + "\n")
    evs, total = la.parse_log(path, year, datetime(year, 12, 31), True)
    return evs


def run_main(args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = la.main(args)
    return code, out.getvalue(), err.getvalue()


class InvalidUserDoubleCount(unittest.TestCase):
    def test_invalid_user_pair_is_one_attempt(self):
        evs = events_from([
            "Oct 28 02:00:00 h sshd[1]: Invalid user admin from 203.0.113.9 port 1",
            "Oct 28 02:00:02 h sshd[1]: Failed password for invalid user admin from 203.0.113.9 port 1 ssh2",
            "Oct 28 02:00:10 h sshd[2]: Invalid user test from 203.0.113.9 port 2",
            "Oct 28 02:00:12 h sshd[2]: Failed password for invalid user test from 203.0.113.9 port 2 ssh2",
            "Oct 28 02:00:20 h sshd[3]: Invalid user oracle from 203.0.113.9 port 3",
            "Oct 28 02:00:22 h sshd[3]: Failed password for invalid user oracle from 203.0.113.9 port 3 ssh2",
        ])
        self.assertEqual(sum(e["counted"] for e in evs), 3)  # 3 real attempts, not 6
        self.assertEqual(la.detect(evs, threshold=5, window_min=10), [])  # no false brute-force alert

    def test_lone_invalid_user_line_still_counts(self):
        evs = events_from(["Oct 28 02:00:00 h sshd[1]: Invalid user admin from 203.0.113.9 port 1"])
        self.assertEqual(sum(e["counted"] for e in evs), 1)


class BruteForceReporting(unittest.TestCase):
    def test_reports_burst_not_whole_file(self):
        lines = [f"Oct 28 01:00:0{i} h sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2" for i in range(5)]
        lines += ["Oct 28 11:00:00 h sshd[9]: Failed password for root from 203.0.113.5 port 1 ssh2",
                  "Oct 28 11:00:01 h sshd[9]: Failed password for root from 203.0.113.5 port 1 ssh2"]
        f = [x for x in la.detect(events_from(lines), 5, 10) if x["category"] == "Brute-force attempt"]
        self.assertEqual(len(f), 1)
        self.assertIn("5 failed attempts", f[0]["detail"])
        self.assertIn("within 4 s", f[0]["detail"])
        self.assertIn("01:00:00-01:00:04", f[0]["detail"])
        self.assertIn("7 in the whole log", f[0]["detail"])

    def test_below_threshold_not_flagged(self):
        lines = [f"Oct 28 01:00:0{i} h sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2" for i in range(4)]
        self.assertEqual([x for x in la.detect(events_from(lines), 5, 10) if x["category"] == "Brute-force attempt"], [])

    def test_slow_attempts_outside_window_not_flagged(self):
        lines = [f"Oct 28 0{i}:00:00 h sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2" for i in range(6)]
        self.assertEqual([x for x in la.detect(events_from(lines), 5, 10) if x["category"] == "Brute-force attempt"], [])


class YearHandling(unittest.TestCase):
    def test_december_log_read_in_january_uses_previous_year(self):
        path = Path(tempfile.mkdtemp()) / "auth.log"
        path.write_text("Dec 31 23:59:00 h sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2\n")
        evs, _ = la.parse_log(path, 2027, datetime(2027, 1, 2), False)
        self.assertEqual(evs[0]["ts"].year, 2026)

    def test_explicit_year_is_respected(self):
        path = Path(tempfile.mkdtemp()) / "auth.log"
        path.write_text("Dec 31 23:59:00 h sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2\n")
        evs, _ = la.parse_log(path, 2027, datetime(2027, 1, 2), True)
        self.assertEqual(evs[0]["ts"].year, 2027)


class AccessValidation(unittest.TestCase):
    def _csvs(self, users, approved):
        d = Path(tempfile.mkdtemp())
        (d / "u.csv").write_text(users)
        (d / "a.csv").write_text(approved)
        return str(d / "u.csv"), str(d / "a.csv")

    def test_future_login_date_is_flagged(self):
        u, a = self._csvs("username,groups,status,last_login\nalice,dev,active,2030-01-01\n",
                          "username,allowed_groups\nalice,dev\n")
        f = la.validate_access(u, a, 90, datetime(2026, 10, 29))
        self.assertTrue(any("future" in x["detail"] for x in f))

    def test_missing_column_is_input_error(self):
        u, a = self._csvs("username,groups\nalice,dev\n", "username,allowed_groups\nalice,dev\n")
        with self.assertRaises(la.InputError):
            la.validate_access(u, a, 90, datetime(2026, 10, 29))

    def test_unapproved_and_excess_privileges(self):
        u, a = self._csvs("username,groups,status,last_login\nbob,dev;sudo,active,2026-10-28\nmal,dev,active,2026-10-28\n",
                          "username,allowed_groups\nbob,dev\n")
        cats = {x["category"] for x in la.validate_access(u, a, 90, datetime(2026, 10, 29))}
        self.assertIn("Excess privileges", cats)
        self.assertIn("Unapproved account", cats)


class ExitCodesAndOutput(unittest.TestCase):
    def test_sample_run_gives_alert_exit_and_expected_counts(self):
        out = tempfile.mkdtemp()
        code, stdout, _ = run_main(["--log", str(SAMPLE / "auth.log"), "--year", "2026",
                                    "--users", str(SAMPLE / "system_users.csv"),
                                    "--approved", str(SAMPLE / "approved_users.csv"),
                                    "--today", "2026-10-29", "--out", out + "/r"])
        self.assertEqual(code, la.EXIT_ALERT)
        self.assertIn("6 failed attempts from 203.0.113.45", stdout)

    def test_clean_log_exits_zero(self):
        d = Path(tempfile.mkdtemp())
        (d / "auth.log").write_text("Oct 28 08:02:11 h sshd[1]: Accepted publickey for alice from 198.51.100.10 port 1 ssh2\n")
        code, _, _ = run_main(["--log", str(d / "auth.log"), "--year", "2026", "--today", "2026-10-29", "--out", str(d / "r")])
        self.assertEqual(code, la.EXIT_OK)

    def test_missing_log_is_input_error_not_alert(self):
        code, _, err = run_main(["--log", "/nonexistent/auth.log"])
        self.assertEqual(code, la.EXIT_INPUT)
        self.assertIn("not found", err)

    def test_bad_date_is_input_error_not_alert(self):
        code, _, err = run_main(["--log", str(SAMPLE / "auth.log"), "--today", "29-10-2026", "--out", tempfile.mkdtemp() + "/r"])
        self.assertEqual(code, la.EXIT_INPUT)
        self.assertIn("YYYY-MM-DD", err)

    def test_bad_csv_is_input_error_not_alert(self):
        d = Path(tempfile.mkdtemp())
        (d / "u.csv").write_text("name,grp\nalice,dev\n")
        (d / "a.csv").write_text("username,allowed_groups\nalice,dev\n")
        code, _, err = run_main(["--log", str(SAMPLE / "auth.log"), "--users", str(d / "u.csv"), "--approved", str(d / "a.csv"),
                                 "--out", str(d / "r")])
        self.assertEqual(code, la.EXIT_INPUT)
        self.assertIn("missing required column", err)

    def test_unexpected_crash_is_internal_error_not_alert(self):
        original = la.run
        la.run = lambda a: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            code, _, err = run_main(["--log", str(SAMPLE / "auth.log")])
        finally:
            la.run = original
        self.assertEqual(code, la.EXIT_INTERNAL)
        self.assertIn("INTERNAL ERROR", err)

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_outputs_are_owner_only(self):
        out = Path(tempfile.mkdtemp()) / "r"
        run_main(["--log", str(SAMPLE / "auth.log"), "--year", "2026", "--today", "2026-10-29", "--out", str(out)])
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)
        for name in ("summary_report.md", "summary_report.json", "events.db"):
            self.assertEqual(stat.S_IMODE((out / name).stat().st_mode), 0o600, name)


class HistoryAndRetention(unittest.TestCase):
    def test_history_kept_without_duplicates_and_old_rows_purged(self):
        d = Path(tempfile.mkdtemp())
        args = ["--log", str(SAMPLE / "auth.log"), "--year", "2026", "--today", "2026-10-29", "--out", str(d / "r")]
        run_main(args)
        run_main(args)  # same log again: no duplicate rows
        db = sqlite3.connect(d / "r" / "events.db")
        first = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        db.close()
        self.assertEqual(first, 18)
        # a later run far in the future purges events older than the retention window
        (d / "empty.log").write_text("Mar 01 08:00:00 h sshd[1]: Accepted publickey for alice from 198.51.100.10 port 1 ssh2\n")
        run_main(["--log", str(d / "empty.log"), "--year", "2027", "--today", "2027-03-01", "--out", str(d / "r")])
        db = sqlite3.connect(d / "r" / "events.db")
        remaining = db.execute("SELECT COUNT(*) FROM events WHERE ts < '2027-01-01'").fetchone()[0]
        db.close()
        self.assertEqual(remaining, 0)  # Oct 2026 events are older than 90 days at 2027-03-01


if __name__ == "__main__":
    unittest.main()
