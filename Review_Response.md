# Response to Independent Review (29 Oct 2026)

| ID | Finding | Action taken | Where |
|---|---|---|---|
| F-22 | No repo link / archive / history | Package is a Git repository with tagged commit `v1.1` and is delivered as a ZIP. A GitHub URL needs the owner's account: push instructions are in `README.md`. | repo, `README.md` |
| F-11 | Invalid-user lines counted twice | Invalid-user + failed-password for one attempt now counts once (`counted` flag); lone invalid-user lines still count | `log_analyzer.py`, test `InvalidUserDoubleCount` |
| F-12 | Crashes exit with alert code | Exit codes 0 / 1 alert / 2 input error / 3 internal error; bad CSV, date, missing file handled | `log_analyzer.py`, tests `ExitCodesAndOutput` |
| F-13 | Root prescribed | README runs as unprivileged `loganalyzer` user in group `adm` | `automation/README.md` |
| F-23 | Roadmap only Markdown | Roadmap, policy and matrix delivered as PDF (Markdown kept as source) | `01_`-`03_*.pdf` |
| F-14 | Whole-file count/span reported | Reports densest burst (count, seconds, times) plus whole-log total | `detect()`, test `BruteForceReporting` |
| F-15 | World-readable reports; PDF claim | Folder 0700, files 0600; PDF/policy describe this accurately | `log_analyzer.py`, test `test_outputs_are_owner_only` |
| F-16 | Table cleared every run | History kept, duplicates ignored, 90-day purge (`--retention-days`) | `store_events`, `purge_old`, test `HistoryAndRetention` |
| F-19 | KPIs without baseline/cadence | Every KPI has baseline source + date, target, review frequency; review cadence stated | PDF section 6, roadmap section 4 |
| F-01 | Tasks owned by "All" | Single named owners; reviewers/participants named separately | Roadmap |
| F-02 / F-07 | Success defined twice; no scoring method | One definition: compliance % = hosts passing all Critical/High controls / in-scope hosts; Critical/High list given | Roadmap, policy B4, PDF |
| F-08 | No assignment step/owner field | Step 3 "Assign owner, start SLA clock"; required ticket fields incl. owner and SLA due time | Escalation matrix |
| F-20 | Phishing baseline unscheduled | Baseline simulation Day 11, follow-up Day 19 | Roadmap, policy, PDF |
| F-24 | Working files in deliverable | Package contains only deliverables (no tool folders, caches or database); sample output kept as text | zip contents |
| F-04 / F-06 | MFA, password history absent from checklists | Added L12, W11; password history in L6 and W3 | Policy B2/B3 |
| F-10 | SEV-3 threshold had no window | Matrix: 5 failed attempts from one IP within 10 minutes | Escalation matrix |
| F-17 | No tests | 18 unit tests | `automation/tests/` |
| F-03 | No float | Critical path and ~2 days float stated | Roadmap |
| F-05 | Log forwarding / custody undefined | Central log host decision (Week 1), custody, checksums defined | Policy B6, roadmap |
| F-09 | Closure criteria missing | Ticket closure criteria and project closure criteria | Matrix, roadmap section 5 |
| F-18 | Future dates ignored; year rollover | Future `last_login` flagged; previous-year inference and `--year` override documented and tested | `log_analyzer.py`, README |
| F-21 | Stray quotation mark in KPI table | KPI table rebuilt; no stray characters found in extracted text | PDF |
| F-25 | README lacks troubleshooting/output | Added expected output, exit codes, troubleshooting table | `automation/README.md` |
| Mismatch: Windows automation | Roadmap said Task Scheduler | Scope clarified everywhere: Linux automation only; Windows by checklist + manual Event Viewer; Windows parsing = Phase 2 | Roadmap, PDF, README |
| Mismatch: dormancy | Policy had no threshold | 90 days in policy, same as tool | Policy B1 |
| Mismatch: retention | DB held one run | Retention implemented | see F-16 |

Not changed: Windows Event Log parsing was not implemented (declared out of scope instead); behaviour on rotated/RHEL logs remains untested.
