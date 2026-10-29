# Project Management & Leadership Roadmap

*Secure & Automated IT Operations Workflow - version 1.1 (revised after independent review)*

## 1. Project Charter

| Item | Detail |
|---|---|
| Project name | Secure & Automated IT Operations Workflow |
| Sponsor | IT Operations Manager / Head of IT |
| Project lead | IT Project Lead |
| Stakeholders | Sponsor (approves baseline, closure); Security lead (policy, incidents); Sysadmin (hosts, automation); Service desk (tickets, users); end users (affected by hardening changes) |
| Duration | 4 weeks (20 working days) |
| Team | Onboarded IT team members (service desk, sysadmin, junior security) |
| Purpose | Improve daily IT operations, system documentation and task tracking; establish a secure baseline for Linux (Kali/Ubuntu) and Windows; deliver an automated log-monitoring proof of concept for Linux hosts. |

**Objectives**
1. Standardize daily IT operations through a shared task board, runbooks and a ticket workflow with named owners.
2. Publish and apply a security baseline for Linux and Windows hosts.
3. Deploy a proof-of-concept Python log-parsing and access-validation pipeline on Linux hosts that produces a daily summary report.
4. Establish measurable KPIs (each with a baseline, target, method and review frequency) and a reporting cadence.

**In scope:** workflow design, documentation, baseline policies, Linux log-parsing automation, team training, KPI tracking.
**Out of scope:** procurement of a full SIEM, network redesign, production changes without change approval, **automated log parsing for Windows** (Windows hosts are covered by the baseline checklist audit and manual Event Viewer review of IDs 4624/4625/4720/4732 in this project; automated Windows Event Log parsing is a Phase 2 backlog item).

**Success criteria (single definition used in every document):**
- *Baseline compliance* = in-scope hosts that pass all Critical and High controls of the baseline checklist, divided by all in-scope hosts. Hosts with a documented, approved, time-limited exception are reported separately and not counted as passing. **Target: >= 90% at Week 4** (>= 95% after phase 2).
- All four objectives delivered by end of Week 4, every team member trained, and the closure criteria in section 5 met.

## 2. Four-Week Implementation Plan

### Week 1 - Discovery & Foundations
| Day | Activity | Owner | Output |
|---|---|---|---|
| 1 | Kick-off, goals, roles, tool access | Project lead | Charter signed off |
| 1-2 | Asset & system inventory (hosts, OS, owners); define in-scope host list | Sysadmin | Inventory sheet |
| 2-3 | Set up task board (Backlog / Doing / Blocked / Review / Done) and ticket categories, fields and SLAs | Project lead (board); Service desk lead (ticket fields) | Live board |
| 3-4 | Documentation standard: runbook template, naming, version control (Git/wiki) | Project lead (author); Sysadmin (reviewer) | Doc template |
| 3-5 | Capture KPI baselines (30-day ticket export, current account and host status) | Service desk lead (tickets); Sysadmin (hosts, accounts) | Baseline sheet |
| 5 | Sponsor decision: designate the central log host and archive custodian (policy B6) | Sponsor | Decision recorded |
| 5 | Week 1 review, risk register v1 | Project lead | Risk register |

### Week 2 - Security Baseline & Process Design
| Day | Activity | Owner | Output |
|---|---|---|---|
| 6-7 | Draft hardening baselines (Linux & Windows) | Security lead (Linux, policy); Sysadmin (Windows) | Baseline policy v1 |
| 7-8 | Define troubleshooting and incident escalation matrix | Project lead + Security lead | Escalation matrix |
| 8-9 | Security awareness guide drafted and peer-reviewed | Security lead (author); Service desk lead (reviewer) | Awareness guide |
| 10 | Review with sponsor; approve baseline | Sponsor | Approval (milestone M2) |

### Week 3 - Implementation & Automation
| Day | Activity | Owner | Output |
|---|---|---|---|
| 11 | **Baseline phishing simulation** (before training, to set the awareness baseline) | Security lead | Click/report rates |
| 11-12 | Baseline audit on pilot hosts (2 Linux, 2 Windows) | Sysadmin | Audit findings |
| 12-14 | Deploy log-parsing script on the 2 Linux pilot hosts (cron, non-root service account); Windows pilots reviewed manually in Event Viewer | Sysadmin | Daily report (Linux) |
| 14 | Validate user access records against the approved list | Security lead | Access exceptions list |
| 15 | Awareness training session (60 min) + quiz | Security lead | Attendance log, quiz scores |

### Week 4 - Rollout, Measurement & Handover
| Day | Activity | Owner | Output |
|---|---|---|---|
| 16-17 | Extend baseline audit to all in-scope hosts; deploy script on all Linux hosts | Sysadmin | Coverage report |
| 18 | Tabletop exercise: simulated brute-force incident run through the escalation matrix | Security lead (facilitator); Service desk lead, Sysadmin, IT Ops Manager (participants) | Lessons learned |
| 19 | Follow-up phishing simulation; KPI baseline-vs-actual review | Security lead (simulation); Project lead (KPI report) | KPI report |
| 20 | Final presentation, retrospective, handover and Phase 2 backlog | Project lead | Closure report |

### Milestones
| Milestone | Date | Gate |
|---|---|---|
| M1 Foundations ready | End Week 1 | Board, inventory, templates, KPI baselines live |
| M2 Baseline approved | Day 10 | Sponsor sign-off |
| M3 Pilot automation live | End Week 3 | Daily report generated on Linux pilot hosts; training delivered |
| M4 Closure | End Week 4 | KPI report and handover accepted by sponsor |

### Critical path and schedule float
- **Critical path:** inventory (Day 1-2) -> baseline draft (Day 6-7) -> sponsor approval (Day 10) -> pilot audit (Day 11-12) -> rollout (Day 16-17) -> KPI report (Day 19).
- **Float:** the afternoons of Day 13 and Day 14 (pilot automation is planned for 1.5 days of effort over 3), the afternoon of Day 17, and the morning of Day 20 - about 2 working days in total.
- **If approval slips more than 1 day:** roll out Linux hosts first and move the Windows audit beyond the pilot hosts to the Phase 2 backlog; report this to the sponsor at the Day 15 review rather than extending the schedule.

## 3. Team Coordination Strategy

### Task Delegation
- **Ownership:** every task has exactly one named owner and a due date on the board; helpers and reviewers are named separately and never replace the owner.
- **Matching:** assign by skill and growth need: new members pair with a buddy for their first two weeks.
- **Definition of done:** output documented, peer-reviewed by one other member, linked on the board.
- **WIP limit:** max 3 items "Doing" per person to avoid overload.
- **Priority rule:** P1 security / outage > P2 blocked users > P3 planned project work > P4 improvements.

### Daily Sync Protocol (15 minutes, same time daily)
1. Yesterday: what was completed (one sentence each).
2. Today: top 1-3 tasks.
3. Blockers: raised immediately; resolved offline, not in the stand-up.
4. Security / incident watch: any alerts or anomalies from the daily log report (the exit-code-1 alert of the script means SEV-1/SEV-2 findings need review the same day).

Async fallback: written update in the team channel by a fixed time for anyone absent. Weekly (Friday, 30 minutes): review of KPIs, risks and the board. Decisions and actions are recorded in a shared log.

### Escalation Procedure (project/work blockers)
| Level | Trigger | Who | Time limit |
|---|---|---|---|
| L0 | Task blocked | Owner tries to resolve, asks buddy | 2 hours |
| L1 | Still blocked | Project lead | Same day |
| L2 | Cross-team / resource issue or schedule risk > 2 days | IT Operations Manager | 1 business day |
| L3 | Security incident, data exposure, major outage | Security lead + Sponsor immediately | Immediate |

### Communication Rules
- Single source of truth: the task board and wiki; no decisions only in private chats.
- Use ticket IDs in every message about an issue.
- Urgent issues by phone/call, not just chat.
- Blameless retrospectives: focus on process, not people.

## 4. KPI Review Cadence
KPIs are defined with baseline, target, method and frequency in the executive proposal (section 6). Baselines are captured in Week 1 (Day 3-5); progress is reviewed weekly at the Friday review, reported to the sponsor at the Day 15 checkpoint and in the Day 19 KPI report, and afterwards monthly by the run owner.

## 5. Project Closure Criteria
The sponsor closes the project when all of the following are true:
1. Milestones M1-M4 are delivered and the documents are published in the wiki/repository under version control.
2. The Day 19 KPI report shows baseline versus actual for every KPI, and any missed target has a named owner and plan.
3. Baseline compliance is at or above target, or each non-compliant host has an approved exception with an expiry date.
4. All SEV-1/SEV-2 findings from the pilot and rollout audits are closed or have an owner and due date.
5. Every team member has completed training (attendance logged) and used the escalation process in the tabletop exercise.
6. The daily log report runs on all in-scope Linux hosts and a run owner is named.
7. A Phase 2 backlog exists (Windows Event Log parsing, central log collection, alerting, SIEM evaluation).
