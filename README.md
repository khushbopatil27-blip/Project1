# Secure & Automated IT Operations Workflow - Submission Package (v1.1)

| File | Deliverable |
|---|---|
| `Executive_Summary_Project_Proposal.pdf` | Executive summary & project proposal (3 pages): scope, risks/compliance, KPIs with baselines |
| `01_Project_Roadmap.pdf` (`.md` source) | Project charter, 4-week plan with owners, float, closure criteria, team coordination strategy |
| `02_Security_Awareness_and_Baseline_Policy.pdf` (`.md`) | Security awareness guide, Linux (Ubuntu/Kali) and Windows baseline policy, audit schedule |
| `03_Troubleshooting_and_Escalation_Matrix.pdf` (`.md`) | Ticket and security-incident workflow maps, SLAs, severity/escalation matrix, RACI |
| `diagrams/` | Workflow diagram sources (`.dot`) and images (`.png`) |
| `automation/` | Python/SQL log-analysis proof of concept: script, `README.md` (run instructions), unit tests, sample data, sample output |
| `Review_Response.md` | How each finding of the independent review was addressed |

## Quick run
```bash
cd automation
python3 log_analyzer.py --log sample_data/auth.log --year 2026 --users sample_data/system_users.csv --approved sample_data/approved_users.csv --today 2026-10-29 --out reports
python3 -m unittest discover -s tests -v      # 18 tests
```
Exit code 1 on the sample data is expected (SEV-1/SEV-2 findings present); 2 = input error; 3 = internal error. See `automation/README.md`.

## Version control
This package is a Git repository (`git log`). To publish it, create an empty repository on GitHub and run `git remote add origin <url> && git push -u origin main --tags`.
