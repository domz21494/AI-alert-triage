# AI Security Alert Triage Pipeline

> **Problem:** Security teams receive thousands of log alerts a day, most of them false positives. Analysts burn out and real attacks get missed.
>
> **Solution:** A pipeline that ingests Linux logs, detects threats with rules + ML, triages each alert with a local LLM agent grounded in MITRE ATT&CK, and automates the response.
>
> **Results:** _(filled in from `make eval` — see Results below)_

## Architecture

```
INGEST → NORMALIZE → DETECT (rules + ML) → CORRELATE & SCORE → LLM TRIAGE (RAG: ATT&CK) → RESPOND
                                                                                   ↓
                                                         MEASURE (metrics, evals in CI)
```

## Results

Held-out test set: 72 hours of simulated auth.log for one server (7,188 lines), 35 injected
attack incidents across 7 attack types, plus benign look-alikes (forgotten passwords, admin
root shells, onboarding) and background internet scanning. Rules were tuned only on a separate
dev set (different seed). Reproduce with `make eval`. Full report: [`results/baseline_rules.md`](results/baseline_rules.md).

| Metric | Rules only | Rules + ML | Full pipeline |
|---|---|---|---|
| Attack incidents detected | **30/35 (86%)** | – | – |
| Alert precision | **94%** (4 false alarms / 3 days) | – | – |
| Alert reduction (log lines → alerts) | **99.0%** (7,188 → 72) | – | – |
| Median time to detect | **18 s** | – | – |
| Low-and-slow brute force detected | **0/5** (blind spot) | – | – |
| Detection throughput | ~100k events/s | – | – |

**What the baseline shows:** threshold rules catch loud attacks within seconds, but an attacker
who guesses one password every 4–10 minutes stays under every threshold. That gap is what the
ML stage has to close — without adding false alarms.

### Detection rules

15 rules in [`src/alerttriage/detect/rules/`](src/alerttriage/detect/rules/), each mapped to MITRE ATT&CK:
brute force (T1110.001), password spraying (T1110.003), distributed brute force, success-after-failures,
recon (T1595), local account creation (T1136.001), sudo root shell (T1548.003), /etc/shadow access
(T1003.008), download-and-execute (T1105), SSH key persistence (T1098.004), cron (T1053.003),
SUID bit (T1548.001), log tampering (T1070.002), sudo guessing, root SSH login (T1078.003).

## Quickstart

```bash
pip install -e ".[dev]"
make test
alerttriage parse tests/fixtures/auth_sample.log --year 2026   # normalize a log
make eval                                                     # simulate data + score rules
alerttriage detect data/sim/test.log --year 2026 | head -3    # raw alerts as JSON
```

## Roadmap
- [x] Week 1a: repo scaffold, common event schema, auth.log parser, CI
- [x] Week 1b: rule engine (15 ATT&CK-mapped rules), labeled simulator, evaluation, baseline
- [ ] Week 1c: Docker attack lab (real sshd + attacker container)
- [ ] Week 2: ML detection (IsolationForest, PyTorch autoencoder, MLflow), correlation & scoring
- [ ] Week 3: local LLM triage agent (Ollama) + ATT&CK RAG, eval suite in CI, response actions
- [ ] Week 4: FastAPI, dashboard, load test, final results
- [ ] Later: Terraform + AWS deployment
