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

| Metric | Rules only | Rules + ML | Full pipeline |
|---|---|---|---|
| Precision | – | – | – |
| Recall | – | – | – |
| F1 | – | – | – |
| Alert reduction | – | – | – |
| p95 latency | – | – | – |

## Quickstart

```bash
pip install -e ".[dev]"
make test
alerttriage parse tests/fixtures/auth_sample.log --year 2026
```

## Roadmap
- [x] Week 1a: repo scaffold, common event schema, auth.log parser, CI
- [ ] Week 1b: attack lab, rule engine, rules-only baseline metrics
- [ ] Week 2: ML detection (IsolationForest, PyTorch autoencoder, MLflow), correlation & scoring
- [ ] Week 3: local LLM triage agent (Ollama) + ATT&CK RAG, eval suite in CI, response actions
- [ ] Week 4: FastAPI, dashboard, load test, final results
- [ ] Later: Terraform + AWS deployment
