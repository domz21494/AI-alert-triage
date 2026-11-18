.PHONY: install test lint fmt up down data eval

install:
	pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check src tests

fmt:
	ruff check --fix src tests && ruff format src tests

up:
	docker compose up -d

down:
	docker compose down

# Labeled datasets: dev (seed 1) is for tuning rules, test (seed 2) is only for reporting.
data:
	alerttriage simulate --seed 1 --out data/sim/dev
	alerttriage simulate --seed 2 --hours 72 --attacks-per-type 5 --out data/sim/test

eval: data
	alerttriage eval data/sim/test.log data/sim/test.labels.jsonl \
		--out results/baseline_rules --title "Baseline: rules only (test set, seed 2, 72h)"
