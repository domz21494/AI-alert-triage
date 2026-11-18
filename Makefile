.PHONY: install test lint fmt up down

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
