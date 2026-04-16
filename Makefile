.PHONY: dev test test-unit test-integration test-security test-perf test-all lint format build docker-build migrate seed proto

# Development
dev:
	docker compose -f docker/docker-compose.yml up -d postgres clickhouse
	cd packages/core && uv run alembic upgrade head
	@echo "Dev services started. Run individual packages with: cd packages/<pkg> && uv run uvicorn ..."

# Testing
test: test-unit test-security

test-all: test-unit test-security test-integration

test-unit:
	cd packages/core && uv run pytest tests/unit -v
	cd packages/core && PYTHONPATH=../proxy/src uv run pytest ../proxy/tests/ -v
	cd packages/sdk-python && uv run pytest tests/ -v

test-integration:
	cd packages/core && uv run pytest tests/integration -v

test-security:
	cd packages/core && uv run pytest tests/security -v

test-coverage:
	cd packages/core && uv run pytest tests/ --cov=agentshield_core --cov-report=term --cov-report=html:htmlcov --cov-fail-under=90 -q

test-coverage-full:
	cd packages/core && AGENTSHIELD_CLICKHOUSE_PORT=8125 AGENTSHIELD_DATABASE_URL="postgresql+asyncpg://agentshield:test-password@localhost:5433/agentshield_test" uv run pytest tests/ --cov=agentshield_core --cov-report=term --cov-report=html:htmlcov --cov-fail-under=95 -q

test-perf:
	cd packages/core && uv run pytest tests/performance -v

# Code quality
lint:
	uv run ruff check packages/
	uv run ruff format --check packages/
	cd packages/console/frontend && npx tsc --noEmit

format:
	uv run ruff format packages/
	uv run ruff check --fix packages/
	cd packages/console/frontend && npx prettier --write src/

# Build
build:
	cd packages/sdk-python && uv build
	cd packages/console/frontend && npm run build

docker-build:
	docker build -f docker/Dockerfile.core -t agentshield/core:latest .
	docker build -f docker/Dockerfile.proxy -t agentshield/proxy:latest .
	docker build -f docker/Dockerfile.console -t agentshield/console:latest .

# Database
migrate:
	cd packages/core && uv run alembic upgrade head

seed:
	bash scripts/seed-db.sh

# Proto
proto:
	bash scripts/generate-proto.sh
