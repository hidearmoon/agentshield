#!/usr/bin/env bash
set -euo pipefail

echo "=== AgentGuard Dev Setup ==="

# Start infrastructure services
echo "Starting PostgreSQL and ClickHouse..."
docker compose -f docker/docker-compose.yml up -d postgres clickhouse

# Wait for services
echo "Waiting for services to be ready..."
sleep 5

# Install Python dependencies
echo "Installing Python dependencies..."
cd packages/core && uv sync && cd ../..
cd packages/proxy && uv sync && cd ../..
cd packages/sdk-python && uv sync && cd ../..
cd packages/console/backend && uv sync && cd ../../../..

# Install frontend dependencies
echo "Installing frontend dependencies..."
cd packages/console/frontend && npm install && cd ../../..

echo ""
echo "=== Setup Complete ==="
echo "Start core engine:    cd packages/core && uv run uvicorn agentguard_core.app:app --reload"
echo "Start proxy:          cd packages/proxy && uv run uvicorn agentguard_proxy.app:app --port 8080 --reload"
echo "Start console:        cd packages/console/backend && uv run uvicorn agentguard_console.app:app --port 8100 --reload"
echo "Start frontend:       cd packages/console/frontend && npm run dev"
