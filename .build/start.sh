#!/bin/bash
set -e

# Start Caddy in background with JSON config
echo "Starting Caddy on port ${PORT:-32090}..."
caddy run --config /app/caddy.json &
CADDY_PID=$!

# Wait for Caddy admin API to be ready
echo "Waiting for Caddy admin API..."
for i in {1..30}; do
    if curl -s http://localhost:2019/config/ > /dev/null 2>&1; then
        echo "Caddy is ready"
        break
    fi
    sleep 0.5
done

# Start Flask app
echo "Starting Flask app on port ${FLASK_PORT:-8080}..."
exec python -m src.app
