#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "${SCRIPT_DIR}/.." || exit 1

set -e

if [ ! -f config/users.yaml ]; then
    cp config/users.yaml.example config/users.yaml 2>/dev/null || true
    echo "Created config/users.yaml from example"
fi

docker network inspect spal_kasm_net >/dev/null 2>&1 || docker network create spal_kasm_net

cleanup() {
    echo ""
    echo "Stopping..."
    docker compose -f docker-compose.local.yml down
    exit 0
}

trap cleanup INT TERM

echo "Starting Mini KASM on http://localhost:32090 ..."
docker compose -f docker-compose.local.yml up --build
