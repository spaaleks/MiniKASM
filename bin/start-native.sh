#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "${SCRIPT_DIR}/.." || exit 1

set -e

if [ ! -d .venv ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate
pip install -q -r requirements.txt

if [ ! -f config/users.yaml ]; then
    cp config/users.yaml.example config/users.yaml 2>/dev/null || true
    echo "Created config/users.yaml from example"
fi

docker network inspect spal_kasm_net >/dev/null 2>&1 || docker network create spal_kasm_net

export CONFIG_PATH=config/users.yaml
export PORT=${PORT:-32090}

echo "Starting Mini KASM on http://localhost:${PORT} ..."
echo "NOTE: This only works on Linux. On macOS, use ./bin/start.sh instead."
python -m src.app
