#!/bin/bash
set -e

IMAGES=(
    "kasmweb/chromium:1.16.1"
    "kasmweb/firefox:1.16.1"
    "kasmweb/chrome:1.16.1"
)

echo "Pulling KASM images..."
for img in "${IMAGES[@]}"; do
    echo "Pulling $img..."
    docker pull "$img"
done
echo "Done."
