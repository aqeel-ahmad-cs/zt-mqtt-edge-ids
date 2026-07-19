#!/usr/bin/env bash
# Launches the edge detection node. Requires root (or CAP_NET_RAW +
# CAP_NET_ADMIN) since it opens a raw capture socket and manipulates
# iptables directly.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

INTERFACE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface)
            INTERFACE="$2"
            shift 2
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    echo "[run_edge_node.sh] this script needs root privileges for raw sockets and iptables" >&2
    exit 1
fi

if [ ! -d ".venv" ]; then
    echo "[run_edge_node.sh] virtualenv not found at .venv - run pip install -r requirements.txt first" >&2
    exit 1
fi

source .venv/bin/activate

if [ -n "$INTERFACE" ]; then
    echo "[run_edge_node.sh] overriding capture interface -> $INTERFACE"
    python3 - "$INTERFACE" <<'PYEOF'
import sys
import yaml

interface = sys.argv[1]
with open("config/network_config.yaml") as f:
    cfg = yaml.safe_load(f)

cfg["capture"]["interface"] = interface

with open("config/network_config.yaml", "w") as f:
    yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)
PYEOF
fi

mkdir -p logs
python3 -m src.edge_node
