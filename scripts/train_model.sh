#!/usr/bin/env bash
# Generates a synthetic baseline dataset, extracts features, and trains
# the Isolation Forest model. Meant to be run once before the edge node
# starts, and re-run whenever the flow feature schema changes.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if [ ! -d ".venv" ]; then
    echo "[train_model.sh] .venv not found - create one with 'python3.11 -m venv .venv' first" >&2
    exit 1
fi

source .venv/bin/activate

echo "[train_model.sh] generating synthetic baseline traffic..."
python3 -m tests.attack_simulators.simulate_normal_traffic --output data/baseline_features.csv --samples 3000

echo "[train_model.sh] training isolation forest..."
python3 - <<'PYEOF'
import pandas as pd
from src.engine.isolation_forest_model import AnomalyDetector
from src.engine.preprocessing import dataframe_to_matrix

df = pd.read_csv("data/baseline_features.csv")
X = dataframe_to_matrix(df)

detector = AnomalyDetector()
detector.fit(X)
detector.save("models/isolation_forest.joblib", "models/scaler.joblib")

print(f"trained on {X.shape[0]} samples, {X.shape[1]} features")
PYEOF

echo "[train_model.sh] done - artifacts written to models/"
