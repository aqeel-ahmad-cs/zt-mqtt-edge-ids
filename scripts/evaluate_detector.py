"""
Produces detection quality metrics against labeled synthetic traffic -
one benign class (normal_traffic) and two attack classes (brute_force,
malformed_flood). This exists specifically because "we built an anomaly
detector" isn't a defensible claim on its own; a committee is going to
ask what its false-positive rate actually is, and this script is what
answers that with numbers instead of a demo screenshot.

Usage:
    python3 -m scripts.evaluate_detector \
        --normal data/baseline_features.csv \
        --brute-force data/brute_force_features.csv \
        --malformed-flood data/malformed_flood_features.csv
"""

import argparse
import logging
import os
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.engine.isolation_forest_model import AnomalyDetector
from src.engine.preprocessing import dataframe_to_matrix

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("evaluate_detector")


def load_labeled_set(path: str, label: int) -> pd.DataFrame:
    try:
        df = pd.read_csv(path)
    except FileNotFoundError:
        logger.error("dataset not found at %s - generate it with the matching simulator first", path)
        raise
    except pd.errors.EmptyDataError:
        logger.error("dataset at %s is empty", path)
        raise

    df["ground_truth_label"] = label
    return df


def main():
    parser = argparse.ArgumentParser(description="Evaluate the trained Isolation Forest against labeled traffic")
    parser.add_argument("--normal", default="data/baseline_features.csv")
    parser.add_argument("--brute-force", default="data/brute_force_features.csv")
    parser.add_argument("--malformed-flood", default="data/malformed_flood_features.csv")
    parser.add_argument("--model-path", default="models/isolation_forest.joblib")
    parser.add_argument("--scaler-path", default="models/scaler.joblib")
    parser.add_argument("--threshold", type=float, default=-0.15,
                         help="matches detection.anomaly_threshold in network_config.yaml")
    parser.add_argument("--output", default="reports/evaluation_metrics.csv")
    args = parser.parse_args()

    normal_df = load_labeled_set(args.normal, label=0)
    brute_df = load_labeled_set(args.brute_force, label=1)
    flood_df = load_labeled_set(args.malformed_flood, label=1)

    combined = pd.concat([normal_df, brute_df, flood_df], ignore_index=True)
    y_true = combined["ground_truth_label"].to_numpy()
    X = dataframe_to_matrix(combined)

    detector = AnomalyDetector()
    try:
        detector.load(args.model_path, args.scaler_path)
    except FileNotFoundError:
        logger.error("no trained model found at %s - run scripts/train_model.sh first", args.model_path)
        sys.exit(1)

    scores = detector.score(X)
    y_pred = (scores < args.threshold).astype(int)  # 1 = flagged as anomalous

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    logger.info("=" * 60)
    logger.info("Evaluation results (threshold=%.4f)", args.threshold)
    logger.info("-" * 60)
    logger.info("True negatives  (benign, correctly passed):     %d", tn)
    logger.info("False positives (benign, wrongly flagged):      %d", fp)
    logger.info("False negatives (attack, missed):                %d", fn)
    logger.info("True positives  (attack, correctly flagged):     %d", tp)
    logger.info("-" * 60)
    logger.info("Precision: %.4f", precision)
    logger.info("Recall:    %.4f", recall)
    logger.info("F1 score:  %.4f", f1)
    logger.info("False positive rate: %.4f", false_positive_rate)
    logger.info("=" * 60)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    try:
        pd.DataFrame([{
            "threshold": args.threshold,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(false_positive_rate, 4),
            "n_normal_samples": len(normal_df),
            "n_attack_samples": len(brute_df) + len(flood_df),
        }]).to_csv(args.output, index=False)
        logger.info("wrote metrics to %s", args.output)
    except OSError as exc:
        logger.error("failed writing metrics report: %s", exc)


if __name__ == "__main__":
    main()
