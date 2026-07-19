"""
Generates synthetic "normal" flow feature rows for training the baseline
model, without needing an actual live broker running. This mirrors the
exact feature schema flow_tracker.py produces so the offline-trained
model transfers cleanly onto live traffic later.
"""

import argparse
import csv
import os
import random


def generate_normal_window(device_type: str, rng: random.Random) -> dict:
    if device_type == "sensor":
        mean_interval = rng.uniform(1.8, 2.2)
        payload_len = rng.uniform(20, 40)
        keep_alive = 60
    elif device_type == "actuator":
        mean_interval = rng.uniform(0.9, 1.5)
        payload_len = rng.uniform(15, 35)
        keep_alive = 30
    else:
        mean_interval = rng.uniform(1.0, 3.0)
        payload_len = rng.uniform(10, 50)
        keep_alive = 45

    return {
        "mean_inter_arrival": round(mean_interval + rng.gauss(0, 0.05), 6),
        "inter_arrival_variance": round(abs(rng.gauss(0.01, 0.005)), 6),
        "mean_payload_length": round(payload_len, 2),
        "max_payload_length": round(payload_len + rng.uniform(0, 10), 2),
        "payload_length_std": round(rng.uniform(1, 4), 2),
        "topic_cardinality": rng.choice([1, 1, 1, 2]),
        "connect_to_publish_ratio": round(rng.uniform(0.0, 0.05), 4),
        "malformed_packet_count": 0,
        "mean_keep_alive": keep_alive,
        "packets_in_window": 20,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="data/baseline_features.csv")
    parser.add_argument("--samples", type=int, default=3000)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    device_types = ["sensor", "actuator", "generic"]

    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    fieldnames = [
        "mean_inter_arrival", "inter_arrival_variance", "mean_payload_length",
        "max_payload_length", "payload_length_std", "topic_cardinality",
        "connect_to_publish_ratio", "malformed_packet_count", "mean_keep_alive",
        "packets_in_window",
    ]

    try:
        with open(args.output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for _ in range(args.samples):
                device_type = rng.choice(device_types)
                writer.writerow(generate_normal_window(device_type, rng))
    except OSError as exc:
        raise SystemExit(f"failed writing baseline dataset to {args.output}: {exc}")

    print(f"wrote {args.samples} normal traffic samples to {args.output}")


if __name__ == "__main__":
    main()
