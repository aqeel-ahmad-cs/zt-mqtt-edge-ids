"""
Simulates a credential brute-force attack pattern: rapid repeated CONNECT
attempts from a single source with tiny, near-identical payloads and an
unnaturally tight inter-arrival distribution (a real human-driven device
never reconnects this fast or this regularly).
"""

import argparse
import csv
import os
import random


def generate_brute_force_window(rng: random.Random) -> dict:
    return {
        "mean_inter_arrival": round(rng.uniform(0.01, 0.08), 6),
        "inter_arrival_variance": round(rng.uniform(0.0001, 0.001), 6),
        "mean_payload_length": round(rng.uniform(5, 15), 2),
        "max_payload_length": round(rng.uniform(15, 25), 2),
        "payload_length_std": round(rng.uniform(0.5, 2.0), 2),
        "topic_cardinality": 0,
        "connect_to_publish_ratio": round(rng.uniform(0.85, 1.0), 4),
        "malformed_packet_count": rng.choice([0, 0, 1]),
        "mean_keep_alive": rng.choice([5, 10, 15]),
        "packets_in_window": 20,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="data/brute_force_features.csv")
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--seed", type=int, default=13)
    args = parser.parse_args()

    rng = random.Random(args.seed)
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
                writer.writerow(generate_brute_force_window(rng))
    except OSError as exc:
        raise SystemExit(f"failed writing brute force dataset to {args.output}: {exc}")

    print(f"wrote {args.samples} brute-force attack samples to {args.output}")


if __name__ == "__main__":
    main()
