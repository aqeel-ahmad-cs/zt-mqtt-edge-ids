"""
Simulates a malformed-packet flood: an attacker hammering the broker with
garbage/truncated frames, either to crash a poorly-hardened parser or to
exhaust connection-handling resources. The signal here is almost entirely
in malformed_packet_count and the abnormally tight publish rate, since a
malformed frame by definition can't populate most of the other MQTT
semantic fields.
"""

import argparse
import csv
import os
import random


def generate_malformed_flood_window(rng: random.Random) -> dict:
    return {
        "mean_inter_arrival": round(rng.uniform(0.001, 0.02), 6),
        "inter_arrival_variance": round(rng.uniform(0.00001, 0.0005), 6),
        "mean_payload_length": round(rng.uniform(0, 5), 2),
        "max_payload_length": round(rng.uniform(0, 10), 2),
        "payload_length_std": round(rng.uniform(0, 3), 2),
        "topic_cardinality": 0,
        "connect_to_publish_ratio": 0.0,
        "malformed_packet_count": rng.randint(12, 20),
        "mean_keep_alive": 0,
        "packets_in_window": 20,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="data/malformed_flood_features.csv")
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--seed", type=int, default=21)
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
                writer.writerow(generate_malformed_flood_window(rng))
    except OSError as exc:
        raise SystemExit(f"failed writing malformed flood dataset to {args.output}: {exc}")

    print(f"wrote {args.samples} malformed-flood attack samples to {args.output}")


if __name__ == "__main__":
    main()
