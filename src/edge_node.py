"""
Wires the three subsystems together into the actual running edge node:
sniff -> extract features -> score -> mitigate. This is the module the
run_edge_node.sh script invokes; everything else in src/ is a library
that this file just composes.
"""

import logging
import logging.handlers
import os
import signal
import sys
from collections import defaultdict, deque

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.engine.isolation_forest_model import AnomalyDetector
from src.engine.preprocessing import feature_dict_to_vector
from src.mitigation.firewall_controller import FirewallController, FirewallControllerError
from src.mitigation.quarantine_ledger import QuarantineLedger
from src.monitor.mqtt_sniffer import MQTTSniffer

logger = logging.getLogger(__name__)


def _configure_logging(log_cfg: dict):
    log_dir = os.path.dirname(log_cfg["log_file"])
    os.makedirs(log_dir, exist_ok=True)

    handler = logging.handlers.RotatingFileHandler(
        log_cfg["log_file"],
        maxBytes=log_cfg["max_bytes"],
        backupCount=log_cfg["backup_count"],
    )
    console_handler = logging.StreamHandler()

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_cfg["level"], logging.INFO))
    root_logger.addHandler(handler)
    root_logger.addHandler(console_handler)


class EdgeNode:
    def __init__(self, network_config_path: str, firewall_config_path: str):
        self.network_config = self._load_yaml(network_config_path)
        self.firewall_config = self._load_yaml(firewall_config_path)

        _configure_logging(self.network_config["logging"])

        self.detector = AnomalyDetector()
        self._load_model()

        self.ledger = QuarantineLedger(self.firewall_config["quarantine"]["ledger_path"])

        try:
            self.firewall = FirewallController(
                chain=self.firewall_config["iptables"]["chain"],
                table=self.firewall_config["iptables"]["table"],
                dry_run=self.firewall_config["response_policy"]["dry_run"],
            )
        except FirewallControllerError as exc:
            logger.error("could not initialize firewall controller: %s", exc)
            raise

        # tracks how many consecutive windows a given IP has been flagged,
        # so a single noisy window doesn't trigger a firewall action
        self._consecutive_flags = defaultdict(int)
        self._recent_scores = defaultdict(
            lambda: deque(maxlen=self.network_config["detection"]["score_smoothing_window"])
        )

        self.sniffer = MQTTSniffer(network_config_path)
        self.sniffer.register_feature_callback(self._on_features_ready)

    def _load_yaml(self, path: str) -> dict:
        try:
            with open(path, "r") as f:
                return yaml.safe_load(f)
        except (FileNotFoundError, yaml.YAMLError) as exc:
            logger.error("failed loading config %s: %s", path, exc)
            raise

    def _load_model(self):
        detection_cfg = self.network_config["detection"]
        try:
            self.detector.load(detection_cfg["model_path"], detection_cfg["scaler_path"])
        except FileNotFoundError:
            logger.error(
                "no trained model found - run scripts/train_model.sh before starting the edge node"
            )
            raise

    def _on_features_ready(self, features: dict):
        source_ip = features["source_ip"]
        client_id = features["client_id"]

        try:
            vector = feature_dict_to_vector(features)
            score = float(self.detector.score(vector)[0])
        except (ValueError, RuntimeError) as exc:
            logger.error("scoring failed for %s (%s): %s", source_ip, client_id, exc)
            return

        threshold = self.network_config["detection"]["anomaly_threshold"]
        is_anomalous = score < threshold

        self._recent_scores[source_ip].append(score)

        if is_anomalous:
            self._consecutive_flags[source_ip] += 1
            logger.warning(
                "anomalous window: ip=%s client_id=%s score=%.4f (threshold=%.4f) consecutive=%d",
                source_ip, client_id, score, threshold, self._consecutive_flags[source_ip],
            )
        else:
            self._consecutive_flags[source_ip] = 0

        min_flags = self.firewall_config["response_policy"]["min_consecutive_flags"]
        if self._consecutive_flags[source_ip] >= min_flags and not self.ledger.is_quarantined(source_ip):
            self._mitigate(source_ip, client_id, score, features)

    def _mitigate(self, source_ip: str, client_id: str, score: float, features: dict):
        max_active = self.firewall_config["quarantine"]["max_active_quarantines"]
        if self.ledger.active_count() >= max_active:
            logger.error(
                "quarantine capacity reached (%d active) - not isolating %s, manual review needed",
                max_active, source_ip,
            )
            return

        try:
            self.firewall.quarantine_ip(source_ip)
            self.ledger.add_entry(source_ip, client_id, score, features)
        except FirewallControllerError as exc:
            logger.error("mitigation failed for %s: %s", source_ip, exc)

    def _handle_shutdown_signal(self, signum, frame):
        # scapy's sniff() loop doesn't check a stop flag between packets on
        # its own, so we rely on this handler mainly to guarantee the log
        # line and any pending ledger writes happen before the interpreter
        # actually tears down - the ledger's own writes are already atomic
        # (temp file + os.replace), so there's no partial-write risk here
        sig_name = signal.Signals(signum).name
        logger.info("received %s, shutting down edge node cleanly", sig_name)
        sys.exit(0)

    def run(self):
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            logger.error(
                "this process needs root (or CAP_NET_RAW + CAP_NET_ADMIN) to open a "
                "raw capture socket and manage iptables - re-run with sudo or via "
                "scripts/run_edge_node.sh"
            )
            sys.exit(1)

        signal.signal(signal.SIGINT, self._handle_shutdown_signal)
        signal.signal(signal.SIGTERM, self._handle_shutdown_signal)

        logger.info("edge node starting - model loaded, firewall chain ready, beginning capture")
        try:
            self.sniffer.start()
        except KeyboardInterrupt:
            logger.info("shutdown requested, exiting cleanly")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Zero-Trust MQTT edge detection node")
    parser.add_argument("--network-config", default="config/network_config.yaml")
    parser.add_argument("--firewall-config", default="config/firewall_rules.yaml")
    args = parser.parse_args()

    node = EdgeNode(args.network_config, args.firewall_config)
    node.run()
