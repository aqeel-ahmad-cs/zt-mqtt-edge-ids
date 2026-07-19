# Zero-Trust Edge Security & Network Anomaly Detection System for MQTT-Based IoT Infrastructure

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> A research-grade, edge-deployable intrusion detection and automated mitigation framework for MQTT-based IoT networks, combining live application-layer traffic inspection with unsupervised machine learning and kernel-level enforcement.

---

## Abstract

The proliferation of constrained IoT devices communicating over lightweight publish/subscribe protocols such as MQTT has introduced a class of network security problems that traditional perimeter-based defenses are poorly equipped to handle. MQTT brokers are frequently deployed with weak or absent authentication, flat network topologies, and no inherent rate limiting, which makes them attractive targets for credential brute-forcing, topic-flooding denial-of-service attacks, and malformed packet exploitation of broker parsers. This project implements a Zero-Trust inspired monitoring and mitigation pipeline that operates directly at the network edge: it passively captures MQTT traffic, derives rolling statistical flow features at the application layer, scores each flow using an unsupervised anomaly detection model, and  upon confident detection of malicious behavior enforces isolation of the offending host at the kernel firewall level without requiring human intervention.

---

## 1. Technical Problem Definition

### 1.1 The IoT/MQTT Threat Surface

| Problem | Root Cause | Consequence |
|---|---|---|
| **Weak authentication surfaces** | MQTT ACLs are broker-side, often misconfigured or left as `allow_anonymous` in production deployments | Credential stuffing / brute-force `CONNECT` floods go undetected until broker exhaustion |
| **No native rate limiting** | The protocol specification leaves QoS and flow control to the application layer | A single compromised client can flood a topic (`PUBLISH` flood) and starve the broker's I/O loop |
| **Flat trust model** | Most residential/industrial IoT deployments place all devices on the same L2/L3 segment | Lateral movement from one compromised sensor to the broker or other devices is trivial |
| **Edge resource constraints** | Detection logic historically assumes cloud-scale compute | Heavyweight IDS/ML solutions are not deployable on the gateway hardware actually sitting at the network edge |

### 1.2 Why Zero-Trust at the Edge

Rather than treating the broker as a trusted internal service and the perimeter firewall as the sole control point, this system continuously re-evaluates every client's behavioral profile connection cadence, topic access patterns, payload size distribution, keep-alive intervals and treats deviation from an established baseline as sufficient grounds for automated network isolation, independent of whether the client presented valid credentials.

### 1.3 Design Constraints

- **No line-rate DPI ASICs available** : capture and parsing must be efficient enough to run on a single ARM Cortex-A72 core without dropping packets under moderate load.
- **No cloud round-trip for detection** : inference must complete locally within the flow window.
- **No supervised attack labels assumed in production** : the primary detector must generalize to attack patterns not present in any training set, which is why Isolation Forest (unsupervised) is the default rather than a classifier.

---

## 2. System Architecture

```
                                                    ┌─────────────────────────┐
                                                    │   Zero-Trust Policy      │
                                                    │   Store (config/*.yaml)  │
                                                    └────────────┬─────────────┘
                                                                 │
┌────────────────┐     mirrored/promisc      ┌──────────────────▼──────────────────┐
│  IoT Devices    │───────traffic────────────▶│         src/monitor                 │
│  (MQTT clients) │                            │  mqtt_sniffer.py (Scapy capture)    │
└────────────────┘                            │  packet_parser.py (MQTT frame decode)│
        │                                     │  flow_tracker.py (rolling stats)     │
        │  MQTT over TCP 1883                 └──────────────────┬──────────────────┘
        ▼                                                        │ feature dict
┌────────────────┐                                                │ per completed window
│  MQTT Broker    │◀───────────────────────────────────────────── │
│  (Mosquitto)    │        legitimate traffic passes through       │
└────────────────┘                                                 ▼
                                                   ┌──────────────────────────────────┐
                                                   │         src/engine                │
                                                   │  preprocessing.py → vector         │
                                                   │  isolation_forest_model.py         │
                                                   │  (autoencoder_model.py optional)   │
                                                   └──────────────────┬────────────────┘
                                                                      │ anomaly score
                                                                      ▼
                                                   ┌──────────────────────────────────┐
                                                   │        src/mitigation             │
                                                   │  firewall_controller.py (iptables) │
                                                   │  quarantine_ledger.py (audit log)  │
                                                   └──────────────────────────────────┘
```

### 2.1 Data Flow Summary

1. **Capture** :`mqtt_sniffer.py` attaches to a mirrored/bridge interface and reassembles MQTT frames from raw TCP segments.
2. **Feature Extraction** : `flow_tracker.py` maintains a bounded rolling window per `(source_ip, client_id)` and emits a 9-dimensional feature vector once the window fills.
3. **Inference** : `isolation_forest_model.py` scores the vector; anything below the configured threshold for `min_consecutive_flags` windows in a row is treated as an active threat.
4. **Enforcement** : `firewall_controller.py` installs an `iptables` DROP rule in a dedicated `ZT_MQTT_QUARANTINE` chain, and `quarantine_ledger.py` records the decision with the triggering feature vector for later audit.

---

## 3. Core Features

- Live MQTT 3.1.1 control-packet parsing directly from TCP payloads (`CONNECT`, `PUBLISH`, `SUBSCRIBE`, and friends), with explicit malformed-frame detection rather than silent drops.
- Bounded-memory rolling flow statistics, safe for continuous operation on constrained edge hardware.
- Unsupervised anomaly detection via Isolation Forest, with an interchangeable PyTorch autoencoder backend for nonlinear feature distributions.
- Automated, auditable mitigation : every firewall action is tied to the feature vector and anomaly score that triggered it.
- Config-driven policy (`/config`) : thresholds, ACLs, and firewall behaviour are never hardcoded.
- Full test coverage of the detection and mitigation path using mocks and hand-built MQTT byte frames, runnable without root or a live broker.

---

## 4. Repository Structure

```
zt-mqtt-edge-ids/
├── README.md
├── LICENSE
├── requirements.txt
├── docker-compose.yml
├── config/
│   ├── mosquitto.conf
│   ├── network_config.yaml
│   ├── mqtt_acl.conf
│   └── firewall_rules.yaml
├── src/
│   ├── edge_node.py
│   ├── monitor/
│   │   ├── mqtt_sniffer.py
│   │   ├── flow_tracker.py
│   │   └── packet_parser.py
│   ├── engine/
│   │   ├── preprocessing.py
│   │   ├── isolation_forest_model.py
│   │   └── autoencoder_model.py
│   └── mitigation/
│       ├── firewall_controller.py
│       └── quarantine_ledger.py
├── models/
│   └── .gitkeep
├── tests/
│   ├── test_packet_parser.py
│   ├── test_flow_tracker.py
│   ├── test_engine.py
│   ├── test_mitigation.py
│   └── attack_simulators/
│       ├── simulate_normal_traffic.py
│       ├── simulate_brute_force.py
│       └── simulate_malformed_flood.py
└── scripts/
    ├── train_model.sh
    └── run_edge_node.sh
```

---

## 5. Setup Instructions

### 5.1 Prerequisites

- **OS**: Linux (Ubuntu 22.04+ recommended) : `iptables` and raw socket capture require a Linux kernel.
- **Python**: 3.11 or later
- **Docker & Docker Compose v2**: for the lab MQTT broker
- **libpcap-dev / tshark**: required by Scapy
- **Root or `CAP_NET_RAW` + `CAP_NET_ADMIN`**: required for packet sniffing and `iptables` rule injection

### 5.2 System Dependencies (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y python3.11 python3.11-venv tshark libpcap-dev iptables
sudo usermod -aG wireshark $USER
```

### 5.3 Python Environment

```bash
git clone https://github.com/<your-username>/zt-mqtt-edge-ids.git
cd zt-mqtt-edge-ids

python3.11 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

### 5.4 Lab Network Topology (Docker)

```bash
docker compose up -d broker
```

### 5.5 Training the Detection Model

```bash
bash scripts/train_model.sh
```

Generates a synthetic baseline dataset, then fits and persists `models/isolation_forest.joblib` and `models/scaler.joblib`.

### 5.6 Running the Edge Node

```bash
sudo ./scripts/run_edge_node.sh --interface docker0
```

### 5.7 Running the Test Suite

```bash
pytest tests/ -v --tb=short
```

---

## 6. Threat Model & Scope

This system detects and mitigates **network and application-layer anomalies observable from traffic metadata and MQTT control-packet structure**. It explicitly does **not**:

- Inspect or decrypt TLS-secured MQTT (8883) traffic : only unencrypted (1883) deployments or environments with a TLS-terminating proxy are in scope.
- Replace broker-side authentication : it is a complementary detection layer.
- Guarantee detection of a sufficiently low-and-slow attack that stays within the statistical envelope of the trained baseline; this is an inherent limitation of unsupervised anomaly detection.

---

## 7. License

MIT License. See [LICENSE](LICENSE).

---

## 8. Implementation Status

- [x] `src/monitor` : packet sniffing engine, MQTT frame parser, and rolling flow statistics
- [x] `src/engine` : feature preprocessing, Isolation Forest detector, optional PyTorch autoencoder
- [x] `src/mitigation` : iptables-based firewall controller and persistent quarantine ledger
- [x] `src/edge_node.py` : orchestrator wiring the three subsystems together
- [x] `tests/` : unit tests plus three attack/traffic simulators
- [x] `config/` : network, MQTT ACL, and firewall rule configuration
- [x] `scripts/evaluate_detector.py` : precision/recall/F1 evaluation against labeled synthetic traffic

## 9. Detection Performance

Measured against 500 benign windows and 200 attack windows (100 brute-force, 100 malformed-flood),
generated by the simulators in `tests/attack_simulators/`, using `scripts/evaluate_detector.py`:

| Threshold | Precision | Recall | F1 | False Positive Rate |
|---|---|---|---|---|
| -0.020 (current default) | 0.960 | 0.970 | 0.965 | 1.6% |
| -0.030 | 0.979 | 0.930 | 0.954 | 0.8% |
| -0.050 | 0.993 | 0.705 | 0.825 | 0.2% |

The threshold in `config/network_config.yaml` was set by sweeping this range and picking the
best F1 tradeoff rather than an arbitrary guess  an earlier default of `-0.15` produced 0%
recall on this same dataset, because the actual score separation between benign and attack
windows sits much closer to zero than that value assumed. This is a concrete example of why
threshold choices need empirical justification rather than intuition: re-run
`python3 -m scripts.evaluate_detector` after any change to the feature schema or training data,
since the right operating point can shift.

These numbers describe detection performance on synthetic traffic with a specific attack
signature (fixed-cadence beaconing and malformed-frame floods); they are not a claim about
performance against attack patterns not represented in `tests/attack_simulators/`.

## 10. Architecture Tradeoffs

The three subsystems (`src/monitor`, `src/engine`, `src/mitigation`) are separate Python
modules with no shared global state, composed in-process by `src/edge_node.py` rather than
run as independent services connected over a message queue. For a single-node edge gateway
the deployment target this project is scoped to an in-process pipeline avoids the added
latency, serialization overhead, and additional failure surface (queue broker uptime, message
schema versioning) that a distributed pub/sub split would introduce, at the cost of not being
horizontally scalable across multiple gateways. If this system needed to run across a fleet of
edge nodes reporting to a central coordinator, the natural extension point is publishing flow
feature vectors to an MQTT topic (the transport is already in place) rather than calling
`self.detector.score()` directly, so `src/engine` could run as an independent consumer service.

## 11. Running the Test Suite Locally

```bash
source .venv/bin/activate
pip install -r requirements.txt
pytest tests/ -v
```

All tests run without root privileges and without a live broker  the firewall and capture layers are exercised through mocks and hand-constructed MQTT byte payloads.
