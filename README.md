# netprint

## Overview
netprint is a low-level network telemetry and anomaly detection tool designed to identify environmental changes and traffic interception. It utilizes multi-layer fingerprinting to establish a deterministic baseline of a network path and monitors for deviations in real-time.

The tool analyzes parameters across the OSI model, including Layer 3 (IP), Layer 4 (TCP), and Layer 7 (TLS), to detect routing shifts, middlebox interference, or cryptographic hijacking.

---

## Technical Specifications

### Fingerprinting Layers
*   **Layer 3 (Network):** Monitors IP TTL (Time to Live) variance, ToS (Type of Service) tags, and the DF (Don't Fragment) flag status.
*   **Layer 4 (Transport):** Analyzes TCP Window Size and stashes a complete TCP Option signature (MSS, Window Scale, SACK Permitted, Timestamps). It also tracks ECN (Explicit Congestion Notification) and CWR flags.
*   **Layer 7 (Application):** Implements JA4S fingerprinting to identify the server-side TLS stack, cipher selection, and extension ordering.

### Detection Logic
1.  **Calibration Phase:** Executes 5 initial probes to map the cluster environment. It accounts for Anycast architectures by learning valid ranges for TTL and ToS.
2.  **Continuous Telemetry:** Monitors the live connection against the established baseline.
3.  **Anomaly Scoring:** Assigns severity scores to deviations. High-score events trigger critical alerts indicating probable interception or infrastructure relocation.

---

## Quick start (copy - paste - enter)
```bash
pkg update -y && pkg install -y git clang make && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && git clone --depth=1 https://github.com/tailsmails/netprint && cd netprint && v -prod netprint.v -o netprint && ln -sf $(pwd)/netprint $PREFIX/bin/netprint
```

---

## Requirements
*   **Operating System:** Linux (required for raw socket support).
*   **Privileges:** Root/Sudo access (required for `SOCK_RAW` to perform deep packet inspection).
*   **Compiler:** V programming language compiler.

---

## Installation

Compile the source code using the V compiler:
```bash
v netprint.v
```

---

## Usage
Run the executable with administrative privileges and specify a target host:

```bash
sudo ./netprint <hostname_or_ip>
```

### Example
```bash
sudo ./netprint google.com
```

---

## Log Interpretation
*   **[INFO]:** Administrative and calibration data.
*   **[STATUS: OK]:** All network parameters match the established baseline.
*   **[WARN: DEVIATION]:** Minor network fluctuations (e.g., latency spikes or non-critical routing shifts).
*   **[ALERT: CRITICAL ANOMALY]:** Significant signature mismatch. This indicates a high probability of MITM (Man-in-the-Middle) interference, kernel stack modification, or TLS termination.

---

## Disclaimer
This tool is intended for network diagnostics and security auditing. Users are responsible for ensuring compliance with local regulations regarding network monitoring.

---

## License
![License](https://img.shields.io/badge/License-MIT-blue.svg)
