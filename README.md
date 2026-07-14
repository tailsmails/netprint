# netprint

## Overview
netprint is a low-level network telemetry and anomaly detection tool designed to identify environmental changes, transport-layer manipulation, and traffic interception. It establishes a deterministic, multi-dimensional baseline of a network path and monitors for deviations in real-time.

By combining traditional rule-based heuristics with a lightweight **Neural Autoencoder** (powered by the VNM library), the tool analyzes features across the OSI model-spanning Layer 3 (IP), Layer 4 (TCP), and Layer 7 (TLS) to identify active routing shifts, proxy-induced middlebox interference, or cryptographic hijacking.

---

## Technical Specifications

### Telemetry & Fingerprinting Layers
*   **Layer 3 (Network):** Monitors Path MTU (PMTU) shifts and executes local DNS resolution checks to identify redirection to private or loopback (RFC1918) networks.
*   **Layer 4 (Transport):** Queries the Linux kernel's `tcp_info` structure via standard socket APIs. It analyzes TCP Maximum Segment Size (MSS), Kernel Peer RTT, Receiver RTT, Retransmit RTO, CWND Size, and RTT Variance. It also extracts a transport-layer options bitmask (such as TS, SACK, WSCALE, ECN, and TFO flags).
*   **Layer 7 (Application):** Performs inline parsing of the TLS Server Hello records to extract the JA4S cryptographic fingerprint and calculates a hash of the server's primary SSL/TLS certificate.
*   **SOCKS5 Proxy Tunneling:** Supports native routing of all TCP probes and TLS handshakes through a SOCKS5 proxy while preserving auxiliary local DNS checks for side-channel validation.

### Detection & Machine Learning Logic
1.  **Calibration Phase:** Executes 10 initial measurement cycles to map the path environment, dynamically discarding dropped handshakes or transient latency spikes to prevent baseline poisoning.
2.  **Neural Autoencoder:** Learns normal path characteristics by training a neural network model to reconstruct the 13-dimensional scaled feature vector. 
3.  **Online Self-Training:** Automatically adapts to slow, natural network drifts by executing tiny online optimization steps on states verified as highly secure (similarity >= 92%).
4.  **Crypto-Anchored Latency Tolerance:** Minimizes false alarms under heavy congestion by scaling down latency-reconstruction penalties when cryptographic features (JA4S and Certificate Hash) match the baseline perfectly.
5.  **Streak-Based Verification:** Suppresses transient network drops by requiring anomalies to persist for at least 3 consecutive cycles before confirming a critical path anomaly.
6.  **User-Adjustable Confidence Threshold:** Allows operators to define custom similarity percentage thresholds (default: 70%) to adapt to varying network environments.

---

## Quick start (copy - paste - enter)
```bash
pkg update -y && pkg install -y git clang make && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && v install --git https://github.com/tailsmails/vnm && git clone --depth=1 https://github.com/tailsmails/netprint && cd netprint && v -prod netprint.v -o netprint && ln -sf $(pwd)/netprint $PREFIX/bin/netprint
```

---

## Requirements
*   **Operating System:** Linux (required for native `tcp_info` kernel structure support).
*   **Privileges:** Standard user privileges (root/sudo is **not** required, as it utilizes standard TCP sockets and the native `getsockopt` API instead of raw socket sniffing).
*   **Compiler:** V programming language compiler.
*   **Dependencies:** The `vnm` (V Neural Model) library.

---

## Installation

First, install the V Neural Model dependency:
```bash
v install --git https://github.com/tailsmails/vnm
```

Then, compile the source code using the V compiler:
```bash
v -prod netprint.v -o netprint
```

---

## Usage
Run the compiled executable directly:

```bash
./netprint
```

Upon startup, the tool will prompt you for:
1.  Optional target hosts.
2.  Optional SOCKS5 proxy configurations.
3.  A custom similarity percentage threshold (the confidence ceiling) to define the trigger level for anomaly detection.

---

## Log Interpretation
*   **[SECURE]:** All parameters, signatures, and transport latencies align within expected bounds of the neural autoencoder (similarity meets or exceeds user threshold).
*   **[WARN: CONTEXTUAL JITTER DETECTED]:** Transient network drops, momentary routing delays, or packet-level jitter that do not persist long enough to trigger an alarm.
*   **[!!! SYSTEM PATH ANOMALY DETECTED !!!]:** Persistent structural signature mismatch over multiple cycles. Indicates a high probability of intermediate TCP termination, active TLS decryption/interception, or DNS spoofing.

---

## Disclaimer
This tool is intended for network diagnostics and security auditing. Users are responsible for ensuring compliance with local regulations regarding network monitoring.

---

## License
![License](https://img.shields.io/badge/License-MIT-blue.svg)
