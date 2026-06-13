# netprint

## Overview
netprint is a low-level network telemetry and anomaly detection tool designed to identify environmental changes and traffic interception. It establishes a deterministic baseline of a network path and monitors for deviations in real-time.

The tool analyzes parameters across the OSI model, including Layer 3 (IP), Layer 4 (TCP), and Layer 7 (TLS), to detect routing shifts, middlebox interference, or cryptographic hijacking.

---

## Technical Specifications

### Fingerprinting Layers
*   **Layer 3 (Network):** Monitors Path MTU (PMTU) shifts and performs real-time DNS resolution checks to identify redirection to private or loopback (RFC1918) networks.
*   **Layer 4 (Transport):** Queries the Linux kernel's `tcp_info` structure via standard socket APIs. It analyzes TCP Maximum Segment Size (MSS), Kernel Peer RTT, Receiver RTT, Retransmit RTO, CWND Size, and RTT Variance. It also extracts a transport-layer options bitmask (negotiated flags such as TS, SACK, WSCALE, ECN, and TFO).
*   **Layer 7 (Application):** Performs inline parsing of the TLS Server Hello records to extract the JA4S cryptographic fingerprint and calculates an FNV-1a hash of the server's primary SSL/TLS certificate.

### Detection Logic
1.  **Calibration Phase:** Executes 10 initial measurement cycles to map the path environment, learning baseline averages and standard deviations for connection latency, handshake ratios, and transport characteristics.
2.  **Continuous Telemetry:** Periodically probes the target in real-time to monitor for live deviations.
3.  **Cumulative Deviation Index:** Evaluates changes against baseline tolerances. If a combination of structural shifts (e.g., latency asymmetry, altered TLS signatures, modified TCP options) crosses safe thresholds, the tool generates a detailed system path anomaly report.

---

## Quick start (copy - paste - enter)
```bash
pkg update -y && pkg install -y git clang make && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && git clone --depth=1 https://github.com/tailsmails/netprint && cd netprint && v -prod netprint.v -o netprint && ln -sf $(pwd)/netprint $PREFIX/bin/netprint
```

---

## Requirements
*   **Operating System:** Linux (required for native `tcp_info` kernel structure support).
*   **Privileges:** Standard user privileges (root/sudo is **not** required, as it utilizes standard TCP sockets and the native `getsockopt` API instead of raw socket sniffing).
*   **Compiler:** V programming language compiler.

---

## Installation

Compile the source code using the V compiler:
```bash
v -prod netprint.v -o netprint
```

---

## Usage
Run the compiled executable directly:

```bash
./netprint
```

*Note: The target host and port are configured within the source file (`google.com:443` by default).*

---

## Log Interpretation
*   **[SECURE]:** All parameters, signatures, and transport latencies align with the established baseline.
*   **[WARN: CONTEXTUAL JITTER DETECTED]:** Minor network fluctuations (e.g., transient routing delays or minor transport-layer jitter).
*   **[!!! SYSTEM PATH ANOMALY DETECTED !!!]:** Significant structural signature mismatch. Indicates a high probability of intermediate TCP termination, TLS interception/decryption, or active local DNS spoofing.

---

## Disclaimer
This tool is intended for network diagnostics and security auditing. Users are responsible for ensuring compliance with local regulations regarding network monitoring.

---

## License
![License](https://img.shields.io/badge/License-MIT-blue.svg)
