# Benchmarks & Technical Validation

This folder contains scripts to validate the performance, stability, and advanced features of `tcpsnitch`.

### Prerequisites
* `tcpsnitch` (installed or compiled locally).
* `iperf3` (for throughput testing).
* `python3` with **root** privileges (`sudo`).

### Validation Scripts

#### 1. Performance (`splice_benchmark.py`)
Measures overhead (throughput and CPU usage) during high-speed transfers using the `splice()` system call (Zero-Copy).
* **Command:** `sudo python3 splice_benchmark.py`
* **Expected Result:** Throughput > 9 Gbps on local loopback, no crashes.

#### 2. Mobility / MPTCP (`netlink_benchmark.py`)
Verifies that the tool dynamically detects IP address additions or removals during program execution.
* **Command:** `sudo python3 netlink_benchmark.py`
* **Expected Result:** Capture of `NEW_ADDR` and `DEL_ADDR` events in the JSON output.

#### 3. Process Management (`fork_benchmark.py`)
Checks tracing continuity when a process duplicates itself (`fork`).
* **Command:** `sudo python3 fork_benchmark.py`
* **Expected Result:** Creation of two distinct trace folders (Parent and Child).

#### 4. Dataset Generation (`build_dataset.py`)
Runs a full suite of real-world scenarios (Web, Streaming, System, Dev) to generate a validated "Gold" dataset.
* **Command:** `sudo python3 build_dataset.py`
* **Output:** `./dataset_final/` folder containing traces and metadata.