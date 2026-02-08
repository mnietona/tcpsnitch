import subprocess
import time
import os
import sys
import json
import shutil

# Benchmark configuration
DURATION = 10
TCPSNITCH_DIR = "/dev/shm/bench_splice"
IPERF_LOGFILE = "/tmp/iperf_result.json"


def run_test(label, port, cmd_prefix=None):
    print(f"\n[TEST] {label} (Port {port})")
    if os.path.exists(IPERF_LOGFILE):
        os.remove(IPERF_LOGFILE)

    cmd_list = cmd_prefix if cmd_prefix else []

    # 1. Start Server
    server = subprocess.Popen(
        ["iperf3", "-s", "-p", str(port), "--one-off"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2)

    # 2. Run Client
    iperf_cmd = [
        "iperf3",
        "-c",
        "127.0.0.1",
        "-p",
        str(port),
        "-t",
        str(DURATION),
        "-Z",
        "--json",
        "--logfile",
        IPERF_LOGFILE,
    ]
    full_cmd = cmd_list + iperf_cmd

    print(f"Command: {' '.join(full_cmd)}")

    try:
        # Use DEVNULL to avoid blocking buffers at high throughput
        subprocess.run(
            full_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=DURATION + 20,
        )

        if os.path.exists(IPERF_LOGFILE):
            with open(IPERF_LOGFILE, "r") as f:
                res = json.loads(f.read())

            # Calculate Gbps from bits_per_second
            gbps = res["end"]["sum_received"]["bits_per_second"] / 1e9
            # Get real system CPU calculated by iperf3
            avg_cpu = res["end"]["cpu_utilization_percent"]["host_total"]

            print(
                f"[RESULT]\n -> Throughput : {gbps:.4f} Gbps\n -> Avg CPU (System) : {avg_cpu:.2f} %"
            )
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        server.terminate()
        server.wait()


if __name__ == "__main__":
    if os.path.exists(TCPSNITCH_DIR):
        shutil.rmtree(TCPSNITCH_DIR, ignore_errors=True)
    os.makedirs(TCPSNITCH_DIR, exist_ok=True)

    run_test("NATIVE", 5201)
    run_test(
        "WITH TCPSNITCH",
        5202,
        ["tcpsnitch", "-n", "-d", TCPSNITCH_DIR, "-f", "0", "-l", "0"],
    )
