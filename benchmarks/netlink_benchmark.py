import subprocess
import time
import os
import sys
import json
import shutil
import glob

# --- CONFIGURATION ---
TCPSNITCH_CMD = "tcpsnitch"
TCPSNITCH_DIR = "/tmp/bench_netlink"
TEST_IP = "10.0.0.42/32"
TEST_INTERFACE = "lo"


def get_tcpsnitch_path(cmd_name):
    path = shutil.which(cmd_name)
    if path:
        return path
    candidates = ["../tcpsnitch", "../bin/tcpsnitch", "./tcpsnitch"]
    for c in candidates:
        if os.path.exists(c) and os.access(c, os.X_OK):
            return os.path.abspath(c)
    return None


def run_netlink_test():
    print(f"\n=== TEST: Netlink Events Detection (MPTCP ready) ===")

    # 1. Preparation
    binary = get_tcpsnitch_path(TCPSNITCH_CMD)
    if not binary:
        print(f"[ERROR] '{TCPSNITCH_CMD}' not found.")
        return

    if os.path.exists(TCPSNITCH_DIR):
        shutil.rmtree(TCPSNITCH_DIR)
    os.makedirs(TCPSNITCH_DIR, exist_ok=True)
    os.chmod(TCPSNITCH_DIR, 0o777)

    # 2. Launch tcpsnitch with a REAL network trigger
    print("1. Launching tcpsnitch (Python socket + sleep)...")

    # TRICK: Open a dummy socket to trigger tcpsnitch initialization
    trigger_cmd = "import socket, time; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); time.sleep(5)"

    cmd = [binary, "-n", "-d", TCPSNITCH_DIR, "-f", "0", "python3", "-c", trigger_cmd]

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    # Wait for Python to start and open socket
    time.sleep(1.5)

    # 3. Inject network event
    print(f"2. Injection: Adding IP {TEST_IP} on {TEST_INTERFACE}...")
    try:
        subprocess.run(
            ["ip", "addr", "add", TEST_IP, "dev", TEST_INTERFACE], check=True
        )
        # Give time for detection
        time.sleep(1)
        print(f"3. Cleanup: Removing IP...")
        subprocess.run(
            ["ip", "addr", "del", TEST_IP, "dev", TEST_INTERFACE], check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] IP command failed: {e}")
        proc.terminate()
        return

    # 4. Wait for completion
    print("4. Waiting for process to finish...")
    proc.wait()

    # 5. Analysis
    print("\n--- TRACE ANALYSIS ---")
    json_files = glob.glob(os.path.join(TCPSNITCH_DIR, "**", "*.json"), recursive=True)

    found_event = False
    debug_content = []

    for json_file in json_files:
        print(f"Inspecting {json_file}...")
        try:
            with open(json_file, "r") as f:
                for line in f:
                    if not line.strip():
                        continue
                    debug_content.append(line.strip())
                    if TEST_IP.split("/")[0] in line:
                        print(f" -> EVENT DETECTED: {line.strip()}")
                        found_event = True
        except Exception as e:
            print(f"[ERROR] Reading file: {e}")

    if found_event:
        print("\n[RESULT] SUCCESS: Netlink event captured.")
        print("   MPTCP/Mobility support validated.")
    else:
        print("\n[RESULT] FAILURE.")
        print("Last captured lines (debug):")
        for l in debug_content[-5:]:
            print(f"  {l}")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[WARNING] Run with 'sudo'!")
        sys.exit(1)

    run_netlink_test()
