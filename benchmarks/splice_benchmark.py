import subprocess
import time
import psutil
import os
import sys
import json
import shutil

# --- CONFIGURATION ---
TCPSNITCH_CMD = "tcpsnitch"
IPERF_SERVER = "127.0.0.1"
DURATION = 10
TCPSNITCH_DIR = "/tmp/bench_splice"
IPERF_LOGFILE = "/tmp/iperf_result.json"


def get_tcpsnitch_path(cmd_name):
    path = shutil.which(cmd_name)
    if path:
        return path
    candidates = ["../tcpsnitch", "../bin/tcpsnitch", "./tcpsnitch"]
    for c in candidates:
        if os.path.exists(c) and os.access(c, os.X_OK):
            return os.path.abspath(c)
    return None


def run_test(label, port, cmd_prefix=None):
    print(f"\n[TEST] {label} (Port {port})")

    # Clean previous log file
    if os.path.exists(IPERF_LOGFILE):
        os.remove(IPERF_LOGFILE)

    cmd_list = []
    if cmd_prefix:
        binary = get_tcpsnitch_path(cmd_prefix[0])
        if not binary:
            print(f"[ERROR] '{cmd_prefix[0]}' not found.")
            return
        cmd_list = [binary] + cmd_prefix[1:]

        # Force silent logging for tcpsnitch
        if "-l" not in cmd_list:
            cmd_list.extend(["-l", "0"])

        # Handle output directory
        if "-d" in cmd_list:
            try:
                idx = cmd_list.index("-d") + 1
                if idx < len(cmd_list):
                    target_dir = cmd_list[idx]
                    os.makedirs(target_dir, exist_ok=True)
                    os.chmod(target_dir, 0o777)
            except:
                pass

    # 1. Start Server
    server_cmd = ["iperf3", "-s", "-p", str(port)]
    server = subprocess.Popen(
        server_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(2)

    # 2. Run Client (using --logfile to isolate JSON output)
    iperf_cmd = [
        "iperf3",
        "-c",
        IPERF_SERVER,
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
        p = subprocess.Popen(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_obj = psutil.Process(p.pid)

        cpu_usage = []
        while p.poll() is None:
            try:
                cpu = proc_obj.cpu_percent(interval=0.5)
                cpu_usage.append(cpu)
            except:
                break

        stdout, stderr = p.communicate()

        # --- ANALYSIS ---
        # Read iperf3 generated file
        if os.path.exists(IPERF_LOGFILE):
            with open(IPERF_LOGFILE, "r") as f:
                file_content = f.read()
        else:
            file_content = ""

        if p.returncode != 0:
            print(f"[ERROR] Crash detected (Code {p.returncode})")
            print(f"STDERR:\n{stderr.decode(errors='ignore')}")

            if file_content:
                print(f"Partial JSON content:\n{file_content[:200]} ...")
            else:
                print("No JSON file produced.")
            return

        try:
            result = json.loads(file_content)
            receiver_bps = result["end"]["sum_received"]["bits_per_second"]
            gbps = receiver_bps / 1e9
            avg_cpu = sum(cpu_usage) / len(cpu_usage) if cpu_usage else 0

            print(f"[RESULT]")
            print(f" -> Throughput : {gbps:.4f} Gbps")
            print(f" -> Avg CPU    : {avg_cpu:.2f} %")

        except json.JSONDecodeError:
            print("[ERROR] JSON Error: File incomplete (iperf likely crashed).")
            print(f"End of file:\n{file_content[-200:] if file_content else 'EMPTY'}")

    except Exception as e:
        print(f"[EXCEPTION] {e}")

    finally:
        server.terminate()
        server.wait()


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[WARNING] Run with 'sudo'!")
        sys.exit(1)

    # Cleanup
    if os.path.exists(TCPSNITCH_DIR):
        shutil.rmtree(TCPSNITCH_DIR, ignore_errors=True)

    # Test 1
    run_test("NATIVE (No tcpsnitch)", 5201)

    # Test 2
    run_test(
        "WITH TCPSNITCH", 5202, [TCPSNITCH_CMD, "-n", "-d", TCPSNITCH_DIR, "-f", "0"]
    )
