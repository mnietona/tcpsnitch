import subprocess
import os
import time
import shutil
import json
import sys

# --- CONFIGURATION ---
DATASET_DIR = "./dataset_final"
INTERFACE_LOGS = 3
TCPSNITCH_CMD = "tcpsnitch"

# --- SCENARIOS ---
SCENARIOS = [
    # 1. WEB & TRANSFER (IPv4 forced for stability)
    (
        "web",
        "wget_wikipedia",
        [
            "wget",
            "-4",
            "--no-check-certificate",
            "-r",
            "-l",
            "1",
            "-nd",
            "--delete-after",
            "https://www.wikipedia.org",
        ],
    ),
    ("web", "curl_redirect_google", ["curl", "-4", "-L", "-v", "http://google.com"]),
    (
        "web",
        "curl_json_api",
        ["curl", "-4", "-H", "Accept: application/json", "https://httpbin.org/get"],
    ),
    # 2. DEVELOPMENT
    (
        "dev",
        "git_clone_small",
        [
            "git",
            "clone",
            "--depth",
            "1",
            "https://github.com/octocat/Hello-World.git",
            "/tmp/tcpsnitch_git_test",
        ],
    ),
    (
        "dev",
        "python_requests_https",
        [
            "python3",
            "-c",
            "import urllib.request; print(urllib.request.urlopen('https://www.python.org').read(100))",
        ],
    ),
    # 3. STREAMING & MEDIA (FIXED: Tele2 server + IPv4)
    # Simulate 10MB streaming
    (
        "media",
        "stream_simulation_10mb",
        [
            "wget",
            "-4",
            "--no-check-certificate",
            "-O",
            "/tmp/speedtest_10mb.zip",
            "http://speedtest.tele2.net/10MB.zip",
        ],
    ),
    # 4. SYSTEM & NETWORK
    ("sys", "dns_dig_trace", ["dig", "+trace", "github.com"]),
    # Disable sandbox to allow root tracing
    ("sys", "apt_update_root", ["apt-get", "-o", "APT::Sandbox::User=root", "update"]),
    ("sys", "host_query", ["host", "-t", "A", "google.com"]),
    # 5. NETLINK / MPTCP TEST
    (
        "net",
        "netlink_monitor_sleep",
        [
            "python3",
            "-c",
            "import socket, time; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); time.sleep(5)",
        ],
    ),
]


def get_tcpsnitch_path():
    path = shutil.which(TCPSNITCH_CMD)
    if path:
        return path
    candidates = [
        "../tcpsnitch",
        "../bin/tcpsnitch",
        "./tcpsnitch",
        "/usr/local/bin/tcpsnitch",
    ]
    for c in candidates:
        if os.path.exists(c) and os.access(c, os.X_OK):
            return os.path.abspath(c)
    return None


def run_trace(binary, category, name, command):
    print(f"\n[+] Scenario: [{category}] {name}")
    print(f"    Command: {' '.join(command)}")

    output_path = os.path.join(DATASET_DIR, category, name)
    if os.path.exists(output_path):
        shutil.rmtree(output_path)
    os.makedirs(output_path, exist_ok=True)
    os.chmod(output_path, 0o777)

    # -l 0 disables console logs to avoid spam
    full_cmd = [
        binary,
        "-n",
        "-d",
        output_path,
        "-f",
        str(INTERFACE_LOGS),
        "-l",
        "0",
    ] + command

    metadata = {
        "timestamp": time.time(),
        "category": category,
        "name": name,
        "command": " ".join(command),
        "status": "failed",
        "duration": 0,
    }

    try:
        start_time = time.time()
        # Increased timeout for streaming
        subprocess.run(full_cmd, check=True, timeout=180)
        duration = time.time() - start_time

        metadata["status"] = "success"
        metadata["duration"] = round(duration, 3)
        print(f"    [OK] Done in {duration:.2f}s")

    except Exception as e:
        print(f"    [ERROR] Failed: {e}")
        metadata["error_msg"] = str(e)

    with open(os.path.join(output_path, "scenario_info.json"), "w") as f:
        json.dump(metadata, f, indent=4)


def cleanup_temp():
    temps = ["/tmp/tcpsnitch_git_test", "/tmp/speedtest_10mb.zip"]
    for t in temps:
        if os.path.exists(t):
            try:
                if os.path.isdir(t):
                    shutil.rmtree(t)
                else:
                    os.remove(t)
            except:
                pass


def main():
    if os.geteuid() != 0:
        print("[WARNING] Run with sudo (root).")
        sys.exit(1)

    binary = get_tcpsnitch_path()
    if not binary:
        print(f"[ERROR] Could not find {TCPSNITCH_CMD}.")
        sys.exit(1)

    print(f"Using binary: {binary}")
    print(f"Dataset dir: {DATASET_DIR}")

    if os.path.exists(DATASET_DIR):
        shutil.rmtree(DATASET_DIR)
    os.makedirs(DATASET_DIR, mode=0o777)

    start_global = time.time()
    for cat, name, cmd in SCENARIOS:
        cleanup_temp()
        run_trace(binary, cat, name, cmd)
        time.sleep(1)
        cleanup_temp()

    # Manifest
    manifest = {
        "generation_date": time.ctime(),
        "total_duration": round(time.time() - start_global, 2),
        "scenarios": [s[1] for s in SCENARIOS],
        "categories": list(set([s[0] for s in SCENARIOS])),
    }
    with open(os.path.join(DATASET_DIR, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=4)

    print("\n--- DATASET GENERATED SUCCESSFULLY ---")


if __name__ == "__main__":
    main()
