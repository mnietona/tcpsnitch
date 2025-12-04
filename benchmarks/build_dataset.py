import subprocess
import os
import time
import shutil

# --- CONFIGURATION ---
TCPSNITCH_BIN = "tcpsnitch"
# Use relative path instead of user specific path
DATASET_DIR = "./dataset_rich"
INTERFACE_LOGS = 3

SCENARIOS = [
    (
        "web_wikipedia",
        [
            "wget",
            "--no-check-certificate",
            "-r",
            "-l",
            "1",
            "-nd",
            "--delete-after",
            "https://www.wikipedia.org",
        ],
    ),
    (
        "media_youtube",
        [
            "yt-dlp",
            "--no-check-certificate",
            "-f",
            "worst",
            "--max-downloads",
            "1",
            "https://www.youtube.com/watch?v=BaW_jenozKc",
        ],
    ),
    (
        "dev_git",
        [
            "git",
            "clone",
            "https://github.com/octocat/Hello-World.git",
            "/tmp/hello_world_test",
        ],
    ),
    ("net_dns", ["dig", "+trace", "google.com"]),
    ("sys_apt", ["apt-get", "update"]),
    (
        "sys_netlink",
        ["python3", "-c", "import time, socket; s=socket.socket(); time.sleep(5)"],
    ),
]


def run_trace(name, command):
    print(f"\n[+] Running scenario: {name}")
    print(f"    Command: {' '.join(command)}")

    output_path = os.path.join(DATASET_DIR, name)

    if not os.path.exists(output_path):
        os.makedirs(output_path)
        os.chmod(output_path, 0o777)

    # Since script runs as root, sudo inside subprocess might be redundant but kept for safety
    full_cmd = [
        TCPSNITCH_BIN,
        "-n",
        "-d",
        output_path,
        "-f",
        str(INTERFACE_LOGS),
    ] + command

    try:
        start_time = time.time()
        subprocess.run(full_cmd, check=False, timeout=120)
        duration = time.time() - start_time
        print(f"    -> Done in {duration:.2f} seconds.")

    except Exception as e:
        print(f"    -> Error: {e}")


def main():
    # 1. Cleanup previous runs
    if os.path.exists(DATASET_DIR):
        print(f"Cleaning {DATASET_DIR}...")
        shutil.rmtree(DATASET_DIR)
    os.makedirs(DATASET_DIR)
    os.chmod(DATASET_DIR, 0o777)

    # 2. Execute scenarios
    print(f"Generating dataset in {DATASET_DIR}...")

    for name, cmd in SCENARIOS:
        run_trace(name, cmd)
        time.sleep(1)

    # 3. Cleanup temp files
    if os.path.exists("/tmp/hello_world_test"):
        shutil.rmtree("/tmp/hello_world_test")

    print("\n--- DONE ---")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script must be run as root.")
        exit(1)
    main()
