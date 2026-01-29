import subprocess
import time
import os
import sys
import shutil
import glob

# --- CONFIGURATION ---
TCPSNITCH_CMD = "tcpsnitch"
TCPSNITCH_DIR = "/tmp/bench_fork"
C_SOURCE = "fork_test_app.c"
C_BINARY = "./fork_test_app"

# Stabilized C program
C_CODE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/socket.h>

void make_dummy_socket(const char* who) {
    printf("[%s] Opening socket (PID %d)...\n", who, getpid());
    fflush(stdout); // Force flush
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) perror("socket");
    else close(sock);
}

int main() {
    printf("[Main] Start (PID %d)\n", getpid());
    fflush(stdout);
    
    // Parent initializes tcpsnitch
    make_dummy_socket("PARENT");

    // Wait for tcpsnitch threads (Netlink Spy) to stabilize
    // Avoids forking during internal malloc calls
    sleep(1); 

    printf("[Main] Forking now...\n");
    fflush(stdout);

    pid_t pid = fork();

    if (pid == 0) {
        // --- CHILD PROCESS ---
        printf("[Child] I am the child (PID %d)\n", getpid());
        fflush(stdout);
        
        // Wait for tcpsnitch reset
        usleep(500000); 
        
        make_dummy_socket("CHILD");
        printf("[Child] Done. Exiting.\n");
        exit(0);
    } else if (pid > 0) {
        // --- PARENT PROCESS ---
        int status;
        wait(&status); // Wait for child
        printf("[Parent] Child finished.\n");
    } else {
        perror("fork");
        return 1;
    }
    return 0;
}
"""


def get_tcpsnitch_path(cmd_name):
    path = shutil.which(cmd_name)
    if path:
        return path
    candidates = ["../tcpsnitch", "../bin/tcpsnitch", "./tcpsnitch"]
    for c in candidates:
        if os.path.exists(c) and os.access(c, os.X_OK):
            return os.path.abspath(c)
    return None


def run_fork_test():
    print(f"\n=== TEST: Process Tree Validation (Fork) ===")

    # 1. Compilation
    print("1. Compiling test C program...")
    with open(C_SOURCE, "w") as f:
        f.write(C_CODE)

    try:
        subprocess.run(["gcc", C_SOURCE, "-o", C_BINARY], check=True)
    except Exception as e:
        print(f"[ERROR] Compilation failed: {e}")
        return

    # 2. Preparation
    binary = get_tcpsnitch_path(TCPSNITCH_CMD)
    if not binary:
        print(f"[ERROR] '{TCPSNITCH_CMD}' not found.")
        return

    if os.path.exists(TCPSNITCH_DIR):
        shutil.rmtree(TCPSNITCH_DIR)
    os.makedirs(TCPSNITCH_DIR, exist_ok=True)
    os.chmod(TCPSNITCH_DIR, 0o777)

    # 3. Execution
    print(f"2. Running tcpsnitch on {C_BINARY}...")
    cmd = [binary, "-n", "-d", TCPSNITCH_DIR, "-f", "0", C_BINARY]

    try:
        # Do not pipe stdout to see live output
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Execution failed: {e}")
        return

    # 4. Analysis
    print("\n--- DIRECTORY ANALYSIS ---")
    subdirs = [f.path for f in os.scandir(TCPSNITCH_DIR) if f.is_dir()]

    print(f"Trace folders found: {len(subdirs)}")
    for d in subdirs:
        print(f"  - {os.path.basename(d)}")
        jsons = glob.glob(os.path.join(d, "*.json"))
        print(f"    -> {len(jsons)} JSON event(s)")

    # Expecting 2 folders (Parent + Child)
    if len(subdirs) >= 2:
        print("\n[RESULT] SUCCESS: Two distinct processes traced.")
        print("   Tcpsnitch correctly follows forks.")
    else:
        print("\n[RESULT] FAILURE or PARTIAL RESULT.")

    # Cleanup
    if os.path.exists(C_SOURCE):
        os.remove(C_SOURCE)
    if os.path.exists(C_BINARY):
        os.remove(C_BINARY)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[WARNING] Run with 'sudo'!")
        sys.exit(1)

    run_fork_test()
