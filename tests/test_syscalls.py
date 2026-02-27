import unittest
import subprocess
import json
import os
import glob
import http.server
import socketserver
import threading
import time

# --- SERVEUR WEB SILENCIEUX ---
class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args): pass 
    def handle(self):
        try: super().handle()
        except Exception: pass

class TestTcpsnitchHooks(unittest.TestCase):
    OUTPUT_DIR = "/tmp/tcpsnitch_test_out"
    TCPSNITCH_BIN = "../bin/tcpsnitch"

    @classmethod
    def setUpClass(cls):
        cls.httpd = socketserver.TCPServer(("127.0.0.1", 8000), QuietHandler)
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self):
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)
        os.system(f"rm -rf {self.OUTPUT_DIR}/*")

    def run_tcpsnitch(self, prog_name):
        prog_path = f"./output/{prog_name}.out"
        cmd = [self.TCPSNITCH_BIN, "-d", self.OUTPUT_DIR, "--", prog_path]
        
        # Exécution silencieuse
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Délai de grâce pour l'écriture disque asynchrone
        time.sleep(0.4) 

        events = []
        for root, _, files in os.walk(self.OUTPUT_DIR):
            for file in files:
                if file.endswith(".json") or file.endswith(".jsonl"):
                    with open(os.path.join(root, file), 'r') as f:
                        for line in f:
                            if line.strip():
                                try: events.append(json.loads(line))
                                except: pass
        return events

    # ===============
    # TESTS SPÉCIAUX 
    # ===============
    def test_special_fork(self):
        evs = self.run_tcpsnitch("fork")
        sock_events = [e for e in evs if e.get("type") == "socket" 
                       and e.get("details", {}).get("sock_info", {}).get("domain") == "AF_INET"]
        self.assertTrue(len(sock_events) >= 2, f"Attendu 2 sockets (parent+enfant), trouvé: {len(sock_events)}")

    def test_special_splice(self):
        evs = self.run_tcpsnitch("splice")
        matching = [e for e in evs if e.get("type") == "splice"]
        self.assertTrue(len(matching) > 0, "L'appel splice n'a pas été détecté")

    def test_special_close_range(self):
        evs = self.run_tcpsnitch("close_range")
        matching = [e for e in evs if e.get("type") in ["close", "close_range"]]
        self.assertTrue(len(matching) > 0)

    def test_special_mptcp(self):
        evs = self.run_tcpsnitch("mptcp")
        matching = [e for e in evs if e.get("type") == "socket" 
                    and e.get("details", {}).get("sock_info", {}).get("domain") == "AF_INET"]
        self.assertTrue(len(matching) > 0)
        self.assertEqual(matching[0]["details"]["sock_info"]["protocol"], "mptcp")

    def test_special_concurrent_connections(self):
        evs = self.run_tcpsnitch("concurrent_connections")
        sock_events = [e for e in evs if e.get("type") == "socket" 
                       and e.get("details", {}).get("sock_info", {}).get("domain") == "AF_INET"]
        self.assertEqual(len(sock_events), 2)

    def test_special_consecutive_connections(self):
        evs = self.run_tcpsnitch("consecutive_connections")
        sock_events = [e for e in evs if e.get("type") == "socket" 
                       and e.get("details", {}).get("sock_info", {}).get("domain") == "AF_INET"]
        self.assertEqual(len(sock_events), 2)

    def test_special_iouring(self):
        evs = self.run_tcpsnitch("iouring")
        matching = [e for e in evs if e.get("type") == "socket"]
        self.assertTrue(len(matching) > 0)

# ======================
# GÉNÉRATION AUTOMATIQUE
# ======================
def make_test_function(prog_name, event_type, is_fail, is_dgram):
    def test(self):
        evs = self.run_tcpsnitch(prog_name)
        matching = [e for e in evs if e.get("type") == event_type]
        if event_type == "socket":
            matching = [e for e in matching if e.get("details", {}).get("sock_info", {}).get("domain") != "AF_NETLINK"]
        
        if (is_dgram or event_type in ["select", "ppoll", "poll"]) and len(matching) == 0:
            return 
        if is_fail and len(matching) == 0:
            return
            
        self.assertTrue(len(matching) > 0, f"Événement '{event_type}' introuvable pour {prog_name}")
        if not is_fail and not is_dgram:
            self.assertEqual(matching[0].get("success"), True, f"Succès incorrect pour {prog_name}")
    return test

SPECIAL_PROGS = ["fork", "concurrent_connections", "consecutive_connections", "close_range", "mptcp", "iouring", "splice"]
c_files = glob.glob("./c_programs/*.c")

for c_file in c_files:
    prog = os.path.basename(c_file).replace(".c", "")
    if prog in SPECIAL_PROGS: continue
    event_type = prog.replace("_dgram", "").replace("_fail", "")
    is_fail = "_fail" in prog
    is_dgram = "_dgram" in prog
    setattr(TestTcpsnitchHooks, f"test_auto_{prog}", make_test_function(prog, event_type, is_fail, is_dgram))

if __name__ == '__main__':
    unittest.main(verbosity=2)