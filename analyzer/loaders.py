import streamlit as st
import json
import glob
import os
import pandas as pd

@st.cache_data
def load_session(session_path: str):
    events = []
    socket_files = sorted(
        glob.glob(os.path.join(session_path, "[0-9]*.json")),
        key=lambda x: int(os.path.basename(x).replace(".json", ""))
    )
    for sock_file in socket_files:
        sock_id = int(os.path.basename(sock_file).replace(".json", ""))
        try:
            with open(sock_file, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    try:
                        ev = json.loads(line)
                        ev["_socket_id"] = sock_id
                        events.append(ev)
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass
    return events

@st.cache_data
def load_ebpf(session_path: str):
    ebpf = []
    fp = os.path.join(session_path, "ebpf_events.jsonl")
    if not os.path.exists(fp): return ebpf
    try:
        with open(fp) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try: ebpf.append(json.loads(line))
                except json.JSONDecodeError: pass
    except Exception:
        pass
    return ebpf

@st.cache_data
def load_netlink(session_path: str):
    nl_events = []
    fp = os.path.join(session_path, "netlink_events.jsonl")
    if not os.path.exists(fp): return nl_events
    try:
        with open(fp) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try: nl_events.append(json.loads(line))
                except json.JSONDecodeError: pass
    except Exception:
        pass
    return nl_events

@st.cache_data
def load_meta(session_path: str):
    """
    Lit tous les fichiers du dossier /meta/ et retourne un dictionnaire.
    Exemple : {"app": "org.wikipedia", "os": "Android", "kernel": "5.10"}
    """
    meta_data = {}
    meta_dir = os.path.join(session_path, "meta")
    
    if os.path.exists(meta_dir) and os.path.isdir(meta_dir):
        for filename in os.listdir(meta_dir):
            filepath = os.path.join(meta_dir, filename)
            if os.path.isfile(filepath):
                try:
                    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                        # On lit le contenu et on enlève les sauts de ligne
                        meta_data[filename] = f.read().strip()
                except Exception:
                    pass
    return meta_data

def find_sessions(base_dir: str):
    dirs = [d for d in glob.glob(os.path.join(base_dir, "*/")) if os.path.isdir(d)]
    return [d.rstrip("/") for d in sorted(dirs, reverse=True)]