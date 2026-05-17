# Makefile — Benchmark 1 : Overhead tcpsnitch

.PHONY: all run analyze clean check-deps

PYTHON   := python3
SHELL    := /bin/bash

all: check-deps run analyze

check-deps:
	@echo "── Vérification des dépendances ──────────────────────"
	@command -v curl >/dev/null || (echo "❌ curl manquant" && exit 1)
	@command -v tc >/dev/null || (echo "❌ commande 'tc' manquante (paquet iproute2) — requise pour simuler la perte de paquets" && exit 1)
	@if [ ! -f /usr/bin/time ]; then echo "❌ /usr/bin/time manquant (paquet time) — requis pour mesurer CPU/RAM"; exit 1; fi
	@echo "✅ Dépendances OK"

run: check-deps
	@echo "── Lancement de la collecte (≈ 45 min) ───────────────"
	bash run_benchmark.sh

analyze:
	@echo "── Analyse des résultats ─────────────────────────────"
	$(PYTHON) analyze.py

clean:
	@echo "── Nettoyage ─────────────────────────────────────────"
	@sudo rm -rf output/
	@echo "✅ Dossier output/ supprimé"