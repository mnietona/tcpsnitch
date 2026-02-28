# Makefile — Benchmark 1 : Overhead tcpsnitch

.PHONY: all run analyze clean check-deps

PYTHON   := python3
SHELL    := /bin/bash

all: check-deps run analyze

check-deps:
	@echo "── Vérification des dépendances ──────────────────────"
	@command -v curl  >/dev/null || (echo "❌ curl manquant"  && exit 1)
	@command -v bc    >/dev/null || (echo "❌ bc manquant — sudo apt install bc" && exit 1)
	@$(PYTHON) -c "import matplotlib" 2>/dev/null || \
		echo "⚠️  matplotlib absent — graphique désactivé (pip install matplotlib --break-system-packages)"
	@echo "✅ Dépendances OK"

run: check-deps
	@echo "── Lancement de la collecte (≈ 30 min) ───────────────"
	bash run_benchmark.sh

analyze:
	@echo "── Analyse des résultats ─────────────────────────────"
	$(PYTHON) analyze.py

clean:
	@echo "── Nettoyage ─────────────────────────────────────────"
	@sudo rm -rf output/
	@echo "✅ output/ supprimé"
