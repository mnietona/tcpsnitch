# Makefile — Benchmark 5 : Stress test

.PHONY: all run analyze clean check-deps

PYTHON := python3

all: check-deps run analyze

check-deps:
	@echo "── Vérification des dépendances ──────────────────────"
	@command -v tcpsnitch  >/dev/null || (echo "❌ tcpsnitch manquant" && exit 1)
	@command -v pgrep      >/dev/null || (echo "❌ pgrep manquant — sudo apt install procps" && exit 1)
	@$(PYTHON) -c "import ctypes" 2>/dev/null || (echo "❌ ctypes manquant" && exit 1)
	@$(PYTHON) -c "import matplotlib" 2>/dev/null || \
		echo "⚠️  matplotlib absent — graphique désactivé"
	@echo "✅ Dépendances OK"

run: check-deps
	@echo "── Lancement de la collecte (≈ 15 min) ───────────────"
	@echo "⚠️  Le scénario C dure 10 min — ne pas interrompre"
	@bash run_benchmark.sh

analyze: 
	@echo "── Analyse des résultats ─────────────────────────────"
	@$(PYTHON) analyze.py

clean:
	@echo "── Nettoyage ─────────────────────────────────────────"
	@sudo rm -rf output/ /tmp/stress_*.py
	@echo "✅ output/ supprimé"