# Makefile — Benchmark 2 : Corrélation eBPF session_id

.PHONY: all run analyze clean check-deps

PYTHON := python3

all: check-deps run analyze

check-deps:
	@echo "── Vérification des dépendances ──────────────────────"
	@command -v tc         >/dev/null || (echo "❌ iproute2 manquant" && exit 1)
	@command -v $(PYTHON)  >/dev/null || (echo "❌ python3 manquant" && exit 1)
	@$(PYTHON) -c "import matplotlib" 2>/dev/null || \
		echo "⚠️  matplotlib absent — graphique désactivé"
	@echo "✅ Dépendances OK"

run: check-deps
	@echo "── Lancement de la collecte (≈ 5 min) ────────────────"
	@bash run_benchmark.sh

analyze:
	@echo "── Analyse des résultats ─────────────────────────────"
	@$(PYTHON) analyze.py

clean:
	@echo "── Nettoyage ─────────────────────────────────────────"
	@sudo rm -rf output/
	@echo "✅ output/ supprimé"