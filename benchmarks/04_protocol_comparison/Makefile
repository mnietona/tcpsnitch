# Makefile — Benchmark 4 : Comparaison de protocoles

.PHONY: all run analyze clean check-deps

PYTHON := python3

all: check-deps run analyze

check-deps:
	@echo "── Vérification des dépendances ──────────────────────"
	@command -v curl        >/dev/null || (echo "❌ curl manquant" && exit 1)
	@command -v tc          >/dev/null || (echo "❌ iproute2 manquant" && exit 1)
	@command -v tcpsnitch   >/dev/null || (echo "❌ tcpsnitch manquant" && exit 1)
	@curl --version | grep -q "HTTP3\|http3\|QUIC\|quic" || \
		echo "⚠️  curl sans HTTP/3 — scénario HTTP/3 sera vide (normal)"
	@$(PYTHON) -c "import matplotlib" 2>/dev/null || \
		echo "⚠️  matplotlib absent — graphique désactivé"
	@echo "✅ Dépendances OK"

run: check-deps
	@echo "── Lancement de la collecte (≈ 15-20 min) ────────────"
	@bash run_benchmark.sh

analyze:
	@echo "── Analyse des résultats ─────────────────────────────"
	@$(PYTHON) analyze.py
	@echo "── Génération de la dent de scie TCP (cwnd) ──────────"
	@$(PYTHON) analyze_cwnd.py

clean:
	@echo "── Nettoyage ─────────────────────────────────────────"
	@sudo rm -rf output/ /tmp/bench4_payload.bin
	@echo "✅ output/ supprimé"