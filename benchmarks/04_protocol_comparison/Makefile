.PHONY: all run analyze clean check-deps

PYTHON := python3

all: check-deps run analyze

check-deps:
	@command -v curl        >/dev/null || (echo "curl manquant" && exit 1)
	@command -v tc          >/dev/null || (echo "iproute2 manquant" && exit 1)
	@command -v tcpsnitch   >/dev/null || (echo "tcpsnitch manquant" && exit 1)
	@curl --version | grep -q "HTTP3\|http3\|QUIC\|quic" || \
		echo "curl sans HTTP/3 — scénario HTTP/3 sera vide (normal)"
	@$(PYTHON) -c "import matplotlib" 2>/dev/null || \
		echo "matplotlib absent — graphique désactivé"
	@echo "Dépendances OK"

run: check-deps
	@bash run_benchmark.sh

analyze:
	@$(PYTHON) analyze.py
	@$(PYTHON) analyze_cwnd.py

clean:
	@sudo rm -rf output/ /tmp/bench4_payload.bin