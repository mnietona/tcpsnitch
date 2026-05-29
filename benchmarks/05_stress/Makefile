.PHONY: all run analyze clean check-deps

PYTHON := python3

all: check-deps run analyze

check-deps:
	@command -v tcpsnitch  >/dev/null || (echo " tcpsnitch manquant" && exit 1)
	@command -v pgrep      >/dev/null || (echo " pgrep manquant — sudo apt install procps" && exit 1)
	@command -v gcc        >/dev/null || (echo " gcc manquant — requis pour les scénarios D et E" && exit 1)
	@$(PYTHON) -c "import ctypes" 2>/dev/null || (echo " ctypes manquant" && exit 1)
	@$(PYTHON) -c "import matplotlib" 2>/dev/null || \
		echo " matplotlib absent — graphique désactivé"
	@echo "Dépendances OK"

run: check-deps
	@bash run_benchmark.sh

analyze: 
	@$(PYTHON) analyze.py

clean:
	@sudo rm -rf output/ /tmp/stress_*.py /tmp/stress_*.c /tmp/stress_e /tmp/stress_d