.PHONY: all run analyze clean check-deps

PYTHON   := python3
SHELL    := /bin/bash

all: check-deps run analyze

check-deps:
	@command -v curl >/dev/null || (echo "curl manquant" && exit 1)
	@command -v tc >/dev/null || (echo "commande 'tc' manquante (paquet iproute2) — requise pour simuler la perte de paquets" && exit 1)
	@if [ ! -f /usr/bin/time ]; then echo "/usr/bin/time manquant (paquet time) — requis pour mesurer CPU/RAM"; exit 1; fi
	@echo "Dépendances OK"

run: check-deps
	bash run_benchmark.sh

analyze:
	$(PYTHON) analyze.py

clean:
	@sudo rm -rf output/
	@sudo rm -f 100MB.bin