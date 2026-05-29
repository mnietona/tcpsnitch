.PHONY: all run analyze clean check-deps

PYTHON := python3

all: check-deps run analyze

check-deps:
	@command -v tc         >/dev/null || (echo "iproute2 manquant" && exit 1)
	@command -v $(PYTHON)  >/dev/null || (echo "python3 manquant" && exit 1)
	@$(PYTHON) -c "import matplotlib" 2>/dev/null || \
		echo "matplotlib absent — graphique désactivé"
	@echo "Dépendances OK"

run: check-deps
	@bash run_benchmark.sh

analyze:
	@$(PYTHON) analyze.py

clean:
	@sudo rm -rf output/
