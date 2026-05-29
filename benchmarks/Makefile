# Détecte automatiquement tous les dossiers commençant par "0" et les trie
SUBDIRS := $(sort $(wildcard 0*/))

.PHONY: all clean run analyze

all:
	@echo "DÉMARRAGE DE LA SUITE COMPLÈTE DES BENCHMARKS..."
	@for dir in $(SUBDIRS); do \
		echo ""; \
		echo "============================================================"; \
		echo " LANCEMENT : $$dir"; \
		echo "============================================================"; \
		$(MAKE) -C $$dir all || exit 1; \
	done
	@echo ""
	@echo "TOUTES LES EXPÉRIENCES SONT TERMINÉES AVEC SUCCÈS !"

clean:
	@echo "NETTOYAGE GLOBAL..."
	@for dir in $(SUBDIRS); do \
		echo " -> Nettoyage de $$dir"; \
		$(MAKE) -C $$dir clean || true; \
	done

run:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir run || exit 1; done

analyze:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir analyze || exit 1; done