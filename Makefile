# Version
MAJOR_VERSION=0
MINOR_VERSION=1
VERSION=$(MAJOR_VERSION).$(MINOR_VERSION)

CONFIG=.config.in

# Directories
SRC_DIR=src
INC_DIR=include
BIN_DIR=bin
BPF_SRC_DIR=src/bpf

# ./bin names
EXECUTABLE=tcpsnitch
BASE_NAME=lib$(EXECUTABLE).so.$(VERSION)
AMD64=x86-64
I386=i386
ARM=arm
LIB_AMD64=$(BASE_NAME)-$(AMD64)
LIB_I386=$(BASE_NAME)-$(I386)
LIB_ARM=$(BASE_NAME)-$(ARM)
LINUX_GIT_HASH=linux_git_hash
ANDROID_GIT_HASH=android_git_hash
ENABLE_I386=enable_i386

# Installation paths
BIN_PATH=$(DESTDIR)/usr/local/bin
DEPS_PATH=$(BIN_PATH)/tcpsnitch_deps

# Compiler & linker flags
CC=gcc
C_FLAGS=-g -fPIC --shared -Wl,-Bsymbolic -std=gnu11 -fvisibility=hidden -D_GNU_SOURCE -I$(INC_DIR)

# -Wno-unused-function : le squelette généré par bpftool contient des fonctions
# statiques inline qui peuvent ne pas toutes être utilisées dans ebpf_collector.c
W_FLAGS=-Wall -Wextra -Werror -Wfloat-equal -Wshadow -Wpointer-arith \
        -Wstrict-prototypes -Wwrite-strings -Waggregate-return -Wcast-qual \
        -Wunreachable-code -Wno-unused-function

# BPF toolchain
BPF_CLANG ?= clang
BPFTOOL   ?= bpftool
BPF_ARCH  ?= x86

# Flags pour le programme côté noyau :
#   -target bpf  : cross-compilation pour la machine virtuelle BPF
#   -g           : émet les infos BTF nécessaires pour CO-RE (Compile Once - Run Everywhere)
#   -O2          : le vérificateur BPF rejette le code non optimisé
BPF_CFLAGS = -g -O2 -target bpf \
             -D__TARGET_ARCH_$(BPF_ARCH) \
             -I$(INC_DIR) \
             -I/usr/include/x86_64-linux-gnu

# Artéfacts générés par la chaîne BPF
BPF_OBJ  = $(BIN_DIR)/tcpsnitch.bpf.o
BPF_SKEL = $(INC_DIR)/tcpsnitch.skel.h

# Dependencies 
# -lbpf ajouté sur tous les targets Linux (pas Android)
DEBIAN_BASED_DEPS=-lpthread -ldl -ljansson -l:libpcap.so.0.8 -lbpf
RPM_BASED_DEPS=-lpthread -ldl -l:libjansson.so.4 -lpcap -lbpf
OTHER_DEPS=-lpthread -ldl -lpcap -ljansson -lbpf
LINUX_DEPS=$(shell if rpm -q -f /usr/bin/rpm >/dev/null 2>&1; then echo $(RPM_BASED_DEPS); elif type apt-get >/dev/null 2>&1; then echo $(DEBIAN_BASED_DEPS); else echo $(OTHER_DEPS); fi)

# Source files (Automatisé avec wildcard pour prendre tout ce qui est dans src et include)
HEADERS=$(wildcard $(INC_DIR)/*.h)
SOURCES=$(wildcard $(SRC_DIR)/*.c)

# $(1) is file name, $(2) is config value
define set_file_opt
    echo $(2) > $(BIN_DIR)/$(1)
endef

default: linux

# Pipeline BPF 

# Étape BPF 1 : compile le programme C eBPF en objet ELF BPF
$(BPF_OBJ): $(BPF_SRC_DIR)/tcpsnitch.bpf.c $(INC_DIR)/bpf_shared_maps.h
	@echo "[-] Compiling BPF kernel program..."
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(BPF_SRC_DIR)
	@$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

# Étape BPF 2 : génère le header squelette libbpf depuis l'objet BPF
#              Ce header est inclus par ebpf_collector.c pour charger/attacher
#              les programmes et accéder aux maps via leurs file descriptors.
$(BPF_SKEL): $(BPF_OBJ)
	@echo "[-] Generating BPF skeleton header..."
	@$(BPFTOOL) gen skeleton $< > $@

# Main Linux target 
linux: $(CONFIG) $(BPF_SKEL) $(HEADERS) $(SOURCES)
	@echo "[-] Compiling Linux 64-bit lib version..."
	@mkdir -p $(BIN_DIR)
	@$(CC) $(C_FLAGS) $(W_FLAGS) $(L_FLAGS) -o ./$(BIN_DIR)/$(LIB_AMD64) $(SOURCES) $(LINUX_DEPS)
	@if grep supports_i386=true .config.in >/dev/null 2>&1; then\
        echo "[-] Compiling Linux 32-bit lib version...";\
        $(CC) $(C_FLAGS) -m32 $(W_FLAGS) $(L_FLAGS) -o ./$(BIN_DIR)/$(LIB_I386) $(SOURCES) $(LINUX_DEPS);\
        $(call set_file_opt,$(ENABLE_I386),true);\
    else\
        echo "[-] 32-bit support is disabled.";\
        $(call set_file_opt,$(ENABLE_I386),false);\
    fi
	@$(call set_file_opt,$(LINUX_GIT_HASH),$(shell git rev-parse HEAD 2>/dev/null || echo "unknown"))

android: $(HEADERS) $(SOURCES)
ifndef CC_ANDROID
	$(error CC_ANDROID variable not set. See README for compilation instructions)
endif
	@echo "[-] Compiling Android lib version..."
	@mkdir -p $(BIN_DIR)
	@$(CC_ANDROID) $(C_FLAGS) $(W_FLAGS) $(L_FLAGS) -o ./$(BIN_DIR)/$(LIB_ARM) $(SOURCES) -Wl,-Bstatic -ljansson -lpcap -Wl,-Bdynamic -ldl -llog
	@$(call set_file_opt,$(ANDROID_GIT_HASH),$(shell git rev-parse HEAD 2>/dev/null || echo "unknown"))

install:
	mkdir -p $(DEPS_PATH)
	install -m 0444 ./$(BIN_DIR)/* $(DEPS_PATH)
	chmod 0755 $(DEPS_PATH)/$(EXECUTABLE)
	ln -fs ./tcpsnitch_deps/$(EXECUTABLE) $(BIN_PATH)/$(EXECUTABLE)

uninstall:
	@rm -rf $(DEPS_PATH)
	@rm $(BIN_PATH)/$(EXECUTABLE)

clean:
	@echo "[-] Cleaning build artifacts..."
	@rm -f ./$(BIN_DIR)/*.so* ./$(BIN_DIR)/*hash ./$(BIN_DIR)/enable_i386 $(CONFIG)
	@rm -f $(BPF_OBJ) $(BPF_SKEL)
	@find . -type f -name '.DS_Store' -delete
	@find . -type f -name '._*' -delete

tests: linux install
	cd tests && rake

index:
	ctags -R .

$(CONFIG):
	@test -f $(CONFIG) || ./configure

.PHONY: configure tests clean index android $(CONFIG)