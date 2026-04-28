# ==============================================================================
# TCPSnitch - Build System
# ==============================================================================

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

# Executable & Library names
EXECUTABLE=tcpsnitch
BASE_NAME=lib$(EXECUTABLE).so.$(VERSION)
AMD64=x86-64
I386=i386
ARM64=arm64

LIB_AMD64=$(BASE_NAME)-$(AMD64)
LIB_I386=$(BASE_NAME)-$(I386)
LIB_ARM64=$(BASE_NAME)-$(ARM64)
LIB_ARM64_EBPF=$(BASE_NAME)-$(ARM64)-ebpf

LINUX_GIT_HASH=linux_git_hash
ANDROID_GIT_HASH=android_git_hash
ENABLE_I386=enable_i386

# Installation paths
BIN_PATH=$(DESTDIR)/usr/local/bin
DEPS_PATH=$(BIN_PATH)/tcpsnitch_deps

# ==============================================================================
# LINUX TOOLCHAIN & FLAGS
# ==============================================================================
CC=gcc
C_FLAGS=-g -fPIC --shared -Wl,-Bsymbolic -std=gnu11 -fvisibility=hidden -D_GNU_SOURCE -I$(INC_DIR)

W_FLAGS=-Wall -Wextra -Wunused -Werror -Wfloat-equal -Wshadow -Wpointer-arith \
        -Wstrict-prototypes -Wwrite-strings -Waggregate-return -Wcast-qual \
        -Wunreachable-code -Wno-unused-function

# BPF Toolchain (Linux)
BPF_CLANG ?= clang
BPFTOOL   ?= bpftool
BPF_ARCH  ?= x86

BPF_CFLAGS = -g -O2 -target bpf \
             -D__TARGET_ARCH_$(BPF_ARCH) \
             -I$(INC_DIR) \
             -I/usr/include/x86_64-linux-gnu

BPF_OBJ  = $(BIN_DIR)/tcpsnitch.bpf.o
BPF_SKEL = $(INC_DIR)/tcpsnitch.skel.h

# Linux Dependencies
DEBIAN_BASED_DEPS=-lpthread -ldl -ljansson -l:libpcap.so.0.8 -lbpf
RPM_BASED_DEPS=-lpthread -ldl -l:libjansson.so.4 -lpcap -lbpf
OTHER_DEPS=-lpthread -ldl -lpcap -ljansson -lbpf
LINUX_DEPS=$(shell if rpm -q -f /usr/bin/rpm >/dev/null 2>&1; then echo $(RPM_BASED_DEPS); elif type apt-get >/dev/null 2>&1; then echo $(DEBIAN_BASED_DEPS); else echo $(OTHER_DEPS); fi)

# ==============================================================================
# ANDROID NDK TOOLCHAIN & FLAGS
# ==============================================================================
NDK_ROOT         ?= $(HOME)/Android/Sdk/ndk/android-ndk-r26d
NDK_TC            = $(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64
ANDROID_API      ?= 34
ANDROID_TARGET    = aarch64-linux-android
CC_ANDROID        = $(NDK_TC)/bin/$(ANDROID_TARGET)$(ANDROID_API)-clang
AR_ANDROID        = $(NDK_TC)/bin/llvm-ar

JANSSON_REPO      = https://github.com/akheron/jansson
ANDROID_DEPS_DIR  = android_deps
LIBBPF_REPO       = https://github.com/libbpf/libbpf
ANDROID_BTF_DIR   = android_btf

# Android eBPF linker deps: Jansson is static, libbpf is pulled dynamically from the phone!
ANDROID_EBPF_LINK_DEPS = -L$(ANDROID_DEPS_DIR)/lib \
                         -Wl,-Bstatic -ljansson \
                         -Wl,-Bdynamic -lbpf -ldl -llog

# Android compiler flags
C_FLAGS_ANDROID = -g -fPIC --shared -Wl,-Bsymbolic -std=gnu11 \
                  -fvisibility=hidden -D_GNU_SOURCE \
                  -D__ANDROID__ -DANDROID \
                  -I$(INC_DIR) \
                  -I$(ANDROID_DEPS_DIR)/include

W_FLAGS_ANDROID = -Wall -Wextra -Werror -Wfloat-equal -Wshadow \
                  -Wpointer-arith -Wstrict-prototypes -Wwrite-strings \
                  -Wcast-qual -Wunreachable-code -Wno-unused-function

# Android linker deps (Standard, no eBPF)
ANDROID_LINK_DEPS = -L$(ANDROID_DEPS_DIR)/lib \
                    -Wl,-Bstatic -ljansson \
                    -Wl,-Bdynamic -ldl -llog

# ==============================================================================
# SOURCES DEFINITION
# ==============================================================================
HEADERS = $(wildcard $(INC_DIR)/*.h)
SOURCES = $(wildcard $(SRC_DIR)/*.c)

# 1. Version Android STANDARD (Safe/Stable)
SOURCES_ANDROID = $(filter-out \
    $(SRC_DIR)/ebpf_collector.c \
    $(SRC_DIR)/ebpf_collector_android_bpf.c, \
    $(SOURCES))

# 2. Version Android eBPF (Experimental)
SOURCES_ANDROID_EBPF = $(filter-out \
    $(SRC_DIR)/ebpf_collector.c \
    $(SRC_DIR)/ebpf_collector_android.c, \
    $(SOURCES))

BPF_ANDROID_OBJ = $(BIN_DIR)/tcpsnitch_android.bpf.o

# ==============================================================================
# RULES & TARGETS
# ==============================================================================

define set_file_opt
    echo $(2) > $(BIN_DIR)/$(1)
endef

default: linux

# --- Main Linux Target ---
$(BPF_OBJ): $(BPF_SRC_DIR)/tcpsnitch.bpf.c $(INC_DIR)/bpf_shared_maps.h
	@echo "[-] Compiling BPF kernel program..."
	@mkdir -p $(BIN_DIR) $(BPF_SRC_DIR)
	@$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ)
	@echo "[-] Generating BPF skeleton header..."
	@$(BPFTOOL) gen skeleton $< > $@

linux: $(CONFIG) $(BPF_SKEL) $(HEADERS) $(SOURCES)
	@echo "[-] Compiling Linux 64-bit lib version..."
	@mkdir -p $(BIN_DIR)
	@$(CC) $(C_FLAGS) $(W_FLAGS) $(L_FLAGS) -o ./$(BIN_DIR)/$(LIB_AMD64) $(SOURCES) $(LINUX_DEPS)
	@if grep supports_i386=true .config.in >/dev/null 2>&1; then \
	    echo "[-] Compiling Linux 32-bit lib version..."; \
	    $(CC) $(C_FLAGS) -m32 $(W_FLAGS) $(L_FLAGS) -o ./$(BIN_DIR)/$(LIB_I386) $(SOURCES) $(LINUX_DEPS); \
	    $(call set_file_opt,$(ENABLE_I386),true); \
	else \
	    echo "[-] 32-bit support is disabled."; \
	    $(call set_file_opt,$(ENABLE_I386),false); \
	fi
	@$(call set_file_opt,$(LINUX_GIT_HASH),$(shell git rev-parse HEAD 2>/dev/null || echo "unknown"))

# --- NDK Safety Check ---
check-ndk:
	@if [ ! -d "$(NDK_ROOT)" ]; then \
	    echo "[!] Error: Android NDK not found at '$(NDK_ROOT)'."; \
	    echo "[!] Please verify the NDK_ROOT path in the Makefile."; exit 1; \
	fi

# --- Automatic Setup of Android Deps (Jansson + libbpf pull) ---
setup-android-deps: check-ndk
	@echo "[-] Setting up Android dependencies..."
	@rm -rf _android_build $(ANDROID_DEPS_DIR)
	@mkdir -p $(ANDROID_DEPS_DIR)/include/bpf $(ANDROID_DEPS_DIR)/lib
	@mkdir -p _android_build

	@echo "[-] Building jansson for Android ARM64..."
	@git clone -q --depth 1 $(JANSSON_REPO) _android_build/jansson
	@cd _android_build/jansson && mkdir build && cd build && \
	    cmake -DCMAKE_TOOLCHAIN_FILE=$(NDK_ROOT)/build/cmake/android.toolchain.cmake \
	          -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-$(ANDROID_API) \
	          -DJANSSON_BUILD_SHARED_LIBS=OFF -DJANSSON_BUILD_EXAMPLES=OFF .. > /dev/null 2>&1 && \
	    make -j$(shell nproc) > /dev/null 2>&1
	@cp _android_build/jansson/src/jansson.h $(ANDROID_DEPS_DIR)/include/
	@cp _android_build/jansson/build/include/jansson_config.h $(ANDROID_DEPS_DIR)/include/
	@cp _android_build/jansson/build/lib/libjansson.a $(ANDROID_DEPS_DIR)/lib/

	@echo "[-] Fetching libbpf headers..."
	@git clone -q --depth 1 $(LIBBPF_REPO) _android_build/libbpf
	@cp _android_build/libbpf/src/*.h $(ANDROID_DEPS_DIR)/include/bpf/

	@echo "[-] Pulling libbpf.so directly from the Pixel 7a..."
	@adb shell su -c "cp \`find /system /apex -name libbpf.so 2>/dev/null | grep lib64 | head -n 1\` /data/local/tmp/libbpf.so"
	@adb pull /data/local/tmp/libbpf.so $(ANDROID_DEPS_DIR)/lib/libbpf.so
	@adb shell su -c "rm /data/local/tmp/libbpf.so"

	@rm -rf _android_build
	@echo "[+] Android dependencies are ready."

# --- Main Android Target (Standard LD_PRELOAD) ---
android: check-ndk $(HEADERS) $(SOURCES_ANDROID)
	@if [ ! -d "$(ANDROID_DEPS_DIR)/lib" ]; then $(MAKE) setup-android-deps; fi
	@echo "[-] Compiling Android arm64 lib version..."
	@mkdir -p $(BIN_DIR)
	@$(CC_ANDROID) $(C_FLAGS_ANDROID) $(W_FLAGS_ANDROID) \
	    -o ./$(BIN_DIR)/$(LIB_ARM64) \
	    $(SOURCES_ANDROID) \
	    $(ANDROID_LINK_DEPS)
	@$(call set_file_opt,$(ANDROID_GIT_HASH),$(shell git rev-parse HEAD 2>/dev/null || echo "unknown"))
	@echo "[+] Done: ./$(BIN_DIR)/$(LIB_ARM64)"
	@file ./$(BIN_DIR)/$(LIB_ARM64)

# --- Compile Android eBPF Kernel Object ---
$(BPF_ANDROID_OBJ): $(BPF_SRC_DIR)/tcpsnitch.bpf.c $(INC_DIR)/bpf_shared_maps.h
	@echo "[-] Compiling Android BPF kernel program..."
	@mkdir -p $(BIN_DIR)
	@$(BPF_CLANG) -g -O2 -target bpf \
	    -D__TARGET_ARCH_arm64 -D__ANDROID__ \
	    -I$(ANDROID_BTF_DIR) -I$(INC_DIR) \
	    -c $< -o $@

# --- EBPF ---
android-ebpf: check-ndk $(HEADERS) $(SOURCES_ANDROID_EBPF) $(BPF_ANDROID_OBJ)
	@if [ ! -f "$(ANDROID_DEPS_DIR)/lib/libbpf.so" ]; then $(MAKE) setup-android-deps; fi
	@echo "[-] Compiling Android arm64 eBPF lib version..."
	@mkdir -p $(BIN_DIR)
	@$(CC_ANDROID) $(C_FLAGS_ANDROID) $(W_FLAGS_ANDROID) \
	    -DTCPSNITCH_EBPF_ANDROID \
	    -o ./$(BIN_DIR)/$(LIB_ARM64_EBPF) \
	    $(SOURCES_ANDROID_EBPF) \
	    $(ANDROID_EBPF_LINK_DEPS)
	@$(call set_file_opt,$(ANDROID_GIT_HASH),$(shell git rev-parse HEAD 2>/dev/null || echo "unknown"))
	@echo "[+] Done: ./$(BIN_DIR)/$(LIB_ARM64_EBPF)"
	@file ./$(BIN_DIR)/$(LIB_ARM64_EBPF)

# --- Utility Targets ---
install:
	@echo "[-] Installing binaries to $(BIN_PATH)..."
	@mkdir -p $(DEPS_PATH)
	@install -m 0444 ./$(BIN_DIR)/* $(DEPS_PATH)
	@chmod 0755 $(DEPS_PATH)/$(EXECUTABLE)
	@chmod 0755 $(DEPS_PATH)/*.so*
	@ln -fs $(DEPS_PATH)/$(EXECUTABLE) $(BIN_PATH)/$(EXECUTABLE)
	@echo "[-] Install complete."

uninstall:
	@echo "[-] Uninstalling tcpsnitch..."
	@rm -rf $(DEPS_PATH)
	@rm -f $(BIN_PATH)/$(EXECUTABLE)
	@echo "[-] Uninstall complete."

clean:
	@echo "[-] Cleaning build artifacts..."
	@find ./$(BIN_DIR) -mindepth 1 ! -name 'tcpsnitch' -exec rm -rf {} +
	@rm -f $(CONFIG)
	@find . -type f -name '.DS_Store' -delete
	@find . -type d -name '__pycache__' -exec rm -rf {} +

tests: linux install
	cd tests && make test

index:
	ctags -R .

$(CONFIG):
	@test -f $(CONFIG) || ./configure

.PHONY: configure tests clean index android android-ebpf check-ndk setup-android-deps install uninstall $(CONFIG)