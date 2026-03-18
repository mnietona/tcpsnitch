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
ARM=arm
ARM64=arm64

LIB_AMD64=$(BASE_NAME)-$(AMD64)
LIB_I386=$(BASE_NAME)-$(I386)
LIB_ARM=$(BASE_NAME)-$(ARM)
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

# -Wno-unused-function : prevents errors from unused static inline functions in the BPF skeleton
W_FLAGS=-Wall -Wextra -Wunused -Werror -Wfloat-equal -Wshadow -Wpointer-arith \
        -Wstrict-prototypes -Wwrite-strings -Waggregate-return -Wcast-qual \
        -Wunreachable-code -Wno-unused-function

# BPF Toolchain (Linux)
BPF_CLANG ?= clang
BPFTOOL   ?= bpftool
BPF_ARCH  ?= x86

# BPF Flags: -target bpf for VM compilation, -g for BTF/CO-RE, -O2 required by Verifier
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

JANSSON_REPO = https://github.com/akheron/jansson
ANDROID_DEPS_DIR  = android_deps

# Android compiler flags
C_FLAGS_ANDROID = -g -fPIC --shared -Wl,-Bsymbolic -std=gnu11 \
                  -fvisibility=hidden -D_GNU_SOURCE \
                  -D__ANDROID__ -DANDROID \
                  -I$(INC_DIR) \
                  -I$(ANDROID_DEPS_DIR)/include

W_FLAGS_ANDROID = -Wall -Wextra -Werror -Wfloat-equal -Wshadow \
                  -Wpointer-arith -Wstrict-prototypes -Wwrite-strings \
                  -Wcast-qual -Wunreachable-code -Wno-unused-function

# Android linker deps (static jansson, no pcap, logcat support)
ANDROID_LINK_DEPS = -L$(ANDROID_DEPS_DIR)/lib -Wl,-Bstatic -ljansson \
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

# --- Linux BPF Pipeline ---
$(BPF_OBJ): $(BPF_SRC_DIR)/tcpsnitch.bpf.c $(INC_DIR)/bpf_shared_maps.h
	@echo "[-] Compiling BPF kernel program..."
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(BPF_SRC_DIR)
	@$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ)
	@echo "[-] Generating BPF skeleton header..."
	@$(BPFTOOL) gen skeleton $< > $@

# --- Main Linux Target ---
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

# --- NDK Safety Check (Hard fail only for NDK) ---
check-ndk:
	@if [ ! -d "$(NDK_ROOT)" ]; then \
		echo "[!] Error: Android NDK not found at '$(NDK_ROOT)'."; \
		echo "[!] Please export NDK_ROOT=/path/to/ndk"; exit 1; \
	fi

# --- Automatic Setup of libjansson ---
setup-android-deps: check-ndk
	@echo "[-] Android dependencies missing. Starting automatic setup..."
	@rm -rf jansson_tmp $(ANDROID_DEPS_DIR)
	@mkdir -p $(ANDROID_DEPS_DIR)/include $(ANDROID_DEPS_DIR)/lib
	@echo "[-] Cloning jansson..."
	@git clone -q --depth 1 $(JANSSON_REPO) jansson_tmp > /dev/null 2>&1
	@echo "[-] Compiling jansson for Android (ARM64/API $(ANDROID_API))..."
	@cd jansson_tmp && mkdir build && cd build && \
		cmake -DCMAKE_TOOLCHAIN_FILE=$(NDK_ROOT)/build/cmake/android.toolchain.cmake \
		      -DANDROID_ABI=arm64-v8a \
		      -DANDROID_PLATFORM=android-$(ANDROID_API) \
		      -DJANSSON_BUILD_SHARED_LIBS=OFF \
		      -DJANSSON_BUILD_EXAMPLES=OFF .. > /dev/null 2>&1 && \
		make -j$(nproc) > /dev/null 2>&1
	@echo "[-] Installing headers and static lib..."
	@cp jansson_tmp/src/jansson.h $(ANDROID_DEPS_DIR)/include/
	@cp jansson_tmp/build/include/jansson_config.h $(ANDROID_DEPS_DIR)/include/
	@cp jansson_tmp/build/lib/libjansson.a $(ANDROID_DEPS_DIR)/lib/
	@rm -rf jansson_tmp
	@echo "[+] Android dependencies are ready."

# --- Main Android Target (Standard LD_PRELOAD) ---
android: check-ndk $(HEADERS) $(SOURCES_ANDROID)
	@if [ ! -d "$(ANDROID_DEPS_DIR)" ]; then $(MAKE) setup-android-deps; fi
	@echo "[-] Compiling Android arm64 lib version..."
	@mkdir -p $(BIN_DIR)
	@$(CC_ANDROID) $(C_FLAGS_ANDROID) $(W_FLAGS_ANDROID) \
		-o ./$(BIN_DIR)/$(LIB_ARM64) \
		$(SOURCES_ANDROID) \
		$(ANDROID_LINK_DEPS)
	@$(call set_file_opt,$(ANDROID_GIT_HASH),$(shell git rev-parse HEAD 2>/dev/null || echo "unknown"))
	@echo "[+] Done: ./$(BIN_DIR)/$(LIB_ARM64)"
	@file ./$(BIN_DIR)/$(LIB_ARM64)

# --- Experimental Android Target (eBPF) ---
android-ebpf: check-ndk $(HEADERS) $(SOURCES_ANDROID_EBPF) $(BPF_ANDROID_OBJ)
	@if [ ! -d "$(ANDROID_DEPS_DIR)" ]; then $(MAKE) setup-android-deps; fi
	@echo "[-] Compiling Android arm64 eBPF lib version..."
	@mkdir -p $(BIN_DIR)
	@$(CC_ANDROID) $(C_FLAGS_ANDROID) $(W_FLAGS_ANDROID) \
		-DTCPSNITCH_EBPF_ANDROID \
		-o ./$(BIN_DIR)/$(LIB_ARM64_EBPF) \
		$(SOURCES_ANDROID_EBPF) \
		$(ANDROID_LINK_DEPS)
	@echo "[+] Done: ./$(BIN_DIR)/$(LIB_ARM64_EBPF)"
	@file ./$(BIN_DIR)/$(LIB_ARM64_EBPF)

# Compile Android eBPF Kernel Object
$(BPF_ANDROID_OBJ): $(BPF_SRC_DIR)/tcpsnitch_android.bpf.c
	@echo "[-] Compiling Android BPF kernel program..."
	@$(BPF_CLANG) -O2 -target bpf \
		-D__TARGET_ARCH_arm64 -D__ANDROID__ \
		-I$(INC_DIR) -I/usr/include -I/usr/include/x86_64-linux-gnu \
		-c $< -o $@

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
	@rm -f ./$(BIN_DIR)/*.so* ./$(BIN_DIR)/*hash ./$(BIN_DIR)/enable_i386 $(CONFIG)
	@rm -f $(BPF_OBJ) $(BPF_SKEL) $(BPF_ANDROID_OBJ)
	@find . -type f -name '.DS_Store' -delete
	@find . -type f -name '._*' -delete

tests: linux install
	cd tests && make test

index:
	ctags -R .

$(CONFIG):
	@test -f $(CONFIG) || ./configure

.PHONY: configure tests clean index android android-ebpf check-ndk install uninstall $(CONFIG)