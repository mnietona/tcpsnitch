CC = gcc
CFLAGS = -Wall -Wextra -D_GNU_SOURCE -Wno-stringop-overflow -Wno-nonnull
LDLIBS = -luring

SRCDIR = c_programs
OUTDIR = output
PYTHON = python3

SRCS = $(wildcard $(SRCDIR)/*.c)
BINS = $(patsubst $(SRCDIR)/%.c, $(OUTDIR)/%.out, $(SRCS))

.PHONY: all clean test

all: $(OUTDIR) $(BINS)

$(OUTDIR):
	@echo "[-] Creating output directory..."
	@mkdir -p $(OUTDIR)

$(OUTDIR)/%.out: $(SRCDIR)/%.c | $(OUTDIR)
	@echo "[-] Compiling $<..."
	@$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

test: all
	@echo "[-] Running tcpsnitch validation suite (requires sudo for eBPF)..."
	@sudo $(PYTHON) test_syscalls.py

clean:
	@echo "[-] Cleaning..."
	@sudo rm -rf $(OUTDIR)/
	@rm -rf __pycache__