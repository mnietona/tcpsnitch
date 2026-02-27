Voici le contenu au format Markdown (.md) :

```markdown
# tcpsnitch - Validation Suite

This directory contains the functional test suite for `tcpsnitch`. It ensures that all intercepted syscalls (LD_PRELOAD) and kernel events (eBPF) are correctly captured and serialized.

## Dependencies

- **Python 3.x**: Used for test orchestration and JSON validation.
- **GCC**: To compile the C test programs.
- **liburing-dev**: Required for `io_uring` test coverage.
- **Sudo**: Required to attach eBPF probes to the kernel.

## Installation

Ensure the required system libraries are installed:
```bash
sudo apt update
sudo apt install python3 gcc liburing-dev
```

## Running the Tests

The simplest way to run the entire suite (115 tests) is to use the provided Makefile:

```bash
make test
```

Manual execution (if already compiled):

```bash
make
sudo python3 test_syscalls.py
```

## Structure

- **c_programs/**: Contains C source files, each targeting a specific syscall or edge case (e.g., `bind_fail.c`, `mptcp.c`).
- **output/**: Directory where compiled test binaries are stored.
- **test_syscalls.py**: The main Python test runner using unittest. It launches a local dummy HTTP server on port 8000 to validate network connections.

## Adding a test

To add a new syscall test:

1. Create a new `.c` file in `c_programs/`.
2. Run `make`.
3. The Python script will automatically detect the new `.out` file and generate a corresponding test case based on the filename (e.g., `mytest_fail.c` will expect a failure log).