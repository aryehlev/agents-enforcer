# Makefile for eBPF programs
# Compiles C eBPF programs to bytecode

CLANG ?= clang
LLC ?= llc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Kernel headers location
KERNEL_HEADERS ?= /usr/src/linux-headers-$(shell uname -r)
LIBBPF_HEADERS ?= /usr/include

# Clang flags for eBPF compilation
CLANG_FLAGS := -target bpf \
    -D__TARGET_ARCH_$(ARCH) \
    -I$(KERNEL_HEADERS)/include \
    -I$(KERNEL_HEADERS)/include/uapi \
    -I$(KERNEL_HEADERS)/arch/$(ARCH)/include \
    -I$(LIBBPF_HEADERS) \
    -g -O2 \
    -Wall -Werror

# Source files
SRCS := lsm.c network.c
OBJS := $(SRCS:.c=.o)

.PHONY: all clean install

all: $(OBJS)
	@echo "eBPF programs compiled successfully"
	@ls -la *.o

%.o: %.c
	@echo "Compiling $< -> $@"
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)

install: $(OBJS)
	@mkdir -p /usr/lib/agent-gateway-enforcer
	cp $(OBJS) /usr/lib/agent-gateway-enforcer/
	@echo "Installed to /usr/lib/agent-gateway-enforcer/"

# Development target - shows detected paths
info:
	@echo "Architecture: $(ARCH)"
	@echo "Kernel headers: $(KERNEL_HEADERS)"
	@echo "Clang: $(shell $(CLANG) --version | head -1)"
	@echo "Sources: $(SRCS)"
