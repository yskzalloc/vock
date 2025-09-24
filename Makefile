# Compiler
CC ?= clang
CFLAGS += -Wall -O2
LDFLAGS +=

# Auto-detect kernel BTF (can be overridden: make DEBUG_INFO_BTF=1)
DEBUG_INFO_BTF ?= $(shell [ -e /sys/kernel/btf/vmlinux ] && echo 1 || echo 0)

# Project
TOOL_NAME = vock

TARGET_EXE = vock
EXE_SOURCE = vock.c

TARGET_LIB = kcovpre.so
LIB_SOURCE = kcovpre.c

BPF_SRC = syscall.bpf.c
BPF_OBJ = syscall.bpf.o

INSTALL_DIR = /usr/local/lib/$(TOOL_NAME)
BIN_DIR = /usr/local/bin

# If BTF exists, enable syscall tracing build.
ifeq ($(DEBUG_INFO_BTF),1)
  CFLAGS += -DDEBUG_INFO_BTF=1
  BUILD_BPF := 1
else
  BUILD_BPF := 0
endif

.PHONY: all
all: $(TARGET_EXE) $(TARGET_LIB) $(if $(filter 1,$(BUILD_BPF)),$(BPF_OBJ))

# vock driver
$(TARGET_EXE): $(EXE_SOURCE)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# preload library (KCOV only)
$(TARGET_LIB): $(LIB_SOURCE)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

# eBPF compile only when BTF is present
ifeq ($(BUILD_BPF),1)
$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	clang -O2 -g -target bpf -c $< -o $@

# Generate vmlinux.h from kernel BTF
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@
endif

.PHONY: install
install: all
	@echo "Installing $(TOOL_NAME) (DEBUG_INFO_BTF=$(DEBUG_INFO_BTF))..."
	sudo mkdir -p $(INSTALL_DIR)
	sudo cp $(TARGET_EXE) $(TARGET_LIB) report.py $(INSTALL_DIR)/
ifneq ($(BUILD_BPF),0)
	sudo cp $(BPF_OBJ) $(INSTALL_DIR)/
endif
	sudo ln -sf $(INSTALL_DIR)/$(TARGET_EXE) $(BIN_DIR)/$(TOOL_NAME)
	@echo "✅ Installed."

.PHONY: uninstall
uninstall:
	sudo rm -f $(BIN_DIR)/$(TOOL_NAME)
	sudo rm -rf $(INSTALL_DIR)
	@echo "✅ Uninstalled."

.PHONY: clean
clean:
	rm -f $(TARGET_EXE) $(TARGET_LIB) $(BPF_OBJ) vmlinux.h

