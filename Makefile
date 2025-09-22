# Makefile for the vock kernel coverage tool

CC ?= gcc
CFLAGS += -Wall -O2
LDFLAGS +=

# --- Configuration ---
TOOL_NAME = vock

# The main driver executable, compiled from vock.c
TARGET_EXE = vock
EXE_SOURCE = vock.c

# The preload library, compiled from vockpre.c
TARGET_LIB = kcovpre.so
LIB_SOURCE = kcovpre.c

# Installation directories
INSTALL_DIR = /usr/local/lib/$(TOOL_NAME)
BIN_DIR = /usr/local/bin

# Default target: build both the executable and the shared library
.PHONY: all
all: $(TARGET_EXE) $(TARGET_LIB)

# Rule to compile the main vock executable
$(TARGET_EXE): $(EXE_SOURCE)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Rule to compile the .so file from vockpre.c
$(TARGET_LIB): $(LIB_SOURCE)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

# Target to install the complete tool
.PHONY: install
install: all
	@echo "Installing $(TOOL_NAME) to $(INSTALL_DIR)..."
	sudo mkdir -p $(INSTALL_DIR)
	sudo cp $(TARGET_EXE) $(INSTALL_DIR)/
	sudo cp $(TARGET_LIB) $(INSTALL_DIR)/
	sudo cp report_coverage.py $(INSTALL_DIR)/
	sudo ln -sf $(INSTALL_DIR)/$(TARGET_EXE) $(BIN_DIR)/$(TOOL_NAME)
	@echo ""
	@echo "✅ Installation complete."
	@echo "You can now run '$(TOOL_NAME)' from any terminal."

# Target to uninstall the tool
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(TOOL_NAME)..."
	sudo rm -f $(BIN_DIR)/$(TOOL_NAME)
	sudo rm -rf $(INSTALL_DIR)
	@echo "✅ Uninstallation complete."

# Target to clean up all build artifacts
.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm -f $(TARGET_EXE) $(TARGET_LIB)

