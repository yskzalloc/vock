# vock, Rust build.
#
# The whole project is Rust. This Makefile is a thin wrapper around cargo so
# that existing workflows (and `vock selftest`, which shells out to `make`)
# keep working. The `CC=...` argument passed by some callers is accepted and
# ignored, there is no C to compile.

CARGO ?= cargo
CARGO_FLAGS ?= --release
TARGET_DIR ?= target/release

.PHONY: all
all: vock.bin mode/kcov.so

.PHONY: build
build:
	$(CARGO) build $(CARGO_FLAGS)

# Place the artifacts where the runtime expects them:
#   ./vock.bin, the main binary (dirname used to locate mode/kcov.so).
#                       Named `.bin` because the workspace member directory at
#                       the repo root is itself called `vock/`, so a bare
#                       `./vock` file would collide with that directory.
#   ./mode/kcov.so, the LD_PRELOAD coverage shim
vock.bin: build
	cp -f $(TARGET_DIR)/vock ./vock.bin

mode/kcov.so: build
	@mkdir -p mode
	cp -f $(TARGET_DIR)/libkcov_preload.so mode/kcov.so

# Install as plain `vock` on PATH. The shim goes to one of the locations
# util.rs probes (/usr/local/lib/vock/kcov.so); the Debian package uses
# /usr/bin + /usr/lib/vock instead (see debian/rules).
PREFIX ?= /usr/local
.PHONY: install
install: all
	install -D -m 0755 $(TARGET_DIR)/vock $(DESTDIR)$(PREFIX)/bin/vock
	install -D -m 0644 $(TARGET_DIR)/libkcov_preload.so $(DESTDIR)$(PREFIX)/lib/vock/kcov.so

.PHONY: clean
clean:
	$(CARGO) clean
	rm -f ./vock.bin mode/kcov.so

.PHONY: test
test:
	$(CARGO) test $(CARGO_FLAGS)
