# FluxGate — build & release packaging.
#
# `make package` reproduces the published Linux artifact:
#   1. build the React console (embedded into the binary via rust-embed)
#   2. cross-compile a fully static musl binary
#   3. tar.gz it into dist/ with a sha256, named to match install.sh
#
# Requirements: cross (`cargo install cross`) + a running Docker daemon, node/npm.

# Version is read from the workspace Cargo.toml so the artifact name stays in sync.
VERSION   := $(shell grep -m1 '^version' Cargo.toml | sed -E 's/.*"(.*)".*/\1/')
TARGET    ?= x86_64-unknown-linux-musl
# Friendly arch label for the artifact name (e.g. x86_64-linux-musl) — matches install.sh.
ARCH      := $(shell echo $(TARGET) | sed -E 's/^([^-]+)-.*/\1/')
DIST_NAME := fluxgate-admin-$(VERSION)-$(ARCH)-linux-musl
DIST_DIR  := dist/$(DIST_NAME)
TARBALL   := dist/$(DIST_NAME).tar.gz
# Release git tag is decoupled from the crate version — read the one install.sh
# downloads from, so the publish hint always matches what users will fetch.
RELEASE_TAG := $(shell grep -m1 'releases/download' install.sh | sed -E 's@.*/download/([^/]+)/.*@\1@')

.DEFAULT_GOAL := help
.PHONY: help web build-linux package test lint clean

help:
	@echo "FluxGate make targets (version $(VERSION)):"
	@echo "  make package          Build web + cross-compile musl + tar.gz into dist/"
	@echo "                        Override arch: make package TARGET=aarch64-unknown-linux-musl"
	@echo "  make web              Build the embedded frontend into web/dist"
	@echo "  make build-linux      Cross-compile the static musl binary ($(TARGET))"
	@echo "  make test             cargo test (workspace)"
	@echo "  make lint             cargo fmt --check + clippy"
	@echo "  make clean            Remove dist/ build artifacts"

web:
	cd web && npm install --no-audit --no-fund
	cd web && npm run build

build-linux: web
	@command -v cross >/dev/null || { echo "error: 'cross' not found — run: cargo install cross (needs Docker)"; exit 1; }
	cross build --release -p fluxgate-admin --target $(TARGET)

package: build-linux
	@rm -rf $(DIST_DIR) $(TARBALL) $(TARBALL).sha256
	@mkdir -p $(DIST_DIR)
	cp target/$(TARGET)/release/fluxgate-admin $(DIST_DIR)/fluxgate-admin
	chmod +x $(DIST_DIR)/fluxgate-admin
	tar -C dist -czf $(TARBALL) $(DIST_NAME)
	@shasum -a 256 $(TARBALL) | tee $(TARBALL).sha256
	@echo ""
	@echo "✓ packaged $(TARBALL) ($$(du -h $(TARBALL) | cut -f1))"
	@echo "  publish: gh release create $(RELEASE_TAG) $(TARBALL) --title $(RELEASE_TAG)"
	@echo "  (tag $(RELEASE_TAG) is the one install.sh downloads from)"

test:
	cargo test --workspace

lint:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets

clean:
	rm -rf dist/fluxgate-admin-*
