# Global variables ============================================================

SHELL := /bin/bash
SED := sed

# Go binary.
GO := go

# Project source code test coverage threshold.
COVERAGE := 0

# Usage components ============================================================

define USAGE_OPTIONS

Options:

   PLATFORMS   The multiple platforms to build.
               Default is 'darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 windows_amd64'.
               This option is available when using: make build.multiarch.
               Example: make build.multiarch PLATFORMS="linux_amd64"
endef
export USAGE_OPTIONS

# Includes ====================================================================

include scripts/makefiles/share.makefile
include scripts/makefiles/go.makefile
include scripts/makefiles/tools.makefile

# Targets =====================================================================

# Print help information by default.
.DEFAULT_GOAL := build

##  dev: Make lint, cover, build and install for development stage.
.PHONY: dev
dev: tidy lint cover build install

##  build: Compile packages and dependencies to generate binary file for current platform.
.PHONY: build
build:
	@${MAKE} go.build

##  build.multiarch: Build for multiple platforms. See option PLATFORMS.
.PHONY: build.multiarch
build.multiarch:
	@${MAKE} go.build.multiarch

##  install: Install the binary gossh to your system.
.PHONY: install
install:
	@${MAKE} go.install

##  tidy: Run go mod tidy.
.PHONY: tidy
tidy:
	@${MAKE} go.tidy

##  lint: Check syntax and style of Go source code.
.PHONY: lint
lint:
	@${MAKE} go.lint

##  test: Run unit test.
.PHONY: test
test:
	@${MAKE} go.test

##  cover: Run unit test and get test coverage.
.PHONY: cover
cover:
	@${MAKE} go.test.cover

##  clean: Remove all files that are created by building.
.PHONY: clean
clean:
	@echo "==========> Cleaning all build output"
	@-rm -vrf ${OUTPUT_DIR}

##  help: Show this help.
.PHONY: help
help: Makefile
	@echo -e "\nUsage: make [TARGETS] [OPTIONS] \n\nTargets:\n"
	@sed -n 's/^##//p' $< | column -t -s ':' | sed -e 's/^/ /'
	@echo "$$USAGE_OPTIONS"

# References:
# https://seisman.github.io/how-to-write-makefile/index.html
