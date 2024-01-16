# share.makefile

# dir of this file.
CURRENT_DIR := $(dir $(lastword ${MAKEFILE_LIST}))

# Project root dir.
ifeq ($(origin ROOT_DIR), undefined)
    ROOT_DIR := $(abspath $(shell cd ${CURRENT_DIR}/../.. && pwd -P))
endif

# Make output dir.
ifeq ($(origin OUTPUT_DIR), undefined)
    OUTPUT_DIR := ${ROOT_DIR}/_output
    $(shell mkdir -p ${OUTPUT_DIR})
endif

# Generate tools dir.
ifeq ($(origin TOOLS_DIR), undefined)
    TOOLS_DIR := ${OUTPUT_DIR}/tools
    $(shell mkdir -p ${TOOLS_DIR})
endif

# Tmp dir.
ifeq ($(origin TMP_DIR), undefined)
    TMP_DIR := ${OUTPUT_DIR}/tmp
    $(shell mkdir -p ${TMP_DIR})
endif

# Get project version.
ifeq ($(origin VERSION), undefined)
    VERSION := $(shell git describe --tags --always --match='v*')
endif

# Check if the git tree is dirty.
GIT_TREE_STATE := "dirty"

ifeq (, $(shell git status --porcelain 2>/dev/null))
    GIT_TREE_STATE = "clean"
endif

# Current git commit.
GIT_COMMIT:=$(shell git rev-parse HEAD)

# Minimum test coverage.
ifeq ($(origin COVERAGE), undefined)
    COVERAGE := 60
endif

# The OS can be linux/windows/darwin when building binaries.
PLATFORMS ?= darwin_amd64 darwin_arm64 linux_amd64 linux_arm64

# Set a specific platform.
ifeq ($(origin PLATFORM), undefined)
    ifeq ($(origin GOOS), undefined)
        GOOS := $(shell go env GOOS)
    endif

    ifeq ($(origin GOARCH), undefined)
        GOARCH := $(shell go env GOARCH)
    endif

    PLATFORM := ${GOOS}_${GOARCH}

    # Use linux as the default OS when building images.
    IMAGE_PLAT := linux_${GOARCH}
else
    GOOS := $(word 1, $(subst _, ,${PLATFORM}))
    GOARCH := $(word 2, $(subst _, ,${PLATFORM}))

    IMAGE_PLAT := linux_${GOARCH}
endif

ifeq (${GOOS}, darwin)
	SED := gsed
endif

# Linux command settings.
FIND := find . ! -path './third_party/*' ! -path './vendor/*'

XARGS := xargs
ifeq (${GOOS}, linux)
    XARGS := xargs --no-run-if-empty
endif

# Makefile settings.
ifndef V
    MAKEFLAGS += --no-print-directory
endif

# Copy githook scripts when execute makefile.
# NOTE: This will be auto execute while run command make.
COPY_GITHOOK := $(shell cp -f githooks/* .git/hooks/ 2>/dev/null)

# Specify tools severity, include: BLOCKER_TOOLS, CRITICAL_TOOLS, TRIVIAL_TOOLS.
# Missing BLOCKER_TOOLS can cause the CI flow execution failed, i.e. `make all` failed.
# Missing CRITICAL_TOOLS can lead to some necessary operations failed. i.e. `make release` failed.
# TRIVIAL_TOOLS are optional tools, missing these tool have no affect.
BLOCKER_TOOLS ?= gsemver golines go-junit-report golangci-lint addlicense goimports
CRITICAL_TOOLS ?= swagger mockgen gotests git-chglog github-release coscmd go-mod-outdated protoc-gen-go cfssl
TRIVIAL_TOOLS ?= depth go-callvis gothanks richgo rts kube-score
