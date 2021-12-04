# go.makefile

# Supports Go versions.
GO_SUPPORTED_VERSIONS ?= 1.13|1.14|1.15|1.16|1.17

# The project package name.
ROOT_PACKAGE = github.com/windvalley/gossh
# The project version package name.
#VERSION_PACKAGE = ${ROOT_PACKAGE}/pkg/version
VERSION_PACKAGE = github.com/go-project-pkg/version

# Go build args.
GO_LDFLAGS += -X ${VERSION_PACKAGE}.GitVersion=${VERSION} \
	-X ${VERSION_PACKAGE}.GitCommit=${GIT_COMMIT} \
	-X ${VERSION_PACKAGE}.GitTreeState=${GIT_TREE_STATE} \
	-X ${VERSION_PACKAGE}.BuildDate=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

ifneq (${DLV},)
	GO_BUILD_FLAGS += -gcflags "all=-N -l"
	LDFLAGS = ""
endif

GO_BUILD_FLAGS += -tags=jsoniter -ldflags "${GO_LDFLAGS}"

ifeq (${ROOT_PACKAGE},)
	$(error the variable ROOT_PACKAGE must be set)
endif

GOPATH := $(shell go env GOPATH)
ifeq ($(origin GOBIN), undefined)
	GOBIN := ${GOPATH}/bin
endif

COMMANDS ?= $(filter-out %.md, $(wildcard ${ROOT_DIR}/cmd/*))
BINS ?= $(foreach cmd,${COMMANDS},$(notdir ${cmd}))

ifeq (${COMMANDS},)
	$(error Could not determine COMMANDS, set ROOT_DIR or run in source dir)
endif

ifeq (${BINS},)
	$(error Could not determine BINS, set ROOT_DIR or run in source dir)
endif

EXCLUDE_TESTS = ${ROOT_PACKAGE}/test ${ROOT_PACKAGE}/pkg/log ${ROOT_PACKAGE}/third_party

.PHONY: go.build.verify
go.build.verify:
ifneq ($(shell ${GO} version | grep -q -E '\bgo(${GO_SUPPORTED_VERSIONS})\b' && echo 0 || echo 1), 0)
	$(error unsupported Go version. Supported versions: '${GO_SUPPORTED_VERSIONS}')
endif

.PHONY: go.build.%
go.build.%:
	$(eval COMMAND := $(word 2,$(subst ., ,$*)))
	$(eval PLATFORM := $(word 1,$(subst ., ,$*)))
	$(eval OS := $(word 1,$(subst _, ,${PLATFORM})))
	$(eval ARCH := $(word 2,$(subst _, ,${PLATFORM})))
	$(eval GO_BIN_EXT = $(if $(findstring windows,${OS}),.exe,))
	@echo "==========> Building binary '${COMMAND}${GO_BIN_EXT}' ${VERSION} for ${OS} ${ARCH}"
	@mkdir -p ${OUTPUT_DIR}/platforms/${OS}/${ARCH}
	@CGO_ENABLED=0 GOOS=${OS} GOARCH=${ARCH} ${GO} build ${GO_BUILD_FLAGS} -o ${OUTPUT_DIR}/platforms/${OS}/${ARCH}/${COMMAND}${GO_BIN_EXT} ${ROOT_PACKAGE}/cmd/${COMMAND}
	@echo "${OUTPUT_DIR}/platforms/${OS}/${ARCH}/${COMMAND}${GO_BIN_EXT}"

.PHONY: go.build
go.build: go.build.verify go.tidy $(addprefix go.build., $(addprefix ${PLATFORM}., ${BINS}))

.PHONY: go.build.multiarch
go.build.multiarch: go.build.verify go.tidy $(foreach p,${PLATFORMS},$(addprefix go.build., $(addprefix ${p}., ${BINS})))

.PHONY: go.lint
go.lint: tools.verify.golangci-lint
	@echo "==========> Run golangci-lint to lint source codes"
	@golangci-lint run -c ${ROOT_DIR}/.golangci.yaml ${ROOT_DIR}/...

.PHONY: go.test
go.test: tools.verify.go-junit-report
	@echo "==========> Run unit test"
	@${GO} test -race -cover -coverprofile=${OUTPUT_DIR}/coverage.out \
		-timeout=10m -short -v `go list ./...|\
		egrep -v "$(subst ' ','|',$(sort ${EXCLUDE_TESTS}))"` | \
		tee >(go-junit-report --set-exit-code >${OUTPUT_DIR}/report.xml)
	@${GO} tool cover -html=${OUTPUT_DIR}/coverage.out -o ${OUTPUT_DIR}/coverage.html
	@${SED} -i '/mock_.*.go/d' ${OUTPUT_DIR}/coverage.out

.PHONY: go.test.cover
go.test.cover: go.test
	@echo -e "\n==========> Run test coverage"
	@${GO} tool cover -func=${OUTPUT_DIR}/coverage.out | \
		awk -v target=${COVERAGE} -f ${ROOT_DIR}/scripts/coverage.awk

.PHONY: go.updates
go.updates: tools.verify.go-mod-outdated
	@${GO} list -u -m -json all | go-mod-outdated -update -direct

.PHONY: go.tidy
go.tidy:
	@echo "==========> go mod tidy"
	@${GO} mod tidy
