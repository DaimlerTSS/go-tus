SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

.DEFAULT_GOAL := help

TARGET=go-tuts

GRAY=\033[1;90m
MAGENTA=\033[1;35m
RESET_COLOR=\033[0m

## build: build the code
build: clean fmt lint
	@echo -e "${GRAY}>> ⚙️\t${MAGENTA}Building...${RESET_COLOR}"
	@go mod tidy -v
	@go build -v -trimpath .
.PHONY: build

## test: execute tests for all packages
test: lint
	@echo -e "${GRAY}>> 🧪\t${MAGENTA}Testing...${RESET_COLOR}"
	@go test -v -count=1 -trimpath ./...
.PHONY: test

## fmt: format all Go source files
fmt:
	@echo -e "${GRAY}>> ✏️\t${MAGENTA}Formatting...${RESET_COLOR}"
	@go fmt ./...
.PHONY: fmt

## lint: examine Go source code and report suspicious constructs
lint:
	@echo -e "${GRAY}>> 🔎\t${MAGENTA}Linting...${RESET_COLOR}"
	@go vet ./...
.PHONY: lint

## clean: clean the binary
clean:
	@echo -e "${GRAY}>> 🧹\t${MAGENTA}Cleaning...${RESET_COLOR}"
	@if [ -f ${TARGET} ] ; then rm -v ${TARGET} ; fi
.PHONY: clean

## mod-download: download modules to local cache
mod-download:
	@echo -e "${GRAY}>> ⬇️\t${MAGENTA}Downloading modules...${RESET_COLOR}"
	@go mod download
.PHONY: mod-download

## help: prints this help message
help:
	@echo -e "Usage: make [target] ...\n"
	@echo -e "Targets:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'
.PHONY: help
