export GO111MODULE=off
export GOPROXY=https://proxy.golang.org

SHELL= /bin/bash
GO ?= go
BIN_DIR := /usr/local/bin
NAME := ps
PROJECT := github.com/gepis/ps
GO_SRC=$(shell find . -name \*.go)

GO_BUILD=$(GO) build
# Go module support: set `-mod=vendor` to use the vendored sources
ifeq ($(shell go help mod >/dev/null 2>&1 && echo true), true)
	GO_BUILD=GO111MODULE=on $(GO) build -mod=vendor
endif

GOBIN ?= $(GO)/bin

all: build

.PHONY: build
build: $(GO_SRC)
	 $(GO_BUILD) -buildmode=pie -o $(NAME) $(PROJECT)/delta

.PHONY: clean
clean:
	rm -rf $(NAME)

.PHONY: vendor
vendor:
	GO111MODULE=on go mod tidy
	GO111MODULE=on go mod vendor
	GO111MODULE=on go mod verify

.PHONY: install
install:
	sudo install -D -m755 $(NAME) $(BIN_DIR)

.PHONY: uninstall
uninstall:
	sudo rm $(BIN_DIR)/$(NAME)
