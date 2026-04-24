.PHONY: build test vet clean install lint

BINARY=kuberneet
CMD=./cmd/kuberneet
VERSION?=0.1.0
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
DATE?=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-ldflags "-X github.com/raphael/kuberneet/cmd.Version=$(VERSION) -X github.com/raphael/kuberneet/cmd.Commit=$(COMMIT) -X github.com/raphael/kuberneet/cmd.Date=$(DATE)"

build:
	go build $(LDFLAGS) -o bin/$(BINARY) $(CMD)

test:
	go test ./... -v

vet:
	go vet ./...

lint: vet
	@echo "Lint passed"

clean:
	rm -rf bin/

install: build
	cp bin/$(BINARY) /usr/local/bin/

run: build
	./bin/$(BINARY) scan --help

# Cross-compile for release
release: build
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-amd64 $(CMD)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-arm64 $(CMD)
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-darwin-amd64 $(CMD)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY)-darwin-arm64 $(CMD)

.DEFAULT_GOAL := build