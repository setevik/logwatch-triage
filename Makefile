BINARY := logtriage
MODULE := github.com/setevik/logtriage
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test lint clean install

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/logtriage

test:
	go test -race -count=1 ./...

lint:
	go vet ./...

clean:
	rm -f $(BINARY)

install: build
	install -D -m 755 $(BINARY) $(HOME)/.local/bin/$(BINARY)
