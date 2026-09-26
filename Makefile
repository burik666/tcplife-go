VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build
build: generate
	go build -ldflags "$(LDFLAGS)" -o ./bin/ .

.PHONY: run
run: build
	./bin/tcplife-go

.PHONY: install
install:
	go install -ldflags "$(LDFLAGS)" .


.PHONY: test
test:
	go test ./...

.PHONY: lint
lint:
	golangci-lint run ./...


.PHONY: clean
clean:
	rm -rf ./bin

.PHONY: generate
generate:
	go generate ./...
