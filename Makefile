.PHONY: build test lint run-sample clean

BINARY := csg
PKG := ./...

build:
	go build -o bin/$(BINARY) ./cmd/csg

test:
	go test -v -race -cover $(PKG)

lint:
	go vet $(PKG)
	@which golangci-lint > /dev/null && golangci-lint run || echo "golangci-lint not installed, skipping"

run-sample: build
	./bin/$(BINARY) version

clean:
	rm -rf bin/
