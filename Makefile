.PHONY: build build-all test cover cover-gate lint sample-data demo golden ci clean

BINARY  := csg
PKG     := ./...
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.3.0-algo)
LDFLAGS := -s -w -X main.version=$(VERSION)
DEMO_DB := tmp/demo.db

# Static binary, no cgo (NFR4).
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/csg

# Cross-compile the release targets into dist/.
build-all:
	@for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
		os=$${t%/*}; arch=$${t##*/}; ext=; [ "$$os" = windows ] && ext=.exe; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-$$os-$$arch$$ext ./cmd/csg || exit 1; \
	done

test:
	go test -v -race -cover $(PKG)

cover:
	go test -covermode=atomic -coverprofile=coverage.out $(PKG)
	go tool cover -func=coverage.out | tail -1

# NFR3: 90% or higher statement coverage on the analyzers and core algorithms.
cover-gate:
	go test -covermode=atomic -coverprofile=core.out ./internal/analyze/... ./internal/prioritize/... ./internal/llm/...
	@go tool cover -func=core.out | awk '/^total:/ { gsub("%", "", $$3); if ($$3 + 0 < 90) { printf "core coverage %s%% is below 90%%\n", $$3; exit 1 } else { printf "core coverage %s%% (gate 90%%)\n", $$3 } }'

lint:
	go vet $(PKG)
	@which golangci-lint > /dev/null && golangci-lint run || echo "golangci-lint not installed, skipping"

# Regenerate the synthetic fixtures in testdata/.
sample-data:
	go run ./tools/gensample -out testdata

# The Unit 4 and Unit 5 demonstration, end to end, against a throwaway
# database. The remediation step replays a fixture recorded from a local
# Ollama model, so it needs no model, no network, and no API key.
demo: build
	rm -f $(DEMO_DB)*
	./bin/$(BINARY) version
	./bin/$(BINARY) ingest cur --db $(DEMO_DB) ./testdata/sample-cur.parquet
	./bin/$(BINARY) ingest cloudtrail --db $(DEMO_DB) ./testdata/sample-events.json
	./bin/$(BINARY) ingest tfstate --db $(DEMO_DB) ./testdata/terraform.tfstate
	./bin/$(BINARY) query --db $(DEMO_DB) "SELECT service, ROUND(SUM(cost), 2) AS cost FROM cur GROUP BY 1 ORDER BY 2 DESC"
	./bin/$(BINARY) analyze --db $(DEMO_DB)
	./bin/$(BINARY) anomalies --db $(DEMO_DB)
	./bin/$(BINARY) remediate SEC-EC2-IMDSV2-001:i-0a1b2c3d4e5f60042 --db $(DEMO_DB) --llm-provider replay --fixture ./testdata/llm/imdsv2-injection-tag.json

# Rewrite testdata/golden/*.diff after an intended change to the LLM layer.
golden:
	go test ./internal/llm -run TestGolden -update

# Run the same gates as GitHub Actions locally (fallback for RAID D-07).
ci: lint test cover-gate build-all demo

# Kept for backward compatibility with the Unit 2 Makefile.
run-sample: demo

clean:
	rm -rf bin/ dist/ tmp/ coverage.out core.out
