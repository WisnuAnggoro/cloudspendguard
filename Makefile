.PHONY: build build-all test cover cover-gate lint sample-data sample-report demo golden ci clean bench eval docker docker-run adversarial acceptance test-makefile

GO      ?= go
GOLANGCI_LINT ?= golangci-lint
BINARY  := csg
PKG     := ./...
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.6.0-beta)
LDFLAGS := -s -w -X main.version=$(VERSION)
DEMO_DB := tmp/demo.db

# Static binary, no cgo (NFR4).
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/csg

# Cross-compile the release targets into dist/.
build-all:
	@for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
		os=$${t%/*}; arch=$${t##*/}; ext=; [ "$$os" = windows ] && ext=.exe; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-$$os-$$arch$$ext ./cmd/csg || exit 1; \
	done

# Race tests cover every package. Coverage is collected separately by `cover`
# and enforced by `cover-gate` in `ci`. This avoids Go issue #75031 for
# auto-switched toolchains covering tool packages that have no test files.
test:
	$(GO) test -v -race $(PKG)

cover:
	$(GO) test -covermode=atomic -coverprofile=coverage.out $(PKG)
	$(GO) tool cover -func=coverage.out | tail -1

# NFR3: 90% or higher statement coverage on the analyzers and core algorithms.
cover-gate:
	$(GO) test -covermode=atomic -coverprofile=core.out ./internal/analyze/... ./internal/prioritize/... ./internal/llm/... ./internal/report/...
	@$(GO) tool cover -func=core.out | awk '/^total:/ { gsub("%", "", $$3); if ($$3 + 0 < 90) { printf "core coverage %s%% is below 90%%\n", $$3; exit 1 } else { printf "core coverage %s%% (gate 90%%)\n", $$3 } }'

lint:
	$(GO) vet $(PKG)
	@if ! command -v "$(GOLANGCI_LINT)" >/dev/null 2>&1; then \
		echo "golangci-lint v2 is required (CI pins v2.14.0). See docs/ci-troubleshooting.md."; \
		exit 1; \
	fi
	@version="$$("$(GOLANGCI_LINT)" version)" || exit 1; \
	case "$$version" in \
		*"version 2."*) ;; \
		*) echo "golangci-lint v2 is required for .golangci.yml; found: $$version"; \
		   echo "Install the CI-pinned v2.14.0 binary. See docs/ci-troubleshooting.md."; exit 1 ;; \
	esac
	$(GOLANGCI_LINT) run

# Makefile behavior checks using fake tools; Python 3, no AWS or Docker needed.
test-makefile:
	python3 scripts/test_makefile.py

# Regenerate the synthetic fixtures in testdata/, then refresh the copies that
# `csg run --sample` embeds in the binary (internal/sample/data).
sample-data:
	$(GO) run ./tools/gensample -out testdata
	cp testdata/sample-cur.csv testdata/sample-events.json testdata/terraform.tfstate internal/sample/data/

# The committed example report, rendered from the bundled sample account.
sample-report: build
	./bin/$(BINARY) run --sample --quiet --report docs/sample-report.html

# NFR1 measurement on synthetic CUR exports (see docs/evaluation.md).
bench:
	scripts/bench.sh

# Detection experiment against tfsec and Checkov (needs both on PATH).
eval:
	scripts/eval.sh

docker:
	docker build -t csg:$(VERSION) --build-arg VERSION=$(VERSION) .

# Run the container against the bundled sample and write ./out/report.html.
docker-run: docker
	mkdir -p out
	docker run --rm --user "$$(id -u):$$(id -g)" -v "$$PWD/out:/out" csg:$(VERSION) run --sample --report /out/report.html

# The Unit 4, 5, and 6 demonstration, end to end, against a throwaway
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
	./bin/$(BINARY) run --sample --report tmp/demo-report.html --stats --top 5
	./bin/$(BINARY) report --db $(DEMO_DB) --format sarif --out tmp/demo.sarif

# Unit 7 adversarial prompt-injection suite: 30 payloads + benign controls.
adversarial:
	$(GO) test ./internal/llm -run 'TestAdversarial' -count=1 -v

# Unit 7 acceptance test for live mode. Needs Docker (LocalStack container).
acceptance:
	sh scripts/acceptance.sh "$(GO)"

# Rewrite testdata/golden/*.diff after an intended change to the LLM layer.
golden:
	$(GO) test ./internal/llm -run TestGolden -update

# Run the same gates as GitHub Actions locally (fallback for RAID D-07).
ci: lint test cover-gate build-all demo

# Kept for backward compatibility with the Unit 2 Makefile.
run-sample: demo

clean:
	rm -rf bin/ dist/ tmp/ coverage.out core.out
