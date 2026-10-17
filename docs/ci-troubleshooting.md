# Local CI troubleshooting

Run commands from `cloudspendguard/`, the directory containing `go.mod` and `Makefile`. The local CI entry point is `make ci`; the Docker-backed acceptance test is a separate command, `make acceptance`.

## Linter configuration error

The repository's `.golangci.yml` uses the v2 schema, including `version: "2"`. An older linter may fail with `'Version' expected a map, got 'string'`; the version field was introduced with the v2 configuration format ([golangci-lint migration guide](https://golangci-lint.run/docs/product/migration-guide/)).

Check the executable actually selected by your shell:

```bash
command -v golangci-lint
golangci-lint version
```

Use v2, preferably the same binary version pinned by `.github/workflows/ci.yml`: v2.14.0. The following installs that pinned version using the project's official binary installer, rather than compiling a possibly incompatible linter locally ([official installation instructions](https://golangci-lint.run/docs/welcome/install/local/)):

```bash
curl -sSfL https://golangci-lint.run/install.sh \
  -o /tmp/cloudspendguard-golangci-install.sh
# Optional: inspect the downloaded installer before executing it.
sh /tmp/cloudspendguard-golangci-install.sh \
  -b "$(go env GOPATH)/bin" v2.14.0
export PATH="$(go env GOPATH)/bin:$PATH"
hash -r
golangci-lint version
make lint
```

Expected: version `2.14.0`, followed by successful `go vet` and `golangci-lint run`. The corrected Makefile fails when the linter is missing, is v1, or reports findings; it no longer mislabels every failure as “not installed” and silently continues.

## `go: no such tool "covdata"`

This error on packages without test files matches Go issue #75031, a toolchain-switching problem that can occur when the `go` executable on `PATH` differs from the selected toolchain. It does not by itself prove that the application tests failed or that Go is incompletely installed ([Go issue #75031](https://github.com/golang/go/issues/75031)).

Inspect the current toolchain before reinstalling anything:

```bash
command -v go
go version
go env GOVERSION GOTOOLCHAIN GOROOT GOTOOLDIR
```

The corrected `make test` runs `go test -v -race ./...` without coverage instrumentation. `make ci` still requires `make cover-gate`, which collects coverage for the analyzers, prioritizer, LLM, and reporter packages and enforces the 90% threshold. `make cover` still collects whole-module coverage, including tool packages with no test files.

If whole-module coverage encounters the toolchain-switching error, explicitly select the currently active toolchain for that command. This applies the workaround reported in the Go issue without changing your global Go configuration ([Go issue #75031](https://github.com/golang/go/issues/75031)):

```bash
GOTOOLCHAIN="$(go env GOVERSION)+auto" make cover
```

Alternatively, select the toolchain used to verify this fix:

```bash
GOTOOLCHAIN=go1.26.5+auto make ci
GOTOOLCHAIN=go1.26.5+auto make cover
```

If the error persists, share the four diagnostic outputs above. Do not copy a `covdata` binary between unrelated Go versions or delete your module cache as a first step.

## Verify the Makefile behavior

These regression checks use fake tool executables, so they need Python 3 but no Go installation, AWS account, Docker daemon, or live model. They check missing and v1 linters, propagated lint failures, successful v2 linting, race-test flags, the retained CI coverage dependency, and the default/overridden `GO` commands.

```bash
make test-makefile
make ci
make adversarial
```

Expected: fourteen Makefile regression checks pass, `make ci` reaches the demo after linting, race testing, coverage gating, and cross-compilation, and `make adversarial` actually invokes Go. LocalStack execution still requires a Docker host and is not implied by these checks.

## Acceptance: license activation failed, exit code 55

The pinned `localstack/localstack:2026.10.0` is a unified LocalStack image and requires `LOCALSTACK_AUTH_TOKEN`. LocalStack introduced the mandatory token with its March 2026 unified image distribution; a free non-commercial plan and student options exist, so a token requirement does not automatically imply a paid subscription ([LocalStack announcement](https://blog.localstack.cloud/localstack-single-image-next-steps/)).

Create an account and generate a developer token through the LocalStack web application. The token must have the appropriate account/license entitlement; keep it out of version control and logs ([LocalStack token documentation](https://docs.localstack.cloud/aws/getting-started/auth-token/)).

Enter it privately in your local Bash or Zsh terminal, not in chat:

```bash
printf 'LocalStack developer token: '
read -r -s LOCALSTACK_AUTH_TOKEN
printf '\n'
export LOCALSTACK_AUTH_TOKEN
make acceptance
```

The input is hidden and the token is not part of the shell command saved in history. This sets it for the current shell session; remove it afterward with `unset LOCALSTACK_AUTH_TOKEN`.

The acceptance test explicitly forwards the environment variable into the container via `testcontainers.WithEnv`; merely setting a token for the separate LocalStack CLI is not sufficient for this Testcontainers-managed container. The script and Go test both fail clearly when the token is missing, and neither includes the token in an error message.

For GitHub Actions, create a dedicated CI auth token and save it in the repository's Actions secrets as `LOCALSTACK_AUTH_TOKEN`. The acceptance job now passes that secret into `make acceptance`; adding the workflow alone does not create the secret ([LocalStack CI token guidance](https://docs.localstack.cloud/aws/getting-started/auth-token/)).

The workflow intentionally fails rather than skips when the secret is missing. Fork pull requests do not ordinarily receive repository secrets; acceptance for those changes must be run in a trusted, reviewed workflow with the secret available, without exposing it to untrusted code ([GitHub secrets documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets)).

The test still uses dummy AWS credentials `test`/`test` for emulated S3 calls. Those are distinct from the real LocalStack activation token; no real AWS access key is needed.

## Acceptance: `rootless Docker not found`

This is a Docker connection failure before LocalStack starts, not a failed S3 assertion. Testcontainers tries several Docker host discovery strategies, with rootless sockets among the fallbacks; the message does not mean rootless Docker is required ([Testcontainers configuration](https://golang.testcontainers.org/features/configuration/)).

First check whether the Docker daemon is reachable. `docker info` is Docker's recommended platform-independent check ([Docker daemon troubleshooting](https://docs.docker.com/engine/daemon/troubleshoot/)):

```bash
docker info
docker context ls
```

If you use Docker Desktop on macOS, open Docker Desktop from Applications and wait for it to finish starting. Alternatively, recent Docker Desktop versions provide `docker desktop start` ([Docker Desktop start](https://docs.docker.com/reference/cli/docker/desktop/start/)).

Once `docker info` succeeds, retry:

```bash
make acceptance
```

The updated target runs `scripts/acceptance.sh`: it checks the CLI and daemon before launching Go, then passes the active context's local socket as `DOCKER_HOST` for Testcontainers. It preserves an existing `DOCKER_HOST` unless an explicit `DOCKER_CONTEXT` selects a different local socket. Docker exposes the context endpoint through `docker context inspect` ([Docker context inspect](https://docs.docker.com/reference/cli/docker/context/inspect.md)).

If Docker CLI works but you are still using the previous Makefile, the local-socket equivalent is:

```bash
DOCKER_HOST="$(docker context inspect --format '{{.Endpoints.docker.Host}}')" \
  make acceptance
```

Use that shortcut for local Docker Desktop/Engine sockets, not as a blanket solution for remote SSH/TLS contexts. Colima and Rancher Desktop may also need runtime-specific socket and networking settings; follow their respective Testcontainers guides ([Colima](https://golang.testcontainers.org/system_requirements/using_colima/), [Rancher Desktop](https://golang.testcontainers.org/system_requirements/rancher/)).

Do not disable Ryuk, use `sudo make acceptance`, or convert the test to a skip just to hide this error. If it persists, share `docker info`, `docker context ls`, and the following diagnostics, with private hostnames redacted:

```bash
docker context inspect --format '{{.Endpoints.docker.Host}}'
printf 'DOCKER_HOST=%s\nDOCKER_CONTEXT=%s\n' \
  "${DOCKER_HOST:-<unset>}" "${DOCKER_CONTEXT:-<unset>}"
```

The preflight regression checks use fake Docker/Go commands. They do not establish that the LocalStack acceptance test has passed on a real Docker host.
