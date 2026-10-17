# LocalStack Acceptance Evidence: October 17, 2026

The developer supplied the terminal output below from a successful local run on October 17, 2026. This records user-run evidence, not a LocalStack execution in the assistant sandbox or a GitHub Actions result.

## Environment and command

- Runtime: Docker Desktop, Docker server 25.0.3, API 1.44.
- Testcontainers for Go: v0.44.0.
- LocalStack image: `localstack/localstack:2026.10.0`.
- Command: `make acceptance`.

Docker preflight passed, the LocalStack health check completed, and the test container stopped and terminated successfully after the assertions. The daemon emitted a non-default seccomp-profile warning; it did not fail this run, and the log does not establish why that profile was configured.

## Relevant terminal output

```text
acceptance: Docker preflight passed; starting the LocalStack test.
=== RUN   TestAcceptance_LiveModeLocalStack
...
--- PASS: TestAcceptance_LiveModeLocalStack (10.87s)
=== RUN   TestAcceptanceLifecycleRequestSchema
--- PASS: TestAcceptanceLifecycleRequestSchema (0.00s)
PASS
ok  github.com/wisnuanggoro/cloudspendguard/cmd/csg 11.363s
```

The developer also ran `TestAcceptanceLifecycleRequestSchema` independently before the full acceptance command; that isolated invocation passed. The excerpt omits container identifiers, the local socket path, and routine lifecycle logs.

## Scope and limitations

The successful `TestAcceptance_LiveModeLocalStack` run exercises the real CLI against the seeded S3 emulator scenario. The separate schema test checks the shared lifecycle fixture's actual AWS SDK XML request without Docker.

This evidence does not establish a real-AWS integration result, a GitHub Actions pass, a deployed CloudSpendGuard application image, or completion of the planned human evaluation. Those activities retain their separate verification status.
