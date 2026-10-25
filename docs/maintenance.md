# Maintenance plan

Operational maintenance plan for CloudSpendGuard (current release: v1.0.0). This document is
the operational counterpart of the maintenance approach: what will be maintained, how, and how
the version-control process supports it.

## Maintenance types

The plan follows the four ISO/IEC 14764 maintenance categories. For each
type, the table lists what it means for CloudSpendGuard and the concrete
mechanism in the repository.

| Type | What it covers in CloudSpendGuard | Mechanism |
|---|---|---|
| Corrective | Defects found in the rule library, the ingest parsers, the prioritizer, or the LLM guardrails | Every fix lands behind a failing regression test; `make ci` runs lint, the full test suite with the race detector, the coverage gate, and the demo before merge |
| Adaptive | AWS API or export-format changes (CUR schema additions, CloudTrail event shapes, S3 API behavior) and toolchain drift (Go releases, GitHub Actions) | The live collector speaks versioned AWS APIs through aws-sdk-go-v2; Dependabot and Renovate open weekly update PRs; the acceptance test pins LocalStack so emulator drift is a reviewed change, not a silent one |
| Perfective | New detectors, new services in live mode, report improvements requested by users | Rule registry pattern: a new rule is one struct plus a positive and a negative fixture; live mode extends service by service |
| Preventive | Refactoring, security hardening, dependency hygiene before it becomes corrective work | `govulncheck` in CI, the 90% coverage gate on analyzers, the adversarial suite as a standing contract, and the release-candidate discipline itself (`-rc1` before `v1.0.0`) |

## Update and monitoring schedule

| Cadence | Activity | Owner | Automation |
|---|---|---|---|
| Per push | Lint, tests, race detector, coverage gate, smoke demo, SARIF validation | CI | GitHub Actions |
| Per release candidate | Acceptance test against LocalStack, cross-compilation matrix, Docker image build | CI | GitHub Actions `acceptance` job |
| Weekly | Dependency updates (Go modules, Actions, Docker base image) | Maintainer review | Dependabot, Renovate |
| Monthly | Vulnerability triage beyond automated alerts, review of skipped rules | Maintainer | `govulncheck` in CI, manual review |
| Per AWS announcement | Check CUR schema and CloudTrail event shape changes against the parsers | Maintainer | Release notes of AWS services, manual |

## Version and configuration management

- Versions follow semantic versioning with milestone tags defined in
  `docs/version-control.md` (`v0.9.0-rc1` is the first release candidate;
  the capstone targets `v1.0.0`).
- Every release is tagged on the merge commit into `main`, documented in
  `CHANGELOG.md` (Keep a Changelog format), and summarized in
  `docs/releases/<tag>.md`.
- Configuration that affects behavior (weights, profiles, LLM backends) is
  explicit on the command line or in environment variables; no hidden config
  files, so a run is reproducible from the repository state alone.
- Test fixtures are byte-stable: `.gitattributes` keeps them LF and binary,
  so golden diffs cannot drift across operating systems.

## Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| An AWS API change breaks the live collector | Medium | Medium | Acceptance test runs in CI on every push; permission failures fail loudly rather than returning partial inventories |
| A dependency ships a breaking or malicious update | Medium | High | Dependabot and Renovate group minor updates for review; `govulncheck` scans on every push; majors get isolated PRs |
| The LLM guardrails miss a new injection pattern | Medium | High | The adversarial suite is a standing contract; new payloads are added to the fixture file with an explicit expected outcome, and the verifier stays the final gate regardless of the sanitizer |
| LocalStack behavior diverges from real AWS | Medium | Low | The acceptance test checks the pipeline shape, not AWS semantics; the pin is deliberate and upgrades are reviewed |
| Fixture drift breaks golden tests | Low | Low | `.gitattributes` enforces LF and binary handling; `make golden` rewrites fixtures after intended changes only |

## References

Letaw, L. (2024). *Handbook of software engineering methods*. Oregon State
University. https://open.oregonstate.education/setextbook/
