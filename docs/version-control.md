# CloudSpendGuard: Version Control and Collaboration

Created in Unit 3 (MSIT 5910). This is the working contract for how history is kept in this repository.

## Repository organization

The boundary between code, documentation, and design artifacts is meant to be obvious to a reviewer
seeing the project for the first time.

```
cmd/csg/            command entry point (M11)
internal/           module implementations, one package per module
pkg/models/         shared types crossing module boundaries
docs/               architecture.md, requirements.md, version-control.md,
                    related-work.md, raid-log.md, gantt.mmd, iam-policy.json
docs/design/        diagram source scripts, rendered from code not pasted in
**/testdata/        fixtures beside the packages they exercise
```

## Branching

A simplified Git Flow model with two long-lived branches and short-lived feature branches.

- `main` always holds a releasable state; every commit on it is reachable from a semantic-version tag.
- `develop` is the integration target where completed work accumulates between releases.
- `feature/<short-description>` branches are cut from `develop`, for example
  `feature/cur-parquet-ingest`, and merge back through a pull request that must pass CI.

When a unit milestone is reached, `develop` merges into `main` and is tagged.

| Tag | Milestone |
|---|---|
| `v0.1.0-ingest` | Ingestion layer complete (M1, M2, M3) |
| `v0.2.0-analyze-alpha` | Cost and security analyzers producing findings (M5, M6) |
| `v0.3.0-algo` | Core logic: rule library (M5, M6), anomaly detector, joint prioritizer (M7), and the remediation and verification loop (M8, M9), pulled forward from `v0.6.0-beta` |
| `v0.6.0-beta` | Integration (`csg run`), reporting (M10), evaluation against tfsec and Checkov, Docker and scheduled-scan deployment; live collector (M3b) moved to a later release |
| `v0.9.0-rc1` | Reporting complete, evaluation run (M10) |
| `v1.0.0` | Release |

### How a milestone is released (Unit 5 example)

```bash
# 1. Each workstream on its own short-lived branch, cut from develop
git switch develop && git pull
git switch -c feature/unit5-core-algorithms
# ... commits ...
git push -u origin feature/unit5-core-algorithms
gh pr create --base develop --title "feat: v0.3.0-algo core algorithms"

# 2. After CI is green and the PR is merged, promote develop to main
git switch main && git pull
git merge --no-ff develop -m "release: v0.3.0-algo"
git push origin main

# 3. Annotated tag on the merge commit, then a GitHub Release from it
git tag -a v0.3.0-algo -m "v0.3.0-algo: core algorithms, rule library, verified LLM remediation"
git push origin v0.3.0-algo
gh release create v0.3.0-algo --title "v0.3.0-algo: Core algorithms and verified LLM remediation" \
  --notes-file docs/releases/v0.3.0-algo.md --prerelease
```

Annotated tags (`-a`) store the author, date, and message, so `git show v0.3.0-algo` explains the
milestone without opening GitHub. Pre-1.0 releases are marked `--prerelease`.

## Commit messages

Conventional Commits. A message reads `feat(ingest/cur): stream Parquet row groups to bound memory`
rather than `update code`. The value of `git log` depends entirely on the discipline of the messages
recorded in it, because the log is the only durable record of *why* a change was made rather than
merely what changed ([Davies, 2024](https://open.umn.edu/opentextbooks/textbooks/blueprints-creating-describing-and-implementing-designs-for-larger-scale-software-projects-davis), Ch. 14.3).
A structured prefix also makes the history machine-readable, so release notes can be generated from
the log itself.

Allowed types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`.

## Consistency and traceability

Documentation lives in the same repository as the code, so a module change and the matching change to
`architecture.md` can be made in one commit. This prevents the drift that occurs when a design
document lives in a separate word-processor file.

Traceability runs along a single chain:

```
RAID-log entry  ->  issue  ->  feature/* branch  ->  pull request  ->  tagged release
```

Any reviewer can therefore reconstruct the reasoning behind any part of the final artifact.
`git status` and `git diff` show exactly what has changed before it is made permanent, and the
repository can be restored to any earlier point ([Davies, 2024](https://open.umn.edu/opentextbooks/textbooks/blueprints-creating-describing-and-implementing-designs-for-larger-scale-software-projects-davis), Ch. 14.2, 14.4, 14.5),
which gives the project a documented ability to recover from a bad design decision.

## Review, on a solo project

Integrated team development is essential to requirement quality
([Summers, 2020](https://www.taylorfrancis.com/books/mono/10.1201/9781003025665/effective-methods-software-engineering-boyd-summers), Ch. 4.2),
but this capstone has no team to hold design reviews. Two substitutes stand in:

1. Pull requests into `develop` are a structured self-review checkpoint. The author reads the complete
   diff against the stated requirement before merging.
2. The CI pipeline is the impartial reviewer, enforcing formatting, static analysis, and coverage
   without negotiation.

The same team-based mechanisms let a future contributor join after release without disturbing project
history ([Davies, 2024](https://open.umn.edu/opentextbooks/textbooks/blueprints-creating-describing-and-implementing-designs-for-larger-scale-software-projects-davis), Ch. 14.6),
which matters because CloudSpendGuard is intended to remain open source once the capstone concludes.

## References

Davies, S. (2024). *Blueprints: Creating, describing, and implementing designs for larger-scale software projects* (Version 2.5). University of Mary Washington. https://open.umn.edu/opentextbooks/textbooks/blueprints-creating-describing-and-implementing-designs-for-larger-scale-software-projects-davis

Summers, B. L. (2020). *Effective methods for software engineering*. Auerbach Publications. https://www.taylorfrancis.com/books/mono/10.1201/9781003025665/effective-methods-software-engineering-boyd-summers
