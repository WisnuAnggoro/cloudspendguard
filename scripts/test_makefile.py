"""Regression checks for local CI orchestration, without running Go or Docker."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class MakefileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.log = self.directory / "go.log"
        self.go = self.executable(
            "fake-go", '#!/bin/sh\nprintf "%s\\n" "$*" >> "$CSG_GO_LOG"\n'
            'if [ -n "${CSG_HOST_LOG:-}" ]; then\n'
            'printf "%s\\n" "${DOCKER_HOST:-}" > "$CSG_HOST_LOG"\nfi\n'
        )
        self.environment = dict(os.environ, CSG_GO_LOG=str(self.log))

    def executable(self, name, content):
        path = self.directory / name
        path.write_text(content)
        path.chmod(0o755)
        return path

    def make(self, target, linter=None):
        command = [shutil.which("make"), "-s", target, f"GO={self.go}"]
        if linter is not None:
            command.append(f"GOLANGCI_LINT={linter}")
        return subprocess.run(
            command, cwd=ROOT, env=self.environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )

    def test_missing_linter_is_failure(self):
        result = self.make("lint", self.directory / "missing-linter")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("v2 is required", result.stdout)
        self.assertNotIn("skipping", result.stdout)

    def test_v1_linter_is_rejected_before_run(self):
        linter = self.executable(
            "lint-v1",
            '#!/bin/sh\nif [ "$1" = version ]; then\n'
            'echo "golangci-lint has version 1.60.0"\nelse\n'
            'echo "unexpected run"; exit 99\nfi\n',
        )
        result = self.make("lint", linter)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("v2 is required", result.stdout)
        self.assertNotIn("unexpected run", result.stdout)

    def test_lint_failure_is_not_swallowed(self):
        linter = self.executable(
            "lint-fail",
            '#!/bin/sh\nif [ "$1" = version ]; then\n'
            'echo "golangci-lint has version 2.14.0"\nelse\n'
            'echo "lint error"; exit 7\nfi\n',
        )
        result = self.make("lint", linter)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("lint error", result.stdout)
        self.assertNotIn("not installed", result.stdout)

    def test_v2_linter_success(self):
        linter = self.executable(
            "lint-ok",
            '#!/bin/sh\nif [ "$1" = version ]; then\n'
            'echo "golangci-lint has version 2.14.0"\nfi\n',
        )
        self.assertEqual(self.make("lint", linter).returncode, 0)
        self.assertIn("vet ./...", self.log.read_text())

    def test_race_test_keeps_all_packages_without_coverage(self):
        self.assertEqual(self.make("test").returncode, 0)
        self.assertEqual(self.log.read_text().strip(), "test -v -race ./...")

    def test_coverage_is_still_a_separate_ci_gate(self):
        # Dry-run the real dependency graph, not a separate copy of the recipe.
        result = subprocess.run(
            [shutil.which("make"), "-n", "ci", f"GO={self.go}"],
            cwd=ROOT, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("-coverprofile=core.out", result.stdout)
        self.assertIn("-race ./...", result.stdout)

    def test_adversarial_uses_go_override(self):
        self.assertEqual(self.make("adversarial").returncode, 0)
        self.assertIn("test ./internal/llm", self.log.read_text())

    def test_default_go_is_defined(self):
        result = subprocess.run(
            [shutil.which("make"), "-n", "adversarial"],
            cwd=ROOT, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertTrue(
            any(line.startswith("go test ") for line in result.stdout.splitlines()),
            result.stdout,
        )

    def fake_docker(self):
        self.executable(
            "docker",
            '#!/bin/sh\ncase "$1" in\n'
            'info) exit "${CSG_DOCKER_STATUS:-0}" ;;\n'
            'context) printf "%s\\n" "${CSG_CONTEXT_ENDPOINT:-unix:///fake/docker.sock}" ;;\n'
            '*) exit 99 ;;\nesac\n',
        )
        self.environment["PATH"] = str(self.directory) + os.pathsep + os.environ["PATH"]
        self.environment.pop("DOCKER_HOST", None)
        self.environment.pop("DOCKER_CONTEXT", None)
        self.environment["CSG_HOST_LOG"] = str(self.directory / "host.log")
        self.environment["LOCALSTACK_AUTH_TOKEN"] = "dummy-token-for-fake-tools-only"

    def test_acceptance_missing_token_does_not_run_go(self):
        self.fake_docker()
        self.environment.pop("LOCALSTACK_AUTH_TOKEN", None)
        result = self.make("acceptance")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("LOCALSTACK_AUTH_TOKEN is required", result.stdout)
        self.assertFalse(self.log.exists())

    def test_acceptance_stopped_daemon_does_not_run_go(self):
        self.fake_docker()
        self.environment["CSG_DOCKER_STATUS"] = "1"
        result = self.make("acceptance")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Docker is not reachable", result.stdout)
        self.assertFalse(self.log.exists())

    def test_acceptance_passes_context_socket_to_go(self):
        self.fake_docker()
        result = self.make("acceptance")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(
            (self.directory / "host.log").read_text().strip(), "unix:///fake/docker.sock"
        )
        self.assertIn("test -tags=acceptance ./cmd/csg", self.log.read_text())
        self.assertNotIn(self.environment["LOCALSTACK_AUTH_TOKEN"], result.stdout)
        self.assertNotIn(self.environment["LOCALSTACK_AUTH_TOKEN"], self.log.read_text())

    def test_acceptance_preserves_explicit_docker_host(self):
        self.fake_docker()
        self.environment["DOCKER_HOST"] = "unix:///explicit/docker.sock"
        result = self.make("acceptance")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(
            (self.directory / "host.log").read_text().strip(),
            "unix:///explicit/docker.sock",
        )

    def test_acceptance_explicit_context_overrides_host(self):
        self.fake_docker()
        self.environment["DOCKER_CONTEXT"] = "desktop-linux"
        self.environment["DOCKER_HOST"] = "unix:///stale/docker.sock"
        result = self.make("acceptance")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(
            (self.directory / "host.log").read_text().strip(), "unix:///fake/docker.sock"
        )

    def test_acceptance_preserves_go_failure(self):
        self.fake_docker()
        self.go = self.executable("go-fail", "#!/bin/sh\nexit 9\n")
        self.assertNotEqual(self.make("acceptance").returncode, 0)


if __name__ == "__main__":
    unittest.main()
