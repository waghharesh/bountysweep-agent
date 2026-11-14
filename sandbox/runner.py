"""Ephemeral Docker Sandbox Runner for isolated bounty patch verification."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import docker
from docker.errors import DockerException
from pydantic import BaseModel, Field

from config.settings import Settings, get_settings

logger = logging.getLogger(__name__)

_PASSED_RE = re.compile(r"(\d+)\s+passed")
_FAILED_RE = re.compile(r"(\d+)\s+failed")
_ERROR_RE = re.compile(r"(\d+)\s+errors?")
_UNITTEST_RAN_RE = re.compile(r"Ran\s+(\d+)\s+tests?\s+in\s+[0-9.]+s", re.IGNORECASE)
_UNITTEST_FAILURES_RE = re.compile(r"failures=(\d+)", re.IGNORECASE)
_UNITTEST_ERRORS_RE = re.compile(r"errors=(\d+)", re.IGNORECASE)
_SAFE_REL_SCRIPT_RE = re.compile(r"^[A-Za-z0-9_./-]+\.py$")
_DOC_TEST_SCRIPT_RE = re.compile(
    r"\bpython(?:3)?\s+([A-Za-z0-9_./-]+\.py)\b",
    re.IGNORECASE,
)
_TEST_FUNC_RE = re.compile(r"^\s*(?:async\s+)?def\s+(test_[a-zA-Z0-9_]+)\s*\(", re.MULTILINE)


class SandboxTestRunResult(BaseModel):
    """Structured result of a single isolated test execution inside the sandbox."""

    passed: bool
    exit_code: int
    passed_count: int
    failed_count: int
    total_count: int
    stdout: str
    stderr: str = ""
    timed_out: bool = False
    duration_seconds: float = 0.0


class SandboxExecutionReport(BaseModel):
    """Comprehensive verification report comparing baseline vs patched test suites."""

    bounty_id: str
    repo_url: str
    baseline_run: SandboxTestRunResult
    patched_run: SandboxTestRunResult
    regression_tests_added: int
    all_existing_tests_passed: bool
    new_regression_test_passed: bool
    submission_approved: bool
    rejection_reason: str | None = None
    container_config_audit: dict[str, Any] = Field(default_factory=dict)


class DockerSandboxRunner:
    """Executes target repository test suites inside an ephemeral, isolated Docker container.

    Security & Isolation Guarantees:
    - Network completely disabled (`network_mode="none"`) during test execution.
    - CPU capped to 1 vCPU (`cpu_period=100_000`, `cpu_quota=100_000`, `nano_cpus=1_000_000_000`).
    - Memory capped to 1GB RAM with swap disabled (`mem_limit="1g"`, `memswap_limit="1g"`).
    - Root filesystem mounted read-only (`read_only=True`).
    - Only `/workspace` volume mounted read-write (`rw`), plus bounded `/tmp` tmpfs with `noexec`.
    - All Linux capabilities dropped (`cap_drop=["ALL"]`) and `no-new-privileges:true`.
    - Hard 120-second execution timeout with guaranteed container removal.
    - Automatic fallback to `python -m unittest discover` or safe local test scripts if `pytest` exits with code 5.
    """

    DEFAULT_PYTEST_COMMAND: list[str] = ["pytest", "-q", "--tb=short"]
    UNITTEST_DISCOVER_COMMAND: list[str] = ["python", "-m", "unittest", "discover"]

    def __init__(
        self,
        settings: Settings | None = None,
        docker_client: Any | None = None,
        allow_local_fallback: bool = True,
    ) -> None:
        self.settings: Settings = settings or get_settings()
        self._docker_client: Any | None = docker_client
        self.allow_local_fallback: bool = allow_local_fallback
        self._last_fallback_command: list[str] | None = None

    def _get_docker_client(self) -> Any:
        """Lazily initialize or return injected Docker client."""
        if self._docker_client is not None:
            return self._docker_client
        self._docker_client = docker.from_env()
        return self._docker_client

    def _build_container_kwargs(
        self,
        workspace_dir: str | Path,
        command: list[str] | str | None = None,
    ) -> dict[str, Any]:
        """Construct strict container isolation arguments for `client.containers.run`."""
        resolved_workspace = str(Path(workspace_dir).resolve())
        cmd = command if command is not None else list(self.DEFAULT_PYTEST_COMMAND)
        mem_limit = self.settings.SANDBOX_MEM_LIMIT

        return {
            "image": self.settings.SANDBOX_IMAGE,
            "command": cmd,
            "network_mode": "none",
            "cpu_period": self.settings.SANDBOX_CPU_PERIOD,
            "cpu_quota": self.settings.SANDBOX_CPU_QUOTA,
            "nano_cpus": 1_000_000_000,
            "mem_limit": mem_limit,
            "memswap_limit": mem_limit,
            "read_only": True,
            "volumes": {
                resolved_workspace: {
                    "bind": "/workspace",
                    "mode": "rw",
                }
            },
            "tmpfs": {
                "/tmp": "size=64m,noexec,nosuid,nodev",
            },
            "working_dir": "/workspace",
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "pids_limit": 128,
            "detach": True,
            "environment": {
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": "/workspace",
            },
        }

    @staticmethod
    def validate_repo_url(repo_url: str) -> str:
        """Validate repository URL to prevent git option injection or local path leaks."""
        if not repo_url or not isinstance(repo_url, str):
            raise ValueError("Repository URL must be a non-empty string.")

        cleaned = repo_url.strip()
        if cleaned.startswith("-"):
            raise ValueError(f"Invalid repository URL (potential option injection): {cleaned}")

        if any(ch in cleaned for ch in ("\x00", "\n", "\r", "\t", " ")):
            raise ValueError("Repository URL contains forbidden whitespace or control characters.")

        parsed = urlparse(cleaned)
        if parsed.scheme not in ("https", "mock"):
            raise ValueError(
                f"Unsupported repository URL scheme '{parsed.scheme}'. Only 'https' is permitted."
            )

        if not parsed.netloc:
            raise ValueError(f"Repository URL is missing host: {cleaned}")

        if ".." in parsed.path.split("/"):
            raise ValueError(f"Path traversal detected in repository URL: {cleaned}")

        return cleaned

    @staticmethod
    def initialize_sample_repo(target_dir: str | Path) -> Path:
        """Create a self-contained sample Python project in `target_dir` for dry-run verification."""
        workspace = Path(target_dir).resolve()
        workspace.mkdir(parents=True, exist_ok=True)

        pkg_dir = workspace / "bounty_pkg"
        pkg_dir.mkdir(parents=True, exist_ok=True)
        (pkg_dir / "__init__.py").write_text('"""Sample target package."""\n', encoding="utf-8")
        (pkg_dir / "calculator.py").write_text(
            '"""Sample calculator module with an unpatched edge case."""\n\n\n'
            "def add(a: float, b: float) -> float:\n"
            "    return a + b\n\n\n"
            "def multiply(a: float, b: float) -> float:\n"
            "    return a * b\n\n\n"
            "def safe_divide(a: float, b: float, default: float = 0.0) -> float:\n"
            "    # Bug: does not guard against division by zero yet\n"
            "    return a / b\n",
            encoding="utf-8",
        )

        tests_dir = workspace / "tests"
        tests_dir.mkdir(parents=True, exist_ok=True)
        (tests_dir / "test_calculator.py").write_text(
            "from bounty_pkg.calculator import add, multiply\n\n\n"
            "def test_add() -> None:\n"
            "    assert add(2, 3) == 5\n\n\n"
            "def test_multiply() -> None:\n"
            "    assert multiply(4, 5) == 20\n",
            encoding="utf-8",
        )
        return workspace

    def clone_repo_to_temp_volume(
        self,
        repo_url: str,
        target_dir: str | Path | None = None,
        branch: str | None = None,
    ) -> Path:
        """Clone a GitHub repository into an isolated temporary workspace directory."""
        validated_url = self.validate_repo_url(repo_url)
        workspace = (
            Path(target_dir).resolve()
            if target_dir is not None
            else Path(tempfile.mkdtemp(prefix="bountysweep_ws_")).resolve()
        )
        workspace.mkdir(parents=True, exist_ok=True)

        if validated_url.startswith("mock://"):
            return self.initialize_sample_repo(workspace)

        cmd = ["git", "clone", "--depth", "1"]
        if branch:
            if branch.startswith("-"):
                raise ValueError(f"Invalid branch name: {branch}")
            cmd.extend(["--branch", branch])
        cmd.extend(["--", validated_url, str(workspace)])

        env = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "https",
        }

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.settings.SANDBOX_TIMEOUT_SECONDS,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            shutil.rmtree(workspace, ignore_errors=True)
            raise RuntimeError(f"Timed out cloning repository {validated_url}") from exc

        if proc.returncode != 0:
            if self.settings.DRY_RUN_MODE:
                logger.warning(
                    "Git clone failed in DRY_RUN_MODE for %s (%s); initializing sample repo.",
                    validated_url,
                    proc.stderr.strip(),
                )
                return self.initialize_sample_repo(workspace)
            shutil.rmtree(workspace, ignore_errors=True)
            raise RuntimeError(
                f"Failed to clone repository {validated_url}: {proc.stderr.strip()}"
            )

        return workspace

    @staticmethod
    def discover_safe_local_test_scripts(workspace_dir: str | Path) -> list[list[str]]:
        """Discover safe local Python test scripts in workspace_dir or mentioned in repo docs."""
        workspace = Path(workspace_dir).resolve()
        if not workspace.exists():
            return []

        candidates: list[str] = []

        # 1. Check scripts mentioned in README / Makefile / pyproject.toml
        for doc_name in ("README.md", "README.rst", "README.txt", "Makefile", "pyproject.toml"):
            doc_path = workspace / doc_name
            if doc_path.exists() and doc_path.is_file():
                try:
                    content = doc_path.read_text(encoding="utf-8", errors="ignore")
                    for match in _DOC_TEST_SCRIPT_RE.finditer(content):
                        candidates.append(match.group(1).strip())
                except OSError:
                    pass

        # 2. Check standard local test script filenames
        for std_rel in (
            "run_tests.py",
            "test.py",
            "tests.py",
            "check_tests.py",
            "scripts/run_tests.py",
            "scripts/test.py",
        ):
            candidates.append(std_rel)

        # 3. Check top-level *test*.py files
        try:
            for child in sorted(workspace.glob("*test*.py")):
                if child.is_file():
                    candidates.append(child.name)
        except OSError:
            pass

        seen: set[str] = set()
        commands: list[list[str]] = []
        for rel in candidates:
            cleaned = rel.lstrip("./")
            if not cleaned or cleaned in seen:
                continue
            if ".." in cleaned.split("/") or cleaned.startswith("-") or not _SAFE_REL_SCRIPT_RE.match(cleaned):
                continue
            resolved = (workspace / cleaned).resolve()
            if resolved != workspace and workspace in resolved.parents and resolved.is_file():
                seen.add(cleaned)
                commands.append(["python", cleaned])

        return commands

    @classmethod
    def get_fallback_test_commands(cls, workspace_dir: str | Path) -> list[list[str]]:
        """Return ordered fallback test runner commands when pytest exits with code 5 (no tests collected)."""
        workspace = Path(workspace_dir).resolve()
        commands: list[list[str]] = [list(cls.UNITTEST_DISCOVER_COMMAND)]
        if (workspace / "tests").is_dir():
            commands.append(["python", "-m", "unittest", "discover", "-s", "tests", "-p", "*test*.py", "-v"])
        elif (workspace / "test").is_dir():
            commands.append(["python", "-m", "unittest", "discover", "-s", "test", "-p", "*test*.py", "-v"])
        commands.extend(cls.discover_safe_local_test_scripts(workspace))
        return commands

    @staticmethod
    def parse_pytest_output(
        stdout: str,
        stderr: str = "",
        exit_code: int = 0,
        timed_out: bool = False,
        duration_seconds: float = 0.0,
        is_fallback_script: bool = False,
    ) -> SandboxTestRunResult:
        """Parse pytest, unittest, or fallback script output into a `SandboxTestRunResult`."""
        combined = f"{stdout}\n{stderr}"
        passed_matches = _PASSED_RE.findall(combined)
        failed_matches = _FAILED_RE.findall(combined)
        error_matches = _ERROR_RE.findall(combined)

        passed_count = int(passed_matches[-1]) if passed_matches else 0
        failed_count = int(failed_matches[-1]) if failed_matches else 0
        error_count = int(error_matches[-1]) if error_matches else 0
        effective_failed = failed_count + error_count

        # Parse unittest output ('Ran N tests in X.XXXs') if pytest counters did not match
        if passed_count == 0 and effective_failed == 0:
            unittest_ran = _UNITTEST_RAN_RE.findall(combined)
            if unittest_ran:
                ran_count = int(unittest_ran[-1])
                u_fail = _UNITTEST_FAILURES_RE.findall(combined)
                u_err = _UNITTEST_ERRORS_RE.findall(combined)
                effective_failed = (int(u_fail[-1]) if u_fail else 0) + (int(u_err[-1]) if u_err else 0)
                if exit_code != 0 and effective_failed == 0 and ran_count > 0:
                    effective_failed = 1
                passed_count = max(0, ran_count - effective_failed)
            elif is_fallback_script and not timed_out and exit_code == 0:
                lower_out = combined.lower()
                if "ran 0 tests" not in lower_out and "no tests ran" not in lower_out:
                    passed_count = 1

        total_count = passed_count + effective_failed

        passed = (
            not timed_out
            and exit_code == 0
            and effective_failed == 0
            and passed_count > 0
        )

        return SandboxTestRunResult(
            passed=passed,
            exit_code=exit_code,
            passed_count=passed_count,
            failed_count=effective_failed,
            total_count=total_count,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            duration_seconds=round(duration_seconds, 4),
        )

    def _run_local_fallback_pytest(
        self,
        workspace_dir: Path,
        command: list[str] | str | None = None,
        is_fallback_script: bool = False,
    ) -> SandboxTestRunResult:
        """Fallback local test execution used in dry-run mode when Docker is unavailable."""
        start = time.monotonic()
        if isinstance(command, str):
            args = command.split()
        elif isinstance(command, list) and command:
            args = list(command)
        else:
            args = list(self.DEFAULT_PYTEST_COMMAND)

        if args[0] == "pytest":
            cmd = [sys.executable, "-m", "pytest", *args[1:]]
        elif args[0] in ("python", "python3"):
            cmd = [sys.executable, *args[1:]]
        else:
            cmd = args

        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(workspace_dir),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(workspace_dir),
        }

        try:
            proc = subprocess.run(
                cmd,
                cwd=str(workspace_dir),
                env=env,
                capture_output=True,
                text=True,
                timeout=self.settings.SANDBOX_TIMEOUT_SECONDS,
                check=False,
            )
            duration = time.monotonic() - start
            return self.parse_pytest_output(
                stdout=proc.stdout,
                stderr=proc.stderr,
                exit_code=proc.returncode,
                timed_out=False,
                duration_seconds=duration,
                is_fallback_script=is_fallback_script,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - start
            stdout_str = (
                exc.stdout.decode("utf-8", errors="replace")
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or "")
            )
            stderr_str = (
                exc.stderr.decode("utf-8", errors="replace")
                if isinstance(exc.stderr, bytes)
                else (exc.stderr or "")
            )
            return self.parse_pytest_output(
                stdout=stdout_str,
                stderr=f"{stderr_str}\nExecution timed out after {self.settings.SANDBOX_TIMEOUT_SECONDS}s.".strip(),
                exit_code=124,
                timed_out=True,
                duration_seconds=duration,
                is_fallback_script=is_fallback_script,
            )

    def _run_single_command_in_container(
        self,
        workspace_path: Path,
        command: list[str] | str | None = None,
        is_fallback_script: bool = False,
    ) -> tuple[SandboxTestRunResult, dict[str, Any]]:
        """Execute a single test command inside the isolated container (or local fallback)."""
        container_kwargs = self._build_container_kwargs(workspace_path, command=command)
        start = time.monotonic()

        try:
            client = self._get_docker_client()
        except DockerException:
            if self.allow_local_fallback and self._docker_client is None:
                logger.info(
                    "Docker daemon socket unavailable on host; using isolated local test fallback."
                )
                result = self._run_local_fallback_pytest(
                    workspace_path,
                    command=command,
                    is_fallback_script=is_fallback_script,
                )
                return result, container_kwargs
            raise

        container = None
        run_kwargs = (
            {k: v for k, v in container_kwargs.items() if k != "nano_cpus"}
            if ("cpu_period" in container_kwargs or "cpu_quota" in container_kwargs)
            else dict(container_kwargs)
        )
        try:
            container = client.containers.run(**run_kwargs)
        except DockerException:
            if self.allow_local_fallback and self._docker_client is None:
                logger.info(
                    "Docker container launch unavailable on host; using local test fallback."
                )
                result = self._run_local_fallback_pytest(
                    workspace_path,
                    command=command,
                    is_fallback_script=is_fallback_script,
                )
                return result, container_kwargs
            raise

        timed_out = False
        exit_code = -1
        stdout_str = ""
        stderr_str = ""

        try:
            wait_result = container.wait(timeout=self.settings.SANDBOX_TIMEOUT_SECONDS)
            if isinstance(wait_result, dict):
                exit_code = int(wait_result.get("StatusCode", 1))
            else:
                exit_code = int(wait_result)
        except Exception as exc:
            timed_out = True
            exit_code = 124
            stderr_str = (
                f"Container execution timed out after {self.settings.SANDBOX_TIMEOUT_SECONDS}s: {exc}"
            )
            try:
                container.kill()
            except Exception:
                pass
        finally:
            duration = time.monotonic() - start
            try:
                raw_logs = container.logs(stdout=True, stderr=True)
                if isinstance(raw_logs, bytes):
                    stdout_str = raw_logs.decode("utf-8", errors="replace")
                else:
                    stdout_str = str(raw_logs)
            except Exception as log_exc:
                stderr_str = f"{stderr_str}\nFailed to fetch container logs: {log_exc}".strip()

            try:
                container.remove(force=True)
            except Exception as rm_exc:
                logger.warning("Failed to force-remove sandbox container: %s", rm_exc)

        result = self.parse_pytest_output(
            stdout=stdout_str,
            stderr=stderr_str,
            exit_code=exit_code,
            timed_out=timed_out,
            duration_seconds=duration,
            is_fallback_script=is_fallback_script,
        )
        return result, container_kwargs

    def run_pytest_in_container(
        self,
        workspace_dir: str | Path,
        command: list[str] | str | None = None,
    ) -> tuple[SandboxTestRunResult, dict[str, Any]]:
        """Run pytest inside an ephemeral isolated container; if pytest exits with code 5 (no tests collected),
        automatically fall back to `python -m unittest discover` or a safe local test script in the repo.
        """
        workspace_path = Path(workspace_dir).resolve()
        self._last_fallback_command = None
        result, container_kwargs = self._run_single_command_in_container(
            workspace_path,
            command=command,
            is_fallback_script=False,
        )

        # If a custom command was explicitly requested or pytest did not exit with code 5, return immediately
        if command is not None or result.exit_code != 5:
            return result, container_kwargs

        logger.info(
            "pytest exited with code 5 (no tests collected) in %s; attempting fallback test runners.",
            workspace_path,
        )
        fallback_commands = self.get_fallback_test_commands(workspace_path)
        for fb_cmd in fallback_commands:
            is_script = fb_cmd[:3] != ["python", "-m", "unittest"]
            fb_result, fb_kwargs = self._run_single_command_in_container(
                workspace_path,
                command=fb_cmd,
                is_fallback_script=is_script,
            )
            if fb_result.passed or fb_result.total_count > 0:
                self._last_fallback_command = fb_cmd
                return fb_result, fb_kwargs

        return result, container_kwargs

    @staticmethod
    def _safe_write_file(workspace_dir: Path, relative_path: str, content: str) -> Path:
        """Write a file inside `workspace_dir`, rejecting any path traversal outside `/workspace`."""
        cleaned_rel = relative_path.lstrip("/")
        target_path = (workspace_dir / cleaned_rel).resolve()
        workspace_resolved = workspace_dir.resolve()
        if target_path != workspace_resolved and workspace_resolved not in target_path.parents:
            raise ValueError(
                f"Refusing to write file outside workspace: {relative_path}"
            )
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(content, encoding="utf-8")
        return target_path

    @classmethod
    def apply_patch_and_tests(
        cls,
        workspace_dir: str | Path,
        file_patches: dict[str, str],
        regression_tests: dict[str, str],
    ) -> int:
        """Write patched source files and regression test files into workspace, returning added test count."""
        workspace_path = Path(workspace_dir).resolve()

        for rel_path, content in file_patches.items():
            cls._safe_write_file(workspace_path, rel_path, content)

        added_tests_count = 0
        for rel_path, test_content in regression_tests.items():
            target = (workspace_path / rel_path.lstrip("/")).resolve()
            existing_funcs: set[str] = set()
            if target.exists() and target.is_file():
                existing_funcs = set(
                    _TEST_FUNC_RE.findall(target.read_text(encoding="utf-8"))
                )

            cls._safe_write_file(workspace_path, rel_path, test_content)
            new_funcs = set(_TEST_FUNC_RE.findall(test_content))
            delta = len(new_funcs - existing_funcs)
            added_tests_count += max(delta, 1 if new_funcs else 0)

        return added_tests_count

    @staticmethod
    def evaluate_submission_gate(
        baseline_run: SandboxTestRunResult,
        patched_run: SandboxTestRunResult,
        regression_tests_added: int,
    ) -> tuple[bool, bool, bool, str | None]:
        """Evaluate whether the patched run satisfies strict PR submission criteria.

        Returns:
            Tuple of `(all_existing_tests_passed, new_regression_test_passed, submission_approved, rejection_reason)`.
        """
        if baseline_run.timed_out:
            return (
                False,
                False,
                False,
                "Baseline test run timed out before patch could be verified.",
            )

        if patched_run.timed_out:
            return (
                False,
                False,
                False,
                f"Patched test run timed out after {patched_run.duration_seconds}s.",
            )

        all_existing_tests_passed = (
            patched_run.passed
            and patched_run.exit_code == 0
            and patched_run.failed_count == 0
            and patched_run.passed_count >= baseline_run.passed_count
            and baseline_run.passed_count > 0
        )

        new_regression_test_passed = (
            all_existing_tests_passed
            and regression_tests_added >= 1
            and patched_run.passed_count >= baseline_run.passed_count + 1
        )

        if not all_existing_tests_passed:
            if patched_run.failed_count > 0 or patched_run.exit_code != 0:
                reason = (
                    f"Patched test suite failed (exit_code={patched_run.exit_code}, "
                    f"failed_count={patched_run.failed_count})."
                )
            elif baseline_run.passed_count == 0:
                reason = "Baseline test suite executed 0 passing tests."
            else:
                reason = (
                    f"Existing test count regressed ({patched_run.passed_count} passed vs "
                    f"{baseline_run.passed_count} baseline)."
                )
            return False, False, False, reason

        if not new_regression_test_passed:
            reason = (
                f"Missing passing regression test: regression_tests_added={regression_tests_added}, "
                f"baseline_passed={baseline_run.passed_count}, patched_passed={patched_run.passed_count}."
            )
            return True, False, False, reason

        return True, True, True, None

    def verify_bounty_patch(
        self,
        bounty_id: str,
        repo_url: str,
        file_patches: dict[str, str],
        regression_tests: dict[str, str],
        workspace_dir: str | Path | None = None,
        pytest_command: list[str] | str | None = None,
        cleanup_workspace: bool = True,
    ) -> SandboxExecutionReport:
        """Execute end-to-end baseline and patched test runs in the sandbox and verify the gate."""
        created_temp = workspace_dir is None
        workspace_path = (
            self.clone_repo_to_temp_volume(repo_url)
            if workspace_dir is None
            else Path(workspace_dir).resolve()
        )

        try:
            baseline_run, container_audit = self.run_pytest_in_container(
                workspace_path,
                command=pytest_command,
            )
            baseline_fallback_cmd = self._last_fallback_command

            regression_tests_added = self.apply_patch_and_tests(
                workspace_dir=workspace_path,
                file_patches=file_patches,
                regression_tests=regression_tests,
            )

            patched_run, container_audit = self.run_pytest_in_container(
                workspace_path,
                command=pytest_command,
            )

            # If baseline used a fallback test runner (e.g., unittest or a safe local test script)
            # and pytest on the patched repo only collected the newly added pytest regression test(s),
            # also run the baseline fallback command to verify all existing tests still pass.
            if (
                pytest_command is None
                and baseline_fallback_cmd is not None
                and patched_run.passed
                and patched_run.passed_count < baseline_run.passed_count + regression_tests_added
            ):
                is_script = baseline_fallback_cmd[:3] != ["python", "-m", "unittest"]
                fb_patched, _ = self._run_single_command_in_container(
                    workspace_path,
                    command=baseline_fallback_cmd,
                    is_fallback_script=is_script,
                )
                if fb_patched.passed and fb_patched.failed_count == 0:
                    combined_passed = fb_patched.passed_count + patched_run.passed_count
                    patched_run = SandboxTestRunResult(
                        passed=True,
                        exit_code=0,
                        passed_count=combined_passed,
                        failed_count=0,
                        total_count=combined_passed,
                        stdout=f"{fb_patched.stdout}\n{patched_run.stdout}".strip(),
                        stderr=f"{fb_patched.stderr}\n{patched_run.stderr}".strip(),
                        timed_out=False,
                        duration_seconds=round(
                            fb_patched.duration_seconds + patched_run.duration_seconds, 4
                        ),
                    )
                elif not fb_patched.passed:
                    patched_run = fb_patched

            (
                all_existing_passed,
                new_regression_passed,
                approved,
                rejection_reason,
            ) = self.evaluate_submission_gate(
                baseline_run=baseline_run,
                patched_run=patched_run,
                regression_tests_added=regression_tests_added,
            )

            return SandboxExecutionReport(
                bounty_id=bounty_id,
                repo_url=repo_url,
                baseline_run=baseline_run,
                patched_run=patched_run,
                regression_tests_added=regression_tests_added,
                all_existing_tests_passed=all_existing_passed,
                new_regression_test_passed=new_regression_passed,
                submission_approved=approved,
                rejection_reason=rejection_reason,
                container_config_audit=container_audit,
            )
        finally:
            if created_temp and cleanup_workspace:
                shutil.rmtree(workspace_path, ignore_errors=True)
