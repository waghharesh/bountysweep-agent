"""Comprehensive unit and dry-run E2E tests for DockerSandboxRunner."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from docker.errors import DockerException

from config.settings import Settings
from sandbox.runner import (
    DockerSandboxRunner,
    SandboxExecutionReport,
    SandboxTestRunResult,
)


def _make_mock_container(
    stdout_bytes: bytes,
    status_code: int = 0,
    wait_exception: Exception | None = None,
) -> MagicMock:
    """Create a mock Docker container object."""
    container = MagicMock()
    if wait_exception is not None:
        container.wait.side_effect = wait_exception
    else:
        container.wait.return_value = {"StatusCode": status_code}
    container.logs.return_value = stdout_bytes
    return container


def test_build_container_kwargs_enforces_strict_isolation(tmp_path: Path) -> None:
    """Verify all mandatory container isolation constraints (network, CPU, RAM, read-only rootfs, volumes)."""
    settings = Settings(
        SANDBOX_IMAGE="python:3.12-slim",
        SANDBOX_TIMEOUT_SECONDS=120,
        SANDBOX_CPU_PERIOD=100_000,
        SANDBOX_CPU_QUOTA=100_000,
        SANDBOX_MEM_LIMIT="1g",
    )
    runner = DockerSandboxRunner(settings=settings)
    kwargs = runner._build_container_kwargs(tmp_path)

    assert kwargs["image"] == "python:3.12-slim"
    assert kwargs["network_mode"] == "none"
    assert kwargs["cpu_period"] == 100_000
    assert kwargs["cpu_quota"] == 100_000
    assert kwargs["nano_cpus"] == 1_000_000_000
    assert kwargs["mem_limit"] == "1g"
    assert kwargs["memswap_limit"] == "1g"
    assert kwargs["read_only"] is True
    assert kwargs["working_dir"] == "/workspace"
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["security_opt"] == ["no-new-privileges:true"]
    assert kwargs["pids_limit"] == 128
    assert kwargs["detach"] is True
    assert kwargs["tmpfs"] == {"/tmp": "size=64m,noexec,nosuid,nodev"}
    assert kwargs["volumes"] == {
        str(tmp_path.resolve()): {
            "bind": "/workspace",
            "mode": "rw",
        }
    }
    assert kwargs["environment"]["PYTHONDONTWRITEBYTECODE"] == "1"
    assert kwargs["environment"]["PYTHONPATH"] == "/workspace"


def test_timeout_handling_kills_and_removes_container(tmp_path: Path) -> None:
    """Verify 120s timeout kills the container, force-removes it, and rejects submission."""
    settings = Settings(SANDBOX_TIMEOUT_SECONDS=120, DRY_RUN_MODE=False)
    baseline_container = _make_mock_container(
        stdout_bytes=b"....\n4 passed in 0.12s\n",
        status_code=0,
    )
    timeout_container = _make_mock_container(
        stdout_bytes=b"hanging test...",
        wait_exception= TimeoutError("Read timed out after 120 seconds"),
    )

    mock_client = MagicMock()
    mock_client.containers.run.side_effect = [baseline_container, timeout_container]

    runner = DockerSandboxRunner(
        settings=settings,
        docker_client=mock_client,
        allow_local_fallback=False,
    )
    DockerSandboxRunner.initialize_sample_repo(tmp_path)

    report = runner.verify_bounty_patch(
        bounty_id="bounty-timeout-001",
        repo_url="https://github.com/example/repo",
        file_patches={"bounty_pkg/calculator.py": "def add(a, b): return a + b\n"},
        regression_tests={"tests/test_reg.py": "def test_infinite():\n    assert True\n"},
        workspace_dir=tmp_path,
    )

    timeout_container.wait.assert_called_once_with(timeout=120)
    timeout_container.kill.assert_called_once()
    timeout_container.remove.assert_called_once_with(force=True)
    baseline_container.remove.assert_called_once_with(force=True)

    assert report.patched_run.timed_out is True
    assert report.patched_run.passed is False
    assert report.submission_approved is False
    assert report.rejection_reason is not None
    assert "timed out" in report.rejection_reason.lower()


def test_baseline_vs_patched_approval_when_all_pass_plus_regression_test(
    tmp_path: Path,
) -> None:
    """Verify submission is approved when 100% of existing tests pass and >=1 new regression test passes."""
    baseline_container = _make_mock_container(
        stdout_bytes=b"..\n2 passed in 0.08s\n",
        status_code=0,
    )
    patched_container = _make_mock_container(
        stdout_bytes=b"...\n3 passed in 0.10s\n",
        status_code=0,
    )

    mock_client = MagicMock()
    mock_client.containers.run.side_effect = [baseline_container, patched_container]

    runner = DockerSandboxRunner(docker_client=mock_client, allow_local_fallback=False)
    DockerSandboxRunner.initialize_sample_repo(tmp_path)

    report = runner.verify_bounty_patch(
        bounty_id="bounty-approve-002",
        repo_url="https://github.com/example/repo",
        file_patches={
            "bounty_pkg/calculator.py": (
                "def add(a: float, b: float) -> float:\n    return a + b\n"
                "def multiply(a: float, b: float) -> float:\n    return a * b\n"
                "def safe_divide(a: float, b: float, default: float = 0.0) -> float:\n"
                "    return default if b == 0 else a / b\n"
            )
        },
        regression_tests={
            "tests/test_regression_zero_div.py": (
                "from bounty_pkg.calculator import safe_divide\n\n"
                "def test_safe_divide_by_zero() -> None:\n"
                "    assert safe_divide(10, 0, default=-1.0) == -1.0\n"
            )
        },
        workspace_dir=tmp_path,
    )

    assert isinstance(report, SandboxExecutionReport)
    assert report.baseline_run.passed_count == 2
    assert report.patched_run.passed_count == 3
    assert report.regression_tests_added == 1
    assert report.all_existing_tests_passed is True
    assert report.new_regression_test_passed is True
    assert report.submission_approved is True
    assert report.rejection_reason is None
    assert report.container_config_audit["network_mode"] == "none"


def test_rejection_when_existing_test_fails_or_no_new_regression_test(
    tmp_path: Path,
) -> None:
    """Verify submission is rejected if any existing test fails OR if 0 new regression tests pass."""
    # Case A: 1 failed test in patched run
    c1_base = _make_mock_container(stdout_bytes=b"..\n2 passed in 0.05s\n", status_code=0)
    c1_patch = _make_mock_container(
        stdout_bytes=b"..F\n1 failed, 2 passed in 0.09s\n",
        status_code=1,
    )
    mock_client_fail = MagicMock()
    mock_client_fail.containers.run.side_effect = [c1_base, c1_patch]

    runner_fail = DockerSandboxRunner(
        docker_client=mock_client_fail, allow_local_fallback=False
    )
    DockerSandboxRunner.initialize_sample_repo(tmp_path)

    report_fail = runner_fail.verify_bounty_patch(
        bounty_id="bounty-reject-fail",
        repo_url="https://github.com/example/repo",
        file_patches={"bounty_pkg/calculator.py": "# broken patch\n"},
        regression_tests={"tests/test_reg.py": "def test_new():\n    assert False\n"},
        workspace_dir=tmp_path,
    )
    assert report_fail.all_existing_tests_passed is False
    assert report_fail.submission_approved is False
    assert report_fail.rejection_reason is not None
    assert "failed" in report_fail.rejection_reason.lower()

    # Case B: All existing tests pass, but 0 new regression tests added/executed
    c2_base = _make_mock_container(stdout_bytes=b"..\n2 passed in 0.05s\n", status_code=0)
    c2_patch = _make_mock_container(stdout_bytes=b"..\n2 passed in 0.05s\n", status_code=0)
    mock_client_no_reg = MagicMock()
    mock_client_no_reg.containers.run.side_effect = [c2_base, c2_patch]

    runner_no_reg = DockerSandboxRunner(
        docker_client=mock_client_no_reg, allow_local_fallback=False
    )
    report_no_reg = runner_no_reg.verify_bounty_patch(
        bounty_id="bounty-reject-no-reg",
        repo_url="https://github.com/example/repo",
        file_patches={"bounty_pkg/calculator.py": "def add(a, b): return a + b\n"},
        regression_tests={},
        workspace_dir=tmp_path,
    )
    assert report_no_reg.all_existing_tests_passed is True
    assert report_no_reg.new_regression_test_passed is False
    assert report_no_reg.submission_approved is False
    assert report_no_reg.rejection_reason is not None
    assert "regression" in report_no_reg.rejection_reason.lower()


def test_repo_url_and_path_traversal_security_guards(tmp_path: Path) -> None:
    """Verify URL validation rejects git option injection and file writing rejects path traversal."""
    with pytest.raises(ValueError, match="option injection"):
        DockerSandboxRunner.validate_repo_url("--upload-pack=evil")

    with pytest.raises(ValueError, match="Unsupported repository URL scheme"):
        DockerSandboxRunner.validate_repo_url("file:///etc/passwd")

    with pytest.raises(ValueError, match="Path traversal"):
        DockerSandboxRunner.validate_repo_url("https://github.com/org/../../etc/passwd")

    with pytest.raises(ValueError, match="outside workspace"):
        DockerSandboxRunner.apply_patch_and_tests(
            workspace_dir=tmp_path,
            file_patches={"../escape.py": "print('escaped')"},
            regression_tests={},
        )


def test_dry_run_e2e_workspace_execution_with_real_pytest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify dry-run E2E mode executes real pytest against a sample repo when Docker socket is absent."""
    monkeypatch.setattr(
        "sandbox.runner.docker.from_env",
        MagicMock(side_effect=DockerException("Docker socket unavailable in test VM")),
    )
    settings = Settings(DRY_RUN_MODE=True, SANDBOX_TIMEOUT_SECONDS=60)
    runner = DockerSandboxRunner(settings=settings, allow_local_fallback=True)

    report = runner.verify_bounty_patch(
        bounty_id="bounty-dryrun-e2e",
        repo_url="mock://github.com/algora-io/sample-bounty",
        file_patches={
            "bounty_pkg/calculator.py": (
                "def add(a: float, b: float) -> float:\n"
                "    return a + b\n\n\n"
                "def multiply(a: float, b: float) -> float:\n"
                "    return a * b\n\n\n"
                "def safe_divide(a: float, b: float, default: float = 0.0) -> float:\n"
                "    if b == 0:\n"
                "        return default\n"
                "    return a / b\n"
            )
        },
        regression_tests={
            "tests/test_safe_divide_regression.py": (
                "from bounty_pkg.calculator import safe_divide\n\n\n"
                "def test_safe_divide_zero_returns_default() -> None:\n"
                "    assert safe_divide(42.0, 0.0, default=-1.0) == -1.0\n"
                "    assert safe_divide(10.0, 2.0) == 5.0\n"
            )
        },
    )

    assert report.baseline_run.passed is True
    assert report.baseline_run.passed_count == 2
    assert report.patched_run.passed is True
    assert report.patched_run.passed_count == 3
    assert report.regression_tests_added == 1
    assert report.all_existing_tests_passed is True
    assert report.new_regression_test_passed is True
    assert report.submission_approved is True
    assert report.container_config_audit["network_mode"] == "none"
    assert report.container_config_audit["mem_limit"] == "1g"
    assert report.container_config_audit["cpu_quota"] == 100_000
    assert report.container_config_audit["read_only"] is True


def test_pytest_exit_code_5_falls_back_to_unittest_or_safe_local_script(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When pytest exits with code 5 (no tests collected), sandbox must fall back to unittest discover or safe repo script."""
    monkeypatch.setattr(
        "sandbox.runner.docker.from_env",
        MagicMock(side_effect=DockerException("Docker socket unavailable in test VM")),
    )

    # Create a repo where tests are in a custom script mentioned in README.md (not named test_*.py so pytest exits 5)
    (tmp_path / "README.md").write_text(
        "# Sample Repo\nRun validation via:\n```bash\npython custom_check_suite.py\n```\n",
        encoding="utf-8",
    )
    (tmp_path / "math_mod.py").write_text(
        "def clamp_positive(val: int) -> int:\n    return val\n",
        encoding="utf-8",
    )
    (tmp_path / "custom_check_suite.py").write_text(
        "import unittest\n"
        "from math_mod import clamp_positive\n\n"
        "class MathCheck(unittest.TestCase):\n"
        "    def test_positive(self) -> None:\n"
        "        self.assertEqual(clamp_positive(5), 5)\n\n"
        "if __name__ == '__main__':\n"
        "    unittest.main()\n",
        encoding="utf-8",
    )

    discovered = DockerSandboxRunner.discover_safe_local_test_scripts(tmp_path)
    assert ["python", "custom_check_suite.py"] in discovered

    runner = DockerSandboxRunner(
        settings=Settings(DRY_RUN_MODE=True, SANDBOX_TIMEOUT_SECONDS=60),
        allow_local_fallback=True,
    )
    report = runner.verify_bounty_patch(
        bounty_id="bounty-fallback-runner",
        repo_url="https://github.com/example/custom-runner-repo",
        file_patches={
            "math_mod.py": (
                "def clamp_positive(val: int) -> int:\n"
                "    return max(0, val)\n"
            )
        },
        regression_tests={
            "tests/test_clamp_regression.py": (
                "from math_mod import clamp_positive\n\n"
                "def test_negative_clamped_to_zero() -> None:\n"
                "    assert clamp_positive(-10) == 0\n"
            )
        },
        workspace_dir=tmp_path,
        cleanup_workspace=False,
    )

    assert report.baseline_run.passed is True
    assert report.baseline_run.passed_count == 1
    assert report.patched_run.passed is True
    assert report.patched_run.passed_count >= 2
    assert report.all_existing_tests_passed is True
    assert report.new_regression_test_passed is True
    assert report.submission_approved is True
