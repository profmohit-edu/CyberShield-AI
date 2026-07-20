"""Comprehensive unit tests for the Mythril security-engine adapter."""

import asyncio
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, cast

import pytest

from security.base import AnalyzerFinding, SourceLocation
from security.mythril import (
    MythrilAdapter,
    MythrilAdapterConfig,
    MythrilExecutionError,
    MythrilInputError,
    MythrilOutputError,
    MythrilTimeoutError,
    MythrilUnavailableError,
)

VALID_SOURCE = "pragma solidity ^0.8.20; contract Vault {}"


@dataclass(slots=True)
class FakeProcess:
    """Minimal asyncio subprocess double with controllable completion."""

    return_code: int = 0
    block_until_killed: bool = False
    killed: bool = False

    async def wait(self) -> int:
        if self.block_until_killed and not self.killed:
            await asyncio.Event().wait()
        return self.return_code

    def kill(self) -> None:
        self.killed = True


@dataclass(frozen=True, slots=True)
class ProcessInvocation:
    """Captured subprocess arguments and source content."""

    arguments: tuple[object, ...]
    keywords: Mapping[str, object]
    source: str


def _issue(
    *,
    rule_id: str = "107",
    title: str = "External Call To User-Supplied Address",
    severity: str = "High",
    description: str = "A call to a user-controlled address is executed.",
    filename: str | None = "Vault.sol",
    line: object | None = 14,
) -> dict[str, object]:
    issue: dict[str, object] = {
        "swc-id": rule_id,
        "title": title,
        "severity": severity,
        "description": description,
        "contract": "Vault",
        "function": "withdraw()",
    }
    if filename is not None:
        issue["filename"] = filename
    if line is not None:
        issue["lineno"] = line
    return issue


def _payload(issues: list[object] | None = None) -> dict[str, object]:
    return {"success": True, "error": None, "issues": issues or []}


def _install_process(
    monkeypatch: pytest.MonkeyPatch,
    *,
    output: object | bytes | None = None,
    return_code: int = 0,
    block_until_killed: bool = False,
) -> tuple[FakeProcess, list[ProcessInvocation]]:
    process = FakeProcess(
        return_code=return_code,
        block_until_killed=block_until_killed,
    )
    invocations: list[ProcessInvocation] = []

    async def fake_create_subprocess_exec(*arguments: object, **keywords: object) -> FakeProcess:
        workspace = cast(Path, keywords["cwd"])
        source_name = cast(str, arguments[2])
        invocations.append(
            ProcessInvocation(
                arguments=arguments,
                keywords=dict(keywords),
                source=(workspace / source_name).read_text(encoding="utf-8"),
            )
        )
        if output is not None:
            output_bytes = output if isinstance(output, bytes) else json.dumps(output).encode()
            output_file = cast(BinaryIO, keywords["stdout"])
            output_file.write(output_bytes)
            output_file.flush()
        return process

    monkeypatch.setattr(
        "security.mythril.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )
    return process, invocations


async def test_analyze_executes_mythril_with_json_and_restricted_streams(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, invocations = _install_process(monkeypatch, output=_payload())

    findings = await MythrilAdapter().analyze(VALID_SOURCE, "Vault.sol")

    assert findings == []
    assert len(invocations) == 1
    invocation = invocations[0]
    assert invocation.arguments == (
        "myth",
        "analyze",
        "Vault.sol",
        "-o",
        "json",
        "--execution-timeout",
        "120",
    )
    assert invocation.source == VALID_SOURCE
    assert invocation.keywords["stdin"] is asyncio.subprocess.DEVNULL
    assert invocation.keywords["stdout"] is not asyncio.subprocess.DEVNULL
    assert invocation.keywords["stderr"] is asyncio.subprocess.DEVNULL
    environment = cast(Mapping[str, str], invocation.keywords["env"])
    assert environment["HOME"] == str(invocation.keywords["cwd"])
    assert set(environment) == {"HOME", "LANG", "LC_ALL", "PATH"}


async def test_analyze_accepts_exit_one_and_normalizes_complete_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issue = _issue(
        description="  Mythril evidence.  ",
        filename="/private/temporary/Vault.sol",
        line=42,
    )
    _install_process(monkeypatch, output=_payload([issue]), return_code=1)

    findings = await MythrilAdapter().analyze(VALID_SOURCE, "Vault.sol")

    assert findings == [
        AnalyzerFinding(
            analyzer="mythril",
            rule_id="SWC-107",
            title="External Call To User-Supplied Address",
            severity="high",
            description="Mythril evidence.",
            location=SourceLocation(path="Vault.sol", start_line=42, end_line=42),
        )
    ]
    assert MythrilAdapter().name == "mythril"


async def test_analyze_preserves_every_issue(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_process(
        monkeypatch,
        output=_payload(
            [
                _issue(rule_id="101", title="Integer Arithmetic Bugs"),
                _issue(rule_id="SWC-106", title="Unprotected Selfdestruct", line=27),
            ]
        ),
        return_code=1,
    )

    findings = await MythrilAdapter().analyze(VALID_SOURCE, "Vault.sol")

    assert [finding.rule_id for finding in findings] == ["SWC-101", "SWC-106"]
    assert [finding.title for finding in findings] == [
        "Integer Arithmetic Bugs",
        "Unprotected Selfdestruct",
    ]


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("Critical", "critical"),
        ("High", "high"),
        ("Medium", "medium"),
        ("Low", "low"),
        ("Informational", "informational"),
    ],
)
async def test_analyze_preserves_explicit_severity_mapping(
    monkeypatch: pytest.MonkeyPatch,
    severity: str,
    expected: str,
) -> None:
    _install_process(monkeypatch, output=_payload([_issue(severity=severity)]))

    findings = await MythrilAdapter().analyze(VALID_SOURCE, "Vault.sol")

    assert findings[0].severity == expected


@pytest.mark.parametrize(
    "issue",
    [
        _issue(filename=None, line=None),
        _issue(filename="Dependency.sol", line=8),
    ],
)
async def test_analyze_omits_unavailable_or_nonuploaded_location(
    monkeypatch: pytest.MonkeyPatch,
    issue: dict[str, object],
) -> None:
    _install_process(monkeypatch, output=_payload([issue]))

    findings = await MythrilAdapter().analyze(VALID_SOURCE, "Vault.sol")

    assert findings[0].location is None


@pytest.mark.parametrize(
    ("source", "source_name"),
    [
        ("", "Vault.sol"),
        (" \n", "Vault.sol"),
        (VALID_SOURCE, ""),
        (VALID_SOURCE, "."),
        (VALID_SOURCE, "../Vault.sol"),
        (VALID_SOURCE, "contracts/Vault.sol"),
        (VALID_SOURCE, "contracts\\Vault.sol"),
        (VALID_SOURCE, "Vault.txt"),
        (VALID_SOURCE, "Vault.sol\x00ignored"),
        (VALID_SOURCE, f"{'v' * 252}.sol"),
    ],
)
async def test_analyze_rejects_invalid_input_before_execution(
    source: str,
    source_name: str,
) -> None:
    with pytest.raises(MythrilInputError):
        await MythrilAdapter().analyze(source, source_name)


async def test_analyze_enforces_utf8_source_size_limit() -> None:
    adapter = MythrilAdapter(MythrilAdapterConfig(max_source_bytes=3))

    with pytest.raises(MythrilInputError, match="size limit"):
        await adapter.analyze("éé", "Vault.sol")


def test_default_config_is_constructible() -> None:
    config = MythrilAdapterConfig()

    assert config.binary == "myth"
    assert config.process_timeout_seconds == 135.0
    assert config.analysis_timeout_seconds == 120


@pytest.mark.parametrize(
    "factory",
    [
        lambda: MythrilAdapterConfig(binary=""),
        lambda: MythrilAdapterConfig(binary="bad\x00binary"),
        lambda: MythrilAdapterConfig(process_timeout_seconds=0),
        lambda: MythrilAdapterConfig(analysis_timeout_seconds=0),
        lambda: MythrilAdapterConfig(max_source_bytes=0),
        lambda: MythrilAdapterConfig(max_output_bytes=0),
    ],
)
def test_config_rejects_invalid_binary_and_non_positive_limits(
    factory: Callable[[], MythrilAdapterConfig],
) -> None:
    with pytest.raises(ValueError):
        factory()


@pytest.mark.parametrize("error_type", [FileNotFoundError, PermissionError, OSError])
async def test_analyze_wraps_unavailable_binary_without_leaking_os_details(
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[OSError],
) -> None:
    async def unavailable(*arguments: object, **keywords: object) -> FakeProcess:
        del arguments, keywords
        raise error_type("private executable path")

    monkeypatch.setattr("security.mythril.asyncio.create_subprocess_exec", unavailable)

    with pytest.raises(MythrilUnavailableError, match="could not be started") as captured:
        await MythrilAdapter().analyze(VALID_SOURCE, "Vault.sol")

    assert "private executable path" not in str(captured.value)


async def test_analyze_rejects_unexpected_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_process(monkeypatch, return_code=2)

    with pytest.raises(MythrilExecutionError, match="execution failed"):
        await MythrilAdapter().analyze(VALID_SOURCE, "Vault.sol")


async def test_analyze_kills_process_after_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    process, _ = _install_process(monkeypatch, block_until_killed=True)
    adapter = MythrilAdapter(MythrilAdapterConfig(process_timeout_seconds=0.001))

    with pytest.raises(MythrilTimeoutError, match="configured timeout"):
        await adapter.analyze(VALID_SOURCE, "Vault.sol")

    assert process.killed is True


async def test_cancellation_kills_process(monkeypatch: pytest.MonkeyPatch) -> None:
    process, _ = _install_process(monkeypatch, block_until_killed=True)
    task = asyncio.create_task(MythrilAdapter().analyze(VALID_SOURCE, "Vault.sol"))
    await asyncio.sleep(0)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert process.killed is True


@pytest.mark.parametrize(
    ("output", "message"),
    [
        (None, "empty JSON"),
        (b"", "empty JSON"),
        (b"not-json", "invalid JSON"),
        (["not", "an", "object"], "root must be an object"),
    ],
)
async def test_analyze_rejects_empty_or_malformed_json(
    monkeypatch: pytest.MonkeyPatch,
    output: object | bytes | None,
    message: str,
) -> None:
    _install_process(monkeypatch, output=output)

    with pytest.raises(MythrilOutputError, match=message):
        await MythrilAdapter().analyze(VALID_SOURCE, "Vault.sol")


async def test_analyze_rejects_oversized_json_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_process(monkeypatch, output=b"1234")
    adapter = MythrilAdapter(MythrilAdapterConfig(max_output_bytes=3))

    with pytest.raises(MythrilOutputError, match="size limit"):
        await adapter.analyze(VALID_SOURCE, "Vault.sol")


@pytest.mark.parametrize(
    ("payload", "error_type", "message"),
    [
        (
            {"success": False, "error": "compiler details", "issues": []},
            MythrilExecutionError,
            "unsuccessful analysis",
        ),
        (
            {"success": True, "issues": {}},
            MythrilOutputError,
            "issues must be an array",
        ),
        (
            _payload(["not-an-object"]),
            MythrilOutputError,
            "issue must be an object",
        ),
        (
            _payload([_issue(rule_id="")]),
            MythrilOutputError,
            "issue.swc-id must be non-empty text",
        ),
        (
            _payload([_issue(title="")]),
            MythrilOutputError,
            "issue.title must be non-empty text",
        ),
        (
            _payload([_issue(severity="Unknown")]),
            MythrilOutputError,
            "unsupported issue severity",
        ),
        (
            _payload([_issue(description="")]),
            MythrilOutputError,
            "issue.description must be non-empty text",
        ),
        (
            _payload([_issue(filename=None, line=14)]),
            MythrilOutputError,
            "invalid source filename",
        ),
        (
            _payload([_issue(filename="Vault.sol", line=None)]),
            MythrilOutputError,
            "source line information",
        ),
        (
            _payload([_issue(line=True)]),
            MythrilOutputError,
            "source line information",
        ),
        (
            _payload([_issue(line=0)]),
            MythrilOutputError,
            "source line information",
        ),
    ],
)
async def test_analyze_fails_closed_for_invalid_mythril_schema(
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
    error_type: type[MythrilExecutionError] | type[MythrilOutputError],
    message: str,
) -> None:
    _install_process(monkeypatch, output=payload)

    with pytest.raises(error_type, match=message):
        await MythrilAdapter().analyze(VALID_SOURCE, "Vault.sol")
