"""Comprehensive unit tests for the Solhint security-engine adapter."""

import asyncio
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, cast

import pytest

from security.base import AnalyzerFinding, SourceLocation
from security.solhint import (
    SolhintAdapter,
    SolhintAdapterConfig,
    SolhintExecutionError,
    SolhintInputError,
    SolhintOutputError,
    SolhintTimeoutError,
    SolhintUnavailableError,
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
    """Captured subprocess arguments and private workspace inputs."""

    arguments: tuple[object, ...]
    keywords: Mapping[str, object]
    source: str
    config: object


def _message(
    *,
    rule_id: object = "avoid-tx-origin",
    severity: object = "Error",
    message: object = "Avoid using tx.origin.",
    filename: object = "Vault.sol",
    line: object = 12,
    column: object = 9,
) -> dict[str, object]:
    return {
        "ruleId": rule_id,
        "severity": severity,
        "message": message,
        "filePath": filename,
        "line": line,
        "column": column,
    }


def _report(*messages: object, conclusion: bool = True) -> list[object]:
    report = list(messages)
    if conclusion and messages:
        report.append({"conclusion": f"{len(messages)} problem/s"})
    return report


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
        source_name = cast(str, arguments[6])
        config_name = cast(str, arguments[4])
        invocations.append(
            ProcessInvocation(
                arguments=arguments,
                keywords=dict(keywords),
                source=(workspace / source_name).read_text(encoding="utf-8"),
                config=json.loads((workspace / config_name).read_text(encoding="utf-8")),
            )
        )
        if output is not None:
            output_bytes = output if isinstance(output, bytes) else json.dumps(output).encode()
            output_file = cast(BinaryIO, keywords["stdout"])
            output_file.write(output_bytes)
            output_file.flush()
        return process

    monkeypatch.setattr(
        "security.solhint.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )
    return process, invocations


async def test_analyze_executes_solhint_with_json_and_trusted_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, invocations = _install_process(monkeypatch, output=[])

    findings = await SolhintAdapter().analyze(VALID_SOURCE, "Vault.sol")

    assert findings == []
    assert len(invocations) == 1
    invocation = invocations[0]
    assert invocation.arguments == (
        "solhint",
        "--formatter",
        "json",
        "--config",
        ".solhint.json",
        "--disc",
        "Vault.sol",
    )
    assert invocation.source == VALID_SOURCE
    assert invocation.config == {"extends": "solhint:recommended"}
    assert invocation.keywords["stdin"] is asyncio.subprocess.DEVNULL
    assert invocation.keywords["stdout"] is not asyncio.subprocess.DEVNULL
    assert invocation.keywords["stderr"] is asyncio.subprocess.DEVNULL
    environment = cast(Mapping[str, str], invocation.keywords["env"])
    assert environment["HOME"] == str(invocation.keywords["cwd"])
    assert set(environment) == {"HOME", "LANG", "LC_ALL", "PATH"}


async def test_analyze_accepts_exit_one_and_preserves_complete_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    message = _message(
        message="  Avoid using tx.origin.  ",
        filename="/private/temporary/Vault.sol",
        line=42,
        column=17,
    )
    _install_process(monkeypatch, output=_report(message), return_code=1)

    findings = await SolhintAdapter().analyze(VALID_SOURCE, "Vault.sol")

    assert findings == [
        AnalyzerFinding(
            analyzer="solhint",
            rule_id="avoid-tx-origin",
            title="Avoid Tx Origin",
            severity="high",
            description="Avoid using tx.origin.",
            location=SourceLocation(
                path="Vault.sol",
                start_line=42,
                end_line=42,
                start_column=17,
                end_column=17,
            ),
        )
    ]
    assert SolhintAdapter().name == "solhint"


async def test_analyze_preserves_every_message_and_skips_conclusion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_process(
        monkeypatch,
        output=_report(
            _message(rule_id="avoid-suicide", line=8),
            _message(rule_id="func-visibility", severity="Warning", line=14),
        ),
        return_code=1,
    )

    findings = await SolhintAdapter().analyze(VALID_SOURCE, "Vault.sol")

    assert [finding.rule_id for finding in findings] == [
        "avoid-suicide",
        "func-visibility",
    ]
    assert [finding.severity for finding in findings] == ["high", "medium"]


@pytest.mark.parametrize(
    ("solhint_severity", "normalized_severity"),
    [("Error", "high"), ("Warning", "medium"), ("error", "high")],
)
async def test_analyze_preserves_explicit_severity_mapping(
    monkeypatch: pytest.MonkeyPatch,
    solhint_severity: str,
    normalized_severity: str,
) -> None:
    _install_process(
        monkeypatch,
        output=_report(_message(severity=solhint_severity)),
    )

    findings = await SolhintAdapter().analyze(VALID_SOURCE, "Vault.sol")

    assert findings[0].severity == normalized_severity


def test_source_location_columns_are_backward_compatible() -> None:
    location = SourceLocation(path="Vault.sol", start_line=1, end_line=1)

    assert location.start_column is None
    assert location.end_column is None


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
    with pytest.raises(SolhintInputError):
        await SolhintAdapter().analyze(source, source_name)


async def test_analyze_enforces_utf8_source_size_limit() -> None:
    adapter = SolhintAdapter(SolhintAdapterConfig(max_source_bytes=3))

    with pytest.raises(SolhintInputError, match="size limit"):
        await adapter.analyze("éé", "Vault.sol")


def test_default_config_is_constructible() -> None:
    config = SolhintAdapterConfig()

    assert config.binary == "solhint"
    assert config.timeout_seconds == 60.0


@pytest.mark.parametrize(
    "factory",
    [
        lambda: SolhintAdapterConfig(binary=""),
        lambda: SolhintAdapterConfig(binary="bad\x00binary"),
        lambda: SolhintAdapterConfig(timeout_seconds=0),
        lambda: SolhintAdapterConfig(max_source_bytes=0),
        lambda: SolhintAdapterConfig(max_output_bytes=0),
    ],
)
def test_config_rejects_invalid_binary_and_non_positive_limits(
    factory: Callable[[], SolhintAdapterConfig],
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

    monkeypatch.setattr("security.solhint.asyncio.create_subprocess_exec", unavailable)

    with pytest.raises(SolhintUnavailableError, match="could not be started") as captured:
        await SolhintAdapter().analyze(VALID_SOURCE, "Vault.sol")

    assert "private executable path" not in str(captured.value)


async def test_analyze_rejects_unexpected_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_process(monkeypatch, return_code=255)

    with pytest.raises(SolhintExecutionError, match="execution failed"):
        await SolhintAdapter().analyze(VALID_SOURCE, "Vault.sol")


async def test_analyze_kills_process_after_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    process, _ = _install_process(monkeypatch, block_until_killed=True)
    adapter = SolhintAdapter(SolhintAdapterConfig(timeout_seconds=0.001))

    with pytest.raises(SolhintTimeoutError, match="configured timeout"):
        await adapter.analyze(VALID_SOURCE, "Vault.sol")

    assert process.killed is True


async def test_cancellation_kills_process(monkeypatch: pytest.MonkeyPatch) -> None:
    process, _ = _install_process(monkeypatch, block_until_killed=True)
    task = asyncio.create_task(SolhintAdapter().analyze(VALID_SOURCE, "Vault.sol"))
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
        ({"not": "an array"}, "root must be an array"),
    ],
)
async def test_analyze_rejects_empty_or_malformed_json(
    monkeypatch: pytest.MonkeyPatch,
    output: object | bytes | None,
    message: str,
) -> None:
    _install_process(monkeypatch, output=output)

    with pytest.raises(SolhintOutputError, match=message):
        await SolhintAdapter().analyze(VALID_SOURCE, "Vault.sol")


async def test_analyze_rejects_oversized_json_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_process(monkeypatch, output=b"1234")
    adapter = SolhintAdapter(SolhintAdapterConfig(max_output_bytes=3))

    with pytest.raises(SolhintOutputError, match="size limit"):
        await adapter.analyze(VALID_SOURCE, "Vault.sol")


@pytest.mark.parametrize(
    ("payload", "error_type", "message"),
    [
        (
            ["not-an-object"],
            SolhintOutputError,
            "report item must be an object",
        ),
        (
            _report(_message(rule_id=None)),
            SolhintExecutionError,
            "unsuccessful analysis",
        ),
        (
            _report(_message(rule_id="")),
            SolhintOutputError,
            "message.ruleId must be non-empty text",
        ),
        (
            _report(_message(severity="Info")),
            SolhintOutputError,
            "unsupported message severity",
        ),
        (
            _report(_message(message="")),
            SolhintOutputError,
            "message.message must be non-empty text",
        ),
        (
            _report(_message(filename="")),
            SolhintOutputError,
            "message.filePath must be non-empty text",
        ),
        (
            _report(_message(filename="Dependency.sol")),
            SolhintOutputError,
            "unexpected source filename",
        ),
        (
            _report(_message(line=0)),
            SolhintOutputError,
            "message.line must be a positive integer",
        ),
        (
            _report(_message(line=True)),
            SolhintOutputError,
            "message.line must be a positive integer",
        ),
        (
            _report(_message(column="1")),
            SolhintOutputError,
            "message.column must be a positive integer",
        ),
        (
            [
                {"conclusion": "one problem"},
                _message(),
            ],
            SolhintOutputError,
            "invalid conclusion record",
        ),
        (
            [{"conclusion": ""}],
            SolhintOutputError,
            "report conclusion must be non-empty text",
        ),
    ],
)
async def test_analyze_fails_closed_for_invalid_solhint_schema(
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
    error_type: type[SolhintExecutionError] | type[SolhintOutputError],
    message: str,
) -> None:
    _install_process(monkeypatch, output=payload)

    with pytest.raises(error_type, match=message):
        await SolhintAdapter().analyze(VALID_SOURCE, "Vault.sol")
