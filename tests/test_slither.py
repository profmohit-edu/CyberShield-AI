"""Comprehensive unit tests for the Slither security-engine adapter."""

import asyncio
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

from security.base import AnalyzerFinding, SourceLocation
from security.slither import (
    SlitherAdapter,
    SlitherAdapterConfig,
    SlitherExecutionError,
    SlitherInputError,
    SlitherOutputError,
    SlitherTimeoutError,
    SlitherUnavailableError,
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


def _detector(
    *,
    rule_id: str = "reentrancy-eth",
    impact: str = "High",
    description: str = "External call occurs before the state update.",
    lines: list[object] | None = None,
) -> dict[str, object]:
    detector: dict[str, object] = {
        "check": rule_id,
        "impact": impact,
        "confidence": "Medium",
        "description": description,
        "elements": [],
    }
    if lines is not None:
        detector["elements"] = [
            {
                "type": "function",
                "name": "withdraw",
                "source_mapping": {
                    "filename_absolute": "/temporary/private/Vault.sol",
                    "filename_relative": "Vault.sol",
                    "lines": lines,
                },
            }
        ]
    return detector


def _payload(detectors: list[object] | None = None) -> dict[str, object]:
    return {
        "success": True,
        "error": None,
        "results": {"detectors": detectors or []},
    }


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
        source_name = cast(str, arguments[1])
        output_name = cast(str, arguments[3])
        invocations.append(
            ProcessInvocation(
                arguments=arguments,
                keywords=dict(keywords),
                source=(workspace / source_name).read_text(encoding="utf-8"),
            )
        )
        if output is not None:
            output_bytes = output if isinstance(output, bytes) else json.dumps(output).encode()
            (workspace / output_name).write_bytes(output_bytes)
        return process

    monkeypatch.setattr(
        "security.slither.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )
    return process, invocations


async def test_analyze_executes_slither_with_json_file_and_restricted_streams(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, invocations = _install_process(monkeypatch, output=_payload())

    findings = await SlitherAdapter().analyze(VALID_SOURCE, "Vault.sol")

    assert findings == []
    assert len(invocations) == 1
    invocation = invocations[0]
    assert invocation.arguments == (
        "slither",
        "Vault.sol",
        "--json",
        "slither-results.json",
    )
    assert invocation.source == VALID_SOURCE
    assert invocation.keywords["stdin"] is asyncio.subprocess.DEVNULL
    assert invocation.keywords["stdout"] is asyncio.subprocess.DEVNULL
    assert invocation.keywords["stderr"] is asyncio.subprocess.DEVNULL
    environment = cast(Mapping[str, str], invocation.keywords["env"])
    assert environment["HOME"] == str(invocation.keywords["cwd"])
    assert set(environment) == {"HOME", "LANG", "LC_ALL", "PATH"}


async def test_analyze_normalizes_provenance_description_and_source_location(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detector = _detector(description="  Evidence from Slither.  ", lines=[44, 42, 43])
    _install_process(monkeypatch, output=_payload([detector]))

    findings = await SlitherAdapter().analyze(VALID_SOURCE, "UploadedVault.sol")

    assert findings == [
        AnalyzerFinding(
            analyzer="slither",
            rule_id="reentrancy-eth",
            title="Reentrancy Eth",
            severity="high",
            description="Evidence from Slither.",
            location=SourceLocation(
                path="UploadedVault.sol",
                start_line=42,
                end_line=44,
            ),
        )
    ]
    assert SlitherAdapter().name == "slither"


@pytest.mark.parametrize(
    ("impact", "expected_severity"),
    [
        ("Critical", "critical"),
        ("High", "high"),
        ("Medium", "medium"),
        ("Low", "low"),
        ("Informational", "informational"),
        ("Optimization", "informational"),
    ],
)
async def test_analyze_preserves_explicit_severity_mapping(
    monkeypatch: pytest.MonkeyPatch,
    impact: str,
    expected_severity: str,
) -> None:
    _install_process(monkeypatch, output=_payload([_detector(impact=impact)]))

    findings = await SlitherAdapter().analyze(VALID_SOURCE, "Vault.sol")

    assert findings[0].severity == expected_severity


async def test_analyze_allows_a_detector_without_source_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_process(monkeypatch, output=_payload([_detector()]))

    findings = await SlitherAdapter().analyze(VALID_SOURCE, "Vault.sol")

    assert findings[0].location is None


@pytest.mark.parametrize(
    ("source", "source_name"),
    [
        ("", "Vault.sol"),
        ("  \n", "Vault.sol"),
        (VALID_SOURCE, ""),
        (VALID_SOURCE, "."),
        (VALID_SOURCE, "../Vault.sol"),
        (VALID_SOURCE, "folder/Vault.sol"),
        (VALID_SOURCE, "folder\\Vault.sol"),
        (VALID_SOURCE, "Vault.txt"),
        (VALID_SOURCE, "Vault.sol\x00ignored"),
        (VALID_SOURCE, f"{'v' * 252}.sol"),
    ],
)
async def test_analyze_rejects_invalid_source_before_execution(
    source: str,
    source_name: str,
) -> None:
    with pytest.raises(SlitherInputError):
        await SlitherAdapter().analyze(source, source_name)


async def test_analyze_enforces_utf8_source_size_limit() -> None:
    adapter = SlitherAdapter(SlitherAdapterConfig(max_source_bytes=3))

    with pytest.raises(SlitherInputError, match="size limit"):
        await adapter.analyze("éé", "Vault.sol")


@pytest.mark.parametrize(
    "config",
    [
        SlitherAdapterConfig,
    ],
)
def test_default_config_is_constructible(config: type[SlitherAdapterConfig]) -> None:
    assert config().binary == "slither"


@pytest.mark.parametrize(
    "factory",
    [
        lambda: SlitherAdapterConfig(binary=""),
        lambda: SlitherAdapterConfig(binary="bad\x00binary"),
        lambda: SlitherAdapterConfig(timeout_seconds=0),
        lambda: SlitherAdapterConfig(max_source_bytes=0),
        lambda: SlitherAdapterConfig(max_output_bytes=0),
    ],
)
def test_config_rejects_non_positive_limits_and_invalid_binary(
    factory: Callable[[], SlitherAdapterConfig],
) -> None:
    with pytest.raises(ValueError):
        factory()


async def test_analyze_wraps_missing_executable_without_leaking_os_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def unavailable(*arguments: object, **keywords: object) -> FakeProcess:
        del arguments, keywords
        raise FileNotFoundError("private executable path")

    monkeypatch.setattr("security.slither.asyncio.create_subprocess_exec", unavailable)

    with pytest.raises(SlitherUnavailableError, match="could not be started") as captured:
        await SlitherAdapter().analyze(VALID_SOURCE, "Vault.sol")

    assert "private executable path" not in str(captured.value)


async def test_analyze_raises_safe_error_for_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_process(monkeypatch, return_code=2)

    with pytest.raises(SlitherExecutionError, match="execution failed"):
        await SlitherAdapter().analyze(VALID_SOURCE, "Vault.sol")


async def test_analyze_kills_process_after_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    process, _ = _install_process(monkeypatch, block_until_killed=True)
    adapter = SlitherAdapter(SlitherAdapterConfig(timeout_seconds=0.001))

    with pytest.raises(SlitherTimeoutError, match="configured timeout"):
        await adapter.analyze(VALID_SOURCE, "Vault.sol")

    assert process.killed is True


@pytest.mark.parametrize(
    ("output", "message"),
    [
        (None, "did not produce"),
        (b"", "empty JSON"),
        (b"not-json", "invalid JSON"),
        (["not", "an", "object"], "root must be an object"),
    ],
)
async def test_analyze_rejects_missing_or_invalid_json_output(
    monkeypatch: pytest.MonkeyPatch,
    output: object | bytes | None,
    message: str,
) -> None:
    _install_process(monkeypatch, output=output)

    with pytest.raises(SlitherOutputError, match=message):
        await SlitherAdapter().analyze(VALID_SOURCE, "Vault.sol")


async def test_analyze_rejects_oversized_json_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_process(monkeypatch, output=b"1234")
    adapter = SlitherAdapter(SlitherAdapterConfig(max_output_bytes=3))

    with pytest.raises(SlitherOutputError, match="size limit"):
        await adapter.analyze(VALID_SOURCE, "Vault.sol")


@pytest.mark.parametrize(
    ("payload", "error_type", "message"),
    [
        ({"success": False}, SlitherExecutionError, "unsuccessful analysis"),
        (
            {"success": True, "results": []},
            SlitherOutputError,
            "results must be an object",
        ),
        (
            {"success": True, "results": {"detectors": {}}},
            SlitherOutputError,
            "results.detectors must be an array",
        ),
        (
            _payload([_detector(impact="Unknown")]),
            SlitherOutputError,
            "unsupported detector impact",
        ),
        (
            _payload([_detector(lines=[42, True])]),
            SlitherOutputError,
            "invalid source line",
        ),
        (
            _payload([_detector(rule_id="")]),
            SlitherOutputError,
            "detector.check must be non-empty text",
        ),
    ],
)
async def test_analyze_fails_closed_for_invalid_slither_schema(
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
    error_type: type[SlitherExecutionError] | type[SlitherOutputError],
    message: str,
) -> None:
    _install_process(monkeypatch, output=payload)

    with pytest.raises(error_type, match=message):
        await SlitherAdapter().analyze(VALID_SOURCE, "Vault.sol")
