"""REST API tests with injected analyzer test doubles."""

from collections.abc import Sequence

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from backend.dependencies import get_api_settings
from backend.main import create_app
from security.base import AnalyzerFinding, Severity, SourceLocation
from services.consensus import ConsensusEngine, ConsensusReport
from services.orchestrator import AnalysisResult, SecurityOrchestrator
from utils.config import Settings

_SOURCE = b"pragma solidity ^0.8.20; contract Vault {}\n"


class StubAnalyzer:
    """Controllable analyzer implementing the production protocol."""

    def __init__(
        self,
        name: str,
        findings: Sequence[AnalyzerFinding] = (),
        failure: Exception | None = None,
    ) -> None:
        self._name = name
        self._findings = tuple(findings)
        self._failure = failure
        self.calls: list[tuple[str, str]] = []

    @property
    def name(self) -> str:
        return self._name

    async def analyze(self, source: str, source_name: str) -> list[AnalyzerFinding]:
        self.calls.append((source, source_name))
        if self._failure is not None:
            raise self._failure
        return list(self._findings)


class BrokenConsensusEngine(ConsensusEngine):
    """Test double for an unexpected pipeline-layer failure."""

    def build_report(self, analysis: AnalysisResult) -> ConsensusReport:
        raise RuntimeError("private implementation secret")


def _finding(
    analyzer: str,
    *,
    severity: Severity = "high",
    line: int = 12,
) -> AnalyzerFinding:
    return AnalyzerFinding(
        analyzer=analyzer,
        rule_id="SWC-107",
        title="Reentrancy",
        severity=severity,
        description=f"{analyzer} detected an external-call reentrancy risk",
        location=SourceLocation(
            path="Vault.sol",
            start_line=line,
            end_line=line,
            start_column=5,
            end_column=18,
        ),
    )


def _app(
    analyzers: Sequence[StubAnalyzer] | None = None,
    *,
    max_bytes: int = 1_000_000,
    consensus_engine: ConsensusEngine | None = None,
) -> FastAPI:
    configured = list(analyzers or [StubAnalyzer("slither")])
    return create_app(
        settings=Settings(max_contract_bytes=max_bytes),
        orchestrator=SecurityOrchestrator(configured),
        consensus_engine=consensus_engine,
    )


def _client(application: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=application), base_url="http://test")


async def test_version_and_health_routes() -> None:
    application = _app()
    async with _client(application) as client:
        health = await client.get("/health")
        version = await client.get("/version")

    assert health.status_code == 200
    assert health.json() == {"status": "ok", "version": "0.1.0"}
    assert version.status_code == 200
    assert version.json() == {"name": "CyberShield AI", "version": "0.1.0"}


async def test_analyze_returns_full_orchestrator_and_consensus_evidence() -> None:
    slither = StubAnalyzer("slither", [_finding("slither", severity="high")])
    mythril = StubAnalyzer("mythril", [_finding("mythril", severity="medium", line=13)])
    solhint = StubAnalyzer("solhint")
    application = _app([slither, mythril, solhint])

    multipart: list[tuple[str, tuple[str | None, bytes | str, str | None]]] = [
        ("contract", ("Vault.sol", _SOURCE, "text/plain")),
        ("enabled_analyzers", (None, "slither,mythril", None)),
        ("enabled_analyzers", (None, "mythril", None)),
    ]
    async with _client(application) as client:
        response = await client.post("/analyze", files=multipart)

    assert response.status_code == 200
    payload = response.json()
    assert payload["execution"]["filename"] == "Vault.sol"
    assert payload["execution"]["source_size_bytes"] == len(_SOURCE)
    assert payload["execution"]["enabled_analyzers"] == ["slither", "mythril"]
    assert payload["execution"]["execution_time_ms"] >= 0
    assert [item["status"] for item in payload["orchestrator"]["analyzers"]] == [
        "succeeded",
        "succeeded",
        "disabled",
    ]
    assert len(payload["orchestrator"]["findings"]) == 2
    canonical = payload["consensus"]["findings"][0]
    assert canonical["severity"] == "high"
    assert canonical["confidence_score"] == 0.7083
    assert canonical["contributing_analyzers"] == ["mythril", "slither"]
    assert [item["analyzer"] for item in canonical["supporting_findings"]] == [
        "mythril",
        "slither",
    ]
    assert canonical["location"] == {
        "path": "Vault.sol",
        "start_line": 12,
        "end_line": 13,
        "start_column": 5,
        "end_column": 18,
    }
    assert len(slither.calls) == len(mythril.calls) == 1
    assert solhint.calls == []


async def test_default_selection_runs_every_injected_analyzer_and_strips_utf8_bom() -> None:
    slither = StubAnalyzer("slither")
    mythril = StubAnalyzer("mythril")
    application = _app([slither, mythril])

    async with _client(application) as client:
        response = await client.post(
            "/analyze",
            files={"contract": ("Vault.SOL", b"\xef\xbb\xbf" + _SOURCE, "text/plain")},
        )

    assert response.status_code == 200
    assert response.json()["execution"]["enabled_analyzers"] is None
    assert slither.calls == [(_SOURCE.decode(), "Vault.SOL")]
    assert mythril.calls == [(_SOURCE.decode(), "Vault.SOL")]


async def test_analyzer_failure_is_sanitized_and_does_not_abort_request() -> None:
    failed = StubAnalyzer("slither", failure=RuntimeError("binary path and secret token"))
    healthy = StubAnalyzer("mythril", [_finding("mythril")])
    application = _app([failed, healthy])

    async with _client(application) as client:
        response = await client.post(
            "/analyze",
            files={"contract": ("Vault.sol", _SOURCE, "text/plain")},
        )

    assert response.status_code == 200
    body = response.text
    assert "secret token" not in body
    metadata = response.json()["orchestrator"]["analyzers"]
    assert metadata[0]["status"] == "failed"
    assert metadata[0]["error"] == {
        "error_type": "RuntimeError",
        "message": "Analyzer execution failed",
    }
    assert metadata[1]["status"] == "succeeded"
    assert response.json()["consensus"]["source_finding_count"] == 1


async def test_findings_without_source_locations_remain_supported_and_explicit() -> None:
    finding = AnalyzerFinding(
        analyzer="slither",
        rule_id="informational-rule",
        title="Compiler pragma",
        severity="informational",
        description="No precise source mapping was reported",
    )
    application = _app([StubAnalyzer("slither", [finding])])

    async with _client(application) as client:
        response = await client.post(
            "/analyze",
            files={"contract": ("Vault.sol", _SOURCE, "text/plain")},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["orchestrator"]["findings"][0]["location"] is None
    assert payload["consensus"]["findings"][0]["location"] is None
    assert payload["consensus"]["findings"][0]["supporting_findings"] == [
        payload["orchestrator"]["findings"][0]
    ]


@pytest.mark.parametrize(
    ("filename", "content", "expected_status", "expected_code"),
    [
        ("Vault.txt", _SOURCE, 415, "unsupported_file_type"),
        ("../Vault.sol", _SOURCE, 422, "invalid_filename"),
        (" Vault.sol", _SOURCE, 422, "invalid_filename"),
        ("x" * 252 + ".sol", _SOURCE, 422, "invalid_filename"),
        ("Vault.sol", b"", 422, "empty_contract"),
        ("Vault.sol", b" \n\t", 422, "empty_contract"),
        ("Vault.sol", b"\xff\xfe", 422, "invalid_source_encoding"),
        ("Vault.sol", b"contract X {\x00}", 422, "invalid_solidity_source"),
    ],
)
async def test_invalid_uploads_return_structured_errors(
    filename: str,
    content: bytes,
    expected_status: int,
    expected_code: str,
) -> None:
    analyzer = StubAnalyzer("slither")
    application = _app([analyzer])

    async with _client(application) as client:
        response = await client.post(
            "/analyze",
            files={"contract": (filename, content, "application/octet-stream")},
        )

    assert response.status_code == expected_status
    assert response.json()["error"]["code"] == expected_code
    assert response.json()["error"]["field"] == "contract"
    assert analyzer.calls == []


async def test_upload_size_limit_accepts_boundary_and_rejects_next_byte() -> None:
    analyzer = StubAnalyzer("slither")
    application = _app([analyzer], max_bytes=len(_SOURCE))

    async with _client(application) as client:
        accepted = await client.post(
            "/analyze",
            files={"contract": ("Vault.sol", _SOURCE, "text/plain")},
        )
        rejected = await client.post(
            "/analyze",
            files={"contract": ("Vault.sol", _SOURCE + b"x", "text/plain")},
        )

    assert accepted.status_code == 200
    assert rejected.status_code == 413
    assert rejected.json()["error"] == {
        "code": "contract_too_large",
        "message": f"The uploaded contract exceeds the {len(_SOURCE)}-byte limit",
        "field": "contract",
        "issues": [],
    }
    assert len(analyzer.calls) == 1


async def test_missing_contract_uses_structured_request_validation_error() -> None:
    application = _app()

    async with _client(application) as client:
        response = await client.post("/analyze")

    assert response.status_code == 422
    payload = response.json()
    assert payload["error"]["code"] == "request_validation_error"
    assert payload["error"]["issues"] == [
        {"field": "contract", "message": "Field required", "error_type": "missing"}
    ]


@pytest.mark.parametrize("selection", ["unknown", "slither,"])
async def test_invalid_analyzer_selection_is_structured(selection: str) -> None:
    application = _app([StubAnalyzer("slither")])

    async with _client(application) as client:
        response = await client.post(
            "/analyze",
            data={"enabled_analyzers": selection},
            files={"contract": ("Vault.sol", _SOURCE, "text/plain")},
        )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_analyzer_selection"
    assert response.json()["error"]["field"] == "enabled_analyzers"


async def test_unexpected_pipeline_error_never_exposes_internal_exception() -> None:
    application = _app(
        [StubAnalyzer("slither")],
        consensus_engine=BrokenConsensusEngine(),
    )

    async with _client(application) as client:
        response = await client.post(
            "/analyze",
            files={"contract": ("Vault.sol", _SOURCE, "text/plain")},
        )

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "analysis_failed",
            "message": "The analysis pipeline could not complete",
            "field": None,
            "issues": [],
        }
    }
    assert "private implementation secret" not in response.text
    assert "traceback" not in response.text.casefold()


async def test_global_error_boundary_returns_only_a_generic_envelope() -> None:
    application = _app()

    async def broken_settings() -> Settings:
        raise RuntimeError("secret dependency details")

    application.dependency_overrides[get_api_settings] = broken_settings
    transport = ASGITransport(app=application, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/version")

    assert response.status_code == 500
    assert response.json()["error"] == {
        "code": "internal_server_error",
        "message": "The server could not complete the request",
        "field": None,
        "issues": [],
    }
    assert "secret dependency details" not in response.text


async def test_application_lifespan_configures_runtime_resources() -> None:
    application = _app()

    async with application.router.lifespan_context(application):
        assert application.state.settings.environment == "development"


def test_openapi_documents_routes_multipart_and_error_contracts() -> None:
    schema = _app().openapi()

    assert schema["info"]["title"] == "CyberShield AI"
    assert schema["info"]["version"] == "0.1.0"
    assert {"/health", "/version", "/analyze"}.issubset(schema["paths"])
    operation = schema["paths"]["/analyze"]["post"]
    assert operation["operationId"] == "analyze_contract"
    multipart_schema = operation["requestBody"]["content"]["multipart/form-data"]["schema"]
    assert "$ref" in multipart_schema
    assert {"200", "413", "415", "422", "500"}.issubset(operation["responses"])
    assert "AnalysisResponse" in schema["components"]["schemas"]
    assert "ErrorResponse" in schema["components"]["schemas"]
