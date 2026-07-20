# CyberShield AI

CyberShield AI is an open-source platform for explainable Solidity smart-contract security analysis. It coordinates established security tools, correlates their findings, and presents evidence for human review. The platform is intended to support security assessment; it does not replace an independent audit or authorize deployment.

## Project status

CyberShield AI has completed Phase 8. The platform includes isolated Slither, Mythril, and Solhint adapters, concurrent orchestration, deterministic consensus correlation, a production REST API, and pure JSON, HTML, Markdown, SARIF 2.1.0, and PDF report generation.

## Core principles

- Analyzer evidence remains traceable to its source tool and contract location.
- Cross-tool agreement is recorded but is not treated as proof of correctness.
- AI-generated explanations and code recommendations are advisory.
- Developers retain responsibility for remediation and deployment decisions.
- Untrusted contracts are processed by isolated security-engine workers.
- Components use typed interfaces so implementations can be tested and replaced independently.

## Architecture

The implementation follows the CyberShield AI reference architecture without introducing alternative components.

1. A developer submits a Solidity contract.
2. The Security Orchestrator validates the request and invokes analyzers.
3. Slither, Mythril, and Solhint produce tool-specific findings.
4. The Consensus Engine normalizes findings and records cross-tool agreement.
5. The Report Builder exports the complete evidence graph as JSON, HTML, Markdown, SARIF 2.1.0, or PDF.
6. AI Security Reasoning is reserved for a future provider abstraction supporting OpenAI or Gemini.
7. The interactive dashboard and deployment readiness workflows remain future milestones.

## Technology stack

- Runtime: Python 3.12
- Operating system: Ubuntu 24.04
- Backend: FastAPI
- Server-side frontend: Jinja2
- Progressive interaction: HTMX
- Client assets: HTML, CSS, and JavaScript
- Security engines: Slither, Mythril, and Solhint
- Application server: Uvicorn
- Reporting: Jinja2 and ReportLab
- Packaging and deployment: Docker and Docker Compose
- Testing: pytest

PostgreSQL, GitHub Actions, and OpenAI/Gemini integrations are planned capabilities and are not part of the current phase.

## Repository structure

```text
CyberShield-AI/
├── backend/          # FastAPI application and HTTP interface
├── frontend/         # Frontend source modules
├── templates/        # Jinja2 templates
├── static/           # CSS, JavaScript, icons, and generated assets
├── security/         # Security-engine adapters and finding normalization
├── models/           # Typed domain and transport models
├── services/         # Application use cases and orchestration services
├── reports/          # Pure multi-format security report generation
├── examples/reports/ # Generated sample reports and screenshots
├── utils/            # Shared infrastructure utilities
├── tests/            # Unit and integration tests
├── .env.example      # Documented environment variables
├── .gitignore        # Repository exclusions
├── Dockerfile        # Ubuntu 24.04 application image
├── docker-compose.yml
├── requirements.txt  # Reproducible Python dependencies
└── README.md
```

## Local requirements

Install the following before running the platform outside Docker:

- Python 3.12
- Node.js and npm for Solhint
- A supported Solidity compiler
- Slither
- Mythril
- Solhint

Security-engine versions will be pinned by the project dependency and container definitions. Do not rely on globally installed unpinned versions in production.

## Initial setup

Create and activate an isolated Python environment:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Create the local environment file:

```bash
cp .env.example .env
```

Environment files may contain secrets and must not be committed.

## Run locally

Start the FastAPI development server:

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

The application will be available at `http://127.0.0.1:8000`.

Operational and discovery endpoints:

- `GET /health` — dependency-free liveness check
- `GET /version` — deployed application version
- `POST /analyze` — multipart Solidity analysis pipeline
- `GET /api/v1/status` — implementation phase and capability inventory
- `GET /docs` — interactive OpenAPI documentation in development

## Run with Docker

Build and start the service:

```bash
docker compose up --build
```

Stop the service:

```bash
docker compose down
```

The container configuration uses Ubuntu 24.04 and Python 3.12. Analyzer execution will be isolated from the web process as the security-worker services are introduced.

## Testing

Run the test suite from the repository root:

```bash
pytest
```

Run tests with coverage reporting:

```bash
pytest --cov=. --cov-report=term-missing
```

Tests must not require external AI services or network access. Security-engine adapters must support deterministic test doubles.

## Logging and error handling

Application modules use structured logging and must not log contract source code, credentials, tokens, or private repository data. Exceptions are translated at system boundaries into stable application errors; internal stack traces remain in protected logs and are not returned to clients.

## Security considerations

- Treat every submitted contract and repository as untrusted input.
- Enforce input-size, file-type, process-time, memory, and output limits.
- Run analyzers without host privileges or access to application secrets.
- Validate analyzer output before converting it into domain models.
- Escape user-controlled content in templates and browser responses.
- Keep AI-provider credentials server-side when future integrations are enabled.
- Require human review before accepting remediation or deployment readiness decisions.

## Compatibility policy

Public HTTP routes, domain models, analyzer result schemas, template context keys, and environment-variable names are compatibility-sensitive. Changes must remain backward compatible within a major release. Deprecations require documentation, tests, and a supported migration period.

## Contributing

Contributions should be focused, typed, documented, and covered by tests. Run formatting, static analysis, and the complete test suite before submitting a change. Security findings should be reported privately to the maintainers rather than disclosed in a public issue.

## Scope limitations

CyberShield AI cannot prove that a smart contract is secure. Static analysis, symbolic execution, linting, and AI-assisted reasoning each have coverage limitations. A readiness assessment summarizes available evidence and unresolved findings; it is not a certification, warranty, or substitute for expert review.
