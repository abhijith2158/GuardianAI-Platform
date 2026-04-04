# GuardianAI

GuardianAI is a developer-first application security platform for teams that want runtime protection, centralized telemetry, and local code auditing without turning day-to-day development into a compliance project.

## What is GuardianAI?

GuardianAI combines three release-ready surfaces:

- A FastAPI ingestor that receives security telemetry, stores it in PostgreSQL/Supabase, and serves a tenant-scoped live dashboard.
- Runtime SDKs for Python and Node.js that detect suspicious behavior inside real applications and forward events to the central command layer.
- A local audit tool that performs rule-first static analysis, supports custom regex rules from `guardian_rules.yaml`, and can optionally append AI remediation advice when Ollama is available on `localhost:11434`.

The platform is designed so the essential protection path works locally and in CI even when optional AI services are offline.

## Core Features

- Multi-tenant telemetry ingestion with developer API keys stored in a `developers` table.
- Tenant-isolated event views in `/v1/events` and `/dashboard`.
- Pooled PostgreSQL access with health probing via `GET /health`.
- Local-first security audit reporting in Markdown, CLI text, and PDF formats.
- Optional Ollama-powered remediation addendum for richer guidance.
- Python and Node middleware for lightweight runtime application self-protection.
- Git hook and CI integration for pre-release security checks.

## Quick Start for Developers

1. Install the Python package and project dependencies.

```bash
pip install -e .
```

2. Configure GuardianAI for Supabase/PostgreSQL.

```powershell
$env:SUPABASE_DB_URL="postgresql://USER:PASSWORD@HOST:5432/postgres"
$env:GUARDIAN_MASTER_API_KEY="set-a-real-admin-key"
$env:GUARDIAN_POLICY_MODE="block"
$env:GUARDIAN_POLICY_ENABLED="1"
```

3. Start the ingestor.

```bash
python -m uvicorn guardian_api:app --host 127.0.0.1 --port 8000
```

4. Register a developer so they receive a tenant-specific API key.

Every SDK client and dashboard user must exist in the `developers` table first. The recommended path is the admin registration endpoint, which uses `GUARDIAN_MASTER_API_KEY`.

```bash
curl -X POST http://127.0.0.1:8000/v1/register \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: set-a-real-admin-key" \
  -d "{\"email\":\"developer@example.com\"}"
```

This returns the developer-specific `api_key` that should be used by the SDK and dashboard for that tenant.

5. Open the dashboard with a developer API key in the URL.

```text
http://127.0.0.1:8000/dashboard?api_key=developer-api-key
```

The dashboard starts with a `Waking up server...` status to handle cold starts gracefully and refreshes every 10 seconds to stay within free-tier hosting limits.

## How to Integrate the SDK

### Python SDK

```python
from guardian_sdk import enable

enable(service_name="payments-api", mode="block")
```

Environment variables:

- `GUARDIAN_API_KEY`: developer API key provisioned in the `developers` table.
- `GUARDIAN_INGEST_URL`: the GuardianAI base URL or full telemetry URL, such as `http://127.0.0.1:8000/` or `http://127.0.0.1:8000/v1/telemetry`
- `GUARDIAN_MODE`: `monitor` or `block`
- `GUARDIAN_ENV`: deployment environment label

The SDK normalizes `GUARDIAN_INGEST_URL` automatically. For example, `https://api.com/` becomes `https://api.com/v1/telemetry`.

### Node.js SDK

```js
const express = require("express");
const guardian = require("@ark/guardian-sdk");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(guardian.enable({ serviceName: "orders-api", mode: "block" }));
```

The Node SDK honors the same ingest URL and API key environment variables and also expands base URLs to `/v1/telemetry` automatically.

## The Local Audit Tool

Run the release audit against any project path:

```bash
python security_audit.py .
```

Outputs:

- Markdown roadmap in `reports/`
- CLI-friendly text report in `reports/`
- PDF report in `reports/`

GuardianAI is rule-first by default:

- AST and regex analysis run locally with no Ollama dependency.
- `guardian_rules.yaml` can define custom regex checks for team-specific coverage.
- If Ollama is reachable at `localhost:11434`, GuardianAI appends an AI mentor remediation section.
- If Ollama is not running, the audit still completes normally and produces professional local-only reports.

Example custom rules file:

```yaml
rules:
  - id: CUSTOM.HARDCODED_SECRET
    message: Potential hardcoded secret token detected.
    pattern: "(?i)(api[_-]?key|secret|token)\\s*[:=]\\s*['\\\"][A-Za-z0-9_\\-]{12,}['\\\"]"
    severity: 7
    file_extensions:
      - ".py"
      - ".js"
```

### Git Hook and CI

- Local pre-commit template runs `python security_audit.py . --ci`
- CI workflow uploads the generated roadmap artifacts
- For intentional local testing, Git still supports `git commit --no-verify`

### Ollama Note

Ollama is optional. GuardianAI does not require it for scanning, reporting, CI gates, or PDF generation. It is only used to append advanced remediation guidance when available.
