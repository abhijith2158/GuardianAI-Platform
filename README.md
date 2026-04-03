# GuardianAI Platform

GuardianAI is an AI-first DevSecOps platform with:

- `guardian-sdk-node/`: Node.js RASP middleware and CLI
- `guardian_sdk/`: Python RASP SDK and CLI
- `guardian_api.py`: centralized FastAPI ingestor and live dashboard
- `scanner.py`: static analysis prototype
- `advisor.py`: remediation roadmap generator

## Installation

### Published SDKs

```bash
npm install @ark/guardian-sdk
npx guardian-cli init
```

```bash
pip install guardian-sdk-python
guardian-cli-py --mode monitor
```

### Repo Development Setup

```bash
pip install -e .
cd guardian-sdk-node
npm install
```

## Central Ingestor Setup

The centralized ingestor uses PostgreSQL via `DATABASE_URL`.

Required environment variables:

- `DATABASE_URL` = PostgreSQL connection string for Supabase or another Postgres host
- `GUARDIAN_API_KEY` = shared API key used by SDKs and the API
- `GUARDIAN_POLICY_MODE` = optional global remote mode override, default `block`
- `GUARDIAN_POLICY_ENABLED` = optional global enable switch, default `1`
- `GUARDIAN_SERVICE_POLICIES` = optional JSON map for per-service policies

Example PowerShell setup:

```powershell
$env:DATABASE_URL="postgresql://USER:PASSWORD@HOST:5432/DBNAME"
$env:GUARDIAN_API_KEY="guardian-dev-key"
$env:GUARDIAN_POLICY_MODE="block"
python -m uvicorn guardian_api:app --host 127.0.0.1 --port 8000
```

## Live Dashboard

The dashboard and events API are protected with the same API key used for ingestion.

Open the dashboard with the API key in the URL query string:

```text
http://127.0.0.1:8000/dashboard?api_key=guardian-dev-key
```

The dashboard polls the live feed every 2 seconds.

## SDK Setup

### Node.js SDK

```bash
npm install @ark/guardian-sdk
npx guardian-cli init
```

```js
const express = require("express");
const guardian = require("@ark/guardian-sdk");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(guardian.enable({ serviceName: "my-service", mode: "block" }));
```

### Python SDK

```python
from guardian_sdk import enable

enable(service_name="my-python-service", mode="block")
```

## Remote Policy and Telemetry

Before starting a protected app, configure:

```powershell
$env:GUARDIAN_API_KEY="guardian-dev-key"
$env:GUARDIAN_INGEST_URL="http://127.0.0.1:8000/v1/telemetry"
$env:GUARDIAN_MODE="monitor"
```

Then start your app normally. On startup, the SDK will:

1. Check in with `/v1/policy`
2. Apply remote `mode` / `enabled` overrides if available
3. Continue logging locally to `security.log`
4. Dual-write telemetry to the central ingestor when `GUARDIAN_INGEST_URL` is set

## Scanner Quick Start

```bash
python scanner.py .
```
