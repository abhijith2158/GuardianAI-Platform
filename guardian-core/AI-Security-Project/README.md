# Live AI Security Operations Center (SOC) — Local Llama + Ollama + Streamlit

This project is a **laptop-scale SOC demo** that tails a `security.log` file in real time, performs **SOC-grade** triage with a **local Llama model via Ollama**, and sends **Telegram alerts** only when a **patterned attack** is detected (not a single typo).

It is designed for a student project / viva review: readable architecture, deterministic safeguards (heuristics + batching), and an audit trail (`alerts_history.csv`).

---

## What’s included

- **`live_monitor.py`**: Live SOC dashboard that watches `security.log`, batches suspicious events per IP, runs LLM classification, and sends Telegram alerts for `CONFIRMED_THREAT`.
- **`app.py`**: Offline “upload logs and scan” UI using the *same* detection engine (can run without Telegram).
- **`soc_engine.py`**: Shared engine:
  - `TailReader` (tell/seek based tailing)
  - heuristics (`suspicion_score`)
  - batching prompt (`ai_classify_batched`)
  - verdict/severity parsing
  - CSV audit export (`alerts_history.csv`)

---

## Setup

### 1) Create and activate a virtual environment (recommended)

```bash
python -m venv venv
.\venv\Scripts\activate
```

### 2) Install dependencies

Install the Python packages used by the dashboards:

```bash
pip install streamlit watchdog requests ollama
```

> If you already have a working environment, you can skip this.

---

## Configure Telegram (required for live SOC)

### Option A (recommended): Streamlit secrets

Create `.streamlit/secrets.toml`:

```toml
TELEGRAM_TOKEN = "123456:ABC..."
TELEGRAM_CHAT_ID = "123456789"
```

### Option B: `.env`

Create `.env` in the project root:

```env
TELEGRAM_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=123456789
```

### Offline mode

- `app.py` **does not require** Telegram credentials (it will show a warning and continue).
- `live_monitor.py` **requires** Telegram credentials (it will show an error and stop), because it’s meant for real-time defense.

---

## Start Ollama (local Llama)

1) Install Ollama from the official website.
2) Pull the model you want (default used by the UI is `llama3.2`):

```bash
ollama pull llama3.2
```

3) Ensure Ollama is running (it typically runs as a background service).

If you want to use a different model name, set it in the UI or via:

```bash
set OLLAMA_MODEL=llama3.2
```

---

## Run the SOC dashboards

### Live SOC (real-time tail of `security.log`)

```bash
streamlit run live_monitor.py
```

- Watches `security.log` in the project folder.
- Maintains a **Live Feed**.
- Batches suspicious lines per IP and sends Telegram alerts only for confirmed attacks.
- Writes audit rows to `alerts_history.csv`.

### Offline scan (upload a log file)

```bash
streamlit run app.py
```

- Upload `.log` or `.txt`
- Scans via the same engine + batching
- Writes `CONFIRMED_THREAT` rows to `alerts_history.csv`
- Shows a small analytics view of the CSV

---

## How “Human Error vs Attack” works (reviewer-friendly)

This system uses a **two-stage design** to stay reliable on a laptop GPU and avoid false alarms:

### Stage 1: Heuristic scoring (cheap, deterministic)

Each new log line is assigned a **Suspicion Score** based on keywords such as:
- auth signals: `failed login`, `denied`, `unauthorized`
- high-risk signals: `sql injection`, `xss`, `rce`, `cve-`, `webshell`, `payload`
- indicators: an IP address in the line

Only if the score crosses a configurable threshold does the line get buffered for model analysis. This avoids calling the LLM on every noisy event.

### Stage 2: Pattern + batching (attack detection)

Instead of analyzing single lines, events are **batched per IP**:
- For authentication events, the engine tracks **failures per IP/user in a sliding time window**.
- When failures cross a threshold (e.g., \( \ge 6 \) failures within 60 seconds), it flushes a batch to the LLM and asks for a single summarized report.

This allows the classifier to distinguish:
- **HUMAN_ERROR**: 1–2 sporadic failures, irregular timing
- **CONFIRMED_THREAT**: many attempts in a tight window, repeated patterns, automation-like timing
- **SUSPICIOUS**: unclear / needs monitoring, but not a phone alert

### Time-interval awareness

The LLM prompt explicitly instructs it to check the **time interval between events in the batch** to separate:
- fast + regular attempts ⇒ likely bot/automation
- slow + irregular attempts ⇒ likely human typo

---

## Reporting / Audit Trail

Every `CONFIRMED_THREAT` is appended to:

- **`alerts_history.csv`**

Columns:
- `timestamp`
- `ip`
- `verdict`
- `severity` (1–10 if provided by the model)

Both dashboards include a small **Analytics** section that visualizes:
- Threats by IP
- Severity distribution

---

## Notes / Tips

- If you edit `security.log` with a tool that rewrites the file, the tailer handles truncation safely and keeps reading new appended lines.
- On Windows, firewall blocking requires **Administrator privileges**. The UI reports permission errors without crashing.

