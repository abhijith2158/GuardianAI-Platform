import os
import time
import queue
import re
import subprocess
from collections import defaultdict, deque
from datetime import datetime
from typing import Deque, Dict, List, Optional, Tuple

import requests
import streamlit as st
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from soc_engine import (
    LogEvent,
    TailReader,
    ai_classify_batched,
    append_alert_history_csv,
    load_required_secrets,
    read_alerts_history,
    parse_ai_verdict_and_severity,
    parse_failed_login,
    suspicion_score,
    trim_deque,
)

# --- 1. SETTINGS ---
LOG_FILE_NAME = "security.log"

# Secrets are required and must come from secrets.toml / .env / env vars.
TELEGRAM_TOKEN, TELEGRAM_CHAT_ID = load_required_secrets()

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
ALERTS_CSV_PATH = os.getenv("SOC_ALERTS_CSV", "alerts_history.csv")

# Default heuristics (tweak in sidebar)
DEFAULT_WINDOW_SECONDS = int(os.getenv("SOC_WINDOW_SECONDS", "60"))
DEFAULT_FAIL_THRESHOLD = int(os.getenv("SOC_FAIL_THRESHOLD", "6"))
DEFAULT_ALERT_COOLDOWN_SECONDS = int(os.getenv("SOC_ALERT_COOLDOWN_SECONDS", "180"))
DEFAULT_SCORE_THRESHOLD = int(os.getenv("SOC_SCORE_THRESHOLD", "4"))
DEFAULT_BATCH_WAIT_SECONDS = float(os.getenv("SOC_BATCH_WAIT_SECONDS", "2.0"))
DEFAULT_MAX_BATCH_LINES = int(os.getenv("SOC_MAX_BATCH_LINES", "25"))
DEFAULT_MAX_MODEL_CALLS_PER_REFRESH = int(os.getenv("SOC_MAX_MODEL_CALLS_PER_REFRESH", "2"))

# --- 2. CORE UTILITIES ---
@st.cache_resource
def get_shared_queue():
    return queue.Queue()

shared_queue = get_shared_queue()

def send_telegram(msg: str, *, token: str, chat_id: str, timeout_s: int = 10) -> Tuple[bool, str]:
    if not token or not chat_id:
        return False, "Telegram token/chat_id not configured."

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": msg, "disable_web_page_preview": True}
    try:
        r = requests.post(url, json=payload, timeout=timeout_s)
    except requests.RequestException as e:
        return False, f"Telegram request failed: {e}"

    try:
        data = r.json()
    except ValueError:
        data = None

    if r.status_code != 200:
        detail = ""
        if isinstance(data, dict):
            detail = data.get("description") or data.get("error_code") or ""
        return False, f"Telegram HTTP {r.status_code}. {detail}".strip()

    if isinstance(data, dict) and data.get("ok") is True:
        return True, "OK"

    detail = ""
    if isinstance(data, dict):
        detail = data.get("description") or ""
    return False, f"Telegram unexpected response. {detail}".strip()


def block_ip_windows(ip: str) -> Tuple[bool, str]:
    rule_name = f"Block_Suspicious_{ip}"
    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        return True, f"Firewall rule added: {rule_name}"
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        stdout = (e.stdout or "").strip()
        detail = stderr or stdout or str(e)
        return False, f"Firewall command failed. {detail} (Try running as Admin.)"
    except Exception as e:
        return False, f"Firewall error: {e}"


@st.cache_resource
def get_tail_reader() -> TailReader:
    return TailReader(LOG_FILE_NAME, start_at_end=True)

# --- 3. THE SMART WATCHER ---
class LogHandler(FileSystemEventHandler):
    def __init__(self, tailer: TailReader):
        super().__init__()
        self.tailer = tailer

    def on_modified(self, event):
        if event.is_directory:
            return
        if os.path.abspath(event.src_path) != os.path.abspath(self.tailer.path):
            return

        # Windows can emit multiple modified events per write; tailer + offset prevents duplicates.
        for ev in self.tailer.read_new_lines():
            shared_queue.put(ev)

# --- 4. UI CONFIGURATION ---
st.set_page_config(page_title="SOC Dashboard", layout="wide")
st.title("🛡️ AI Security Operations Center")

if "events" not in st.session_state:
    st.session_state.events = []  # List[LogEvent]
if "processed" not in st.session_state:
    st.session_state.processed = set()  # Set[(path, offset)]
if "failures" not in st.session_state:
    st.session_state.failures = defaultdict(deque)  # type: ignore[var-annotated]
if "alerts_sent" not in st.session_state:
    st.session_state.alerts_sent = 0
if "last_alert_at" not in st.session_state:
    st.session_state.last_alert_at = {}  # Dict[str, float] keyed by ip
if "last_analysis" not in st.session_state:
    st.session_state.last_analysis = None
if "batch" not in st.session_state:
    # ip -> {"first_at": float, "lines": List[str], "max_score": int, "user": Optional[str]}
    st.session_state.batch = {}
if "llm_calls" not in st.session_state:
    st.session_state.llm_calls = 0

# Sidebar controls
with st.sidebar:
    st.subheader("⚙️ Detection Settings")
    window_s = st.number_input("Window (seconds)", min_value=10, max_value=600, value=DEFAULT_WINDOW_SECONDS, step=10)
    fail_threshold = st.number_input("Failures to flag as attack", min_value=3, max_value=50, value=DEFAULT_FAIL_THRESHOLD, step=1)
    cooldown_s = st.number_input("Alert cooldown per IP (seconds)", min_value=30, max_value=3600, value=DEFAULT_ALERT_COOLDOWN_SECONDS, step=30)
    score_threshold = st.number_input("Heuristic score threshold (LLM gate)", min_value=1, max_value=30, value=DEFAULT_SCORE_THRESHOLD, step=1)
    batch_wait_s = st.number_input("Batch wait seconds (same IP)", min_value=0.5, max_value=10.0, value=float(DEFAULT_BATCH_WAIT_SECONDS), step=0.5)
    max_batch_lines = st.number_input("Max lines per batch", min_value=5, max_value=100, value=DEFAULT_MAX_BATCH_LINES, step=5)
    max_llm_calls = st.number_input("Max LLM calls per refresh", min_value=1, max_value=10, value=DEFAULT_MAX_MODEL_CALLS_PER_REFRESH, step=1)
    st.caption("Goal: fewer LLM calls on RTX 3050 while still catching attack patterns.")

# Metrics
c1, c2, c3 = st.columns(3)
c1.metric("Lines Ingested", len(st.session_state.events))
c2.metric("Alerts Sent", st.session_state.alerts_sent)
c3.metric("GPU Engine", "RTX 3050", delta="Online")

# Start Observer
if "observer_started" not in st.session_state:
    tailer = get_tail_reader()
    observer = Observer()
    observer.schedule(
        LogHandler(tailer),
        path=os.path.dirname(os.path.abspath(__file__)),
        recursive=False,
    )
    observer.start()
    st.session_state.observer_started = True
    st.session_state.observer = observer

# Sync Queue to UI
ingested_now = 0
while not shared_queue.empty():
    ev: LogEvent = shared_queue.get()
    key = (ev.path, ev.offset)
    if key in st.session_state.processed:
        continue
    st.session_state.processed.add(key)
    st.session_state.events.append(ev)
    ingested_now += 1

# Always poll tailer as a backup (in case watchdog misses an event).
tailer = get_tail_reader()
for ev in tailer.read_new_lines():
    key = (ev.path, ev.offset)
    if key in st.session_state.processed:
        continue
    st.session_state.processed.add(key)
    st.session_state.events.append(ev)
    ingested_now += 1

# --- 5. ANALYSIS & DISPLAY ---
col_feed, col_ai = st.columns([1, 1.5])

with col_feed:
    st.subheader("📡 Live Feed")
    st.caption(f"Ingested this refresh: {ingested_now}")
    for e in reversed(st.session_state.events[-15:]):
        st.text(f"➜ {e.line}")

with col_ai:
    st.subheader("🧠 AI Threat Analysis")
    if st.session_state.last_analysis:
        st.info(st.session_state.last_analysis)

    st.session_state.llm_calls = 0

    def _add_to_batch(ip: str, line: str, *, user: Optional[str], score: int) -> None:
        b = st.session_state.batch.get(ip)
        if not b:
            st.session_state.batch[ip] = {"first_at": time.time(), "lines": [line], "max_score": score, "user": user}
            return
        if len(b["lines"]) < int(max_batch_lines):
            b["lines"].append(line)
        b["max_score"] = max(int(b["max_score"]), int(score))
        if user and not b.get("user"):
            b["user"] = user

    def _flush_batch(ip: str, *, fail_count: Optional[int], user: Optional[str]) -> None:
        if st.session_state.llm_calls >= int(max_llm_calls):
            return
        b = st.session_state.batch.get(ip)
        if not b:
            return
        lines = list(b.get("lines") or [])
        if not lines:
            st.session_state.batch.pop(ip, None)
            return

        st.session_state.llm_calls += 1
        analysis = ai_classify_batched(
            model=OLLAMA_MODEL,
            recent_lines=lines,
            ip=ip,
            user=user or b.get("user"),
            fail_count=fail_count,
            window_s=int(window_s) if fail_count is not None else None,
            heuristic_score=int(b.get("max_score") or 0),
        )
        verdict, severity = parse_ai_verdict_and_severity(analysis)
        st.session_state.last_analysis = f"{analysis}\n\nEvidence IP: {ip}\nBatch size: {len(lines)}"

        if verdict == "CONFIRMED_THREAT":
            msg = (
                "🚨 AI SOC ALERT\n"
                f"Verdict: {verdict}\n"
                f"IP: {ip}\n"
                f"User: {(user or b.get('user') or 'unknown')}\n"
                f"Severity: {severity if severity is not None else 'unknown'}\n"
                f"Failures_in_window: {fail_count if fail_count is not None else 'n/a'}\n\n"
                f"{analysis}\n\n"
                "Batched evidence:\n"
                + "\n".join(lines[-10:])
            )
            ok, detail = send_telegram(msg, token=TELEGRAM_TOKEN, chat_id=TELEGRAM_CHAT_ID)
            if ok:
                st.session_state.alerts_sent += 1
                st.session_state.last_alert_at[ip] = time.time()
                append_alert_history_csv(
                    csv_path=ALERTS_CSV_PATH,
                    timestamp=datetime.now(),
                    ip=ip,
                    verdict=verdict,
                    severity=severity,
                )
                st.success("Telegram alert sent and written to alerts_history.csv.")
            else:
                st.error(f"Telegram alert failed: {detail}")

        st.session_state.batch.pop(ip, None)

    # Process newly ingested lines in order (not just "latest")
    new_events = st.session_state.events[-ingested_now:] if ingested_now else []
    if new_events:
        for ev in new_events:
            parsed = parse_failed_login(ev.line)
            if parsed:
                user, ip, ts = parsed
                dq: Deque[datetime] = st.session_state.failures[(ip, user)]
                dq.append(ts)
                trim_deque(dq, int(window_s), ts)
                count = len(dq)

                # Heuristic gate + batching: push auth-related lines into per-IP batch when score is high
                score = suspicion_score(ev.line)
                if score >= int(score_threshold):
                    _add_to_batch(ip, ev.line, user=user, score=score)

                # Escalate on *pattern* (multiple failures) with per-IP cooldown, then flush batch
                should_escalate = count >= int(fail_threshold)
                last_sent = float(st.session_state.last_alert_at.get(ip, 0.0))
                in_cooldown = (time.time() - last_sent) < float(cooldown_s)

                if should_escalate and not in_cooldown:
                    # Ensure the batch includes a bit of evidence even if score gate didn't add lines.
                    if ip not in st.session_state.batch:
                        recent_same_ip = [
                            e.line
                            for e in st.session_state.events[-300:]
                            if (m := parse_failed_login(e.line)) and m[1] == ip
                        ]
                        for l in recent_same_ip[-int(max_batch_lines) :]:
                            _add_to_batch(ip, l, user=user, score=suspicion_score(l))

                    with st.spinner(f"Batch analyzing: {ip} ({count} fails / {window_s}s)"):
                        _flush_batch(ip, fail_count=count, user=user)
                continue

            # Non-auth lines: heuristic score gate. If high, attempt to attribute to an IP and batch.
            score = suspicion_score(ev.line)
            if score >= int(score_threshold):
                ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", ev.line)
                ip = ip_match.group(0) if ip_match else "unknown"
                _add_to_batch(ip, ev.line, user=None, score=score)

    # Flush old batches (backpressure + batching)
    now = time.time()
    flush_candidates: List[str] = []
    for ip, b in list(st.session_state.batch.items()):
        age = now - float(b.get("first_at", now))
        if age >= float(batch_wait_s) or len(b.get("lines") or []) >= int(max_batch_lines):
            flush_candidates.append(ip)

    for ip in flush_candidates:
        with st.spinner(f"Batch analyzing buffered events for IP: {ip}"):
            _flush_batch(ip, fail_count=None, user=None)

    # Optional quick action (manual) - safe failure if not admin
    st.markdown("---")
    st.subheader("🛠️ Response Actions (optional)")
    last_ip = None
    if st.session_state.events:
        ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", st.session_state.events[-1].line)
        last_ip = ip_match.group(0) if ip_match else None
    st.caption("Firewall blocking requires Administrator privileges on Windows.")
    if st.button("⛔ Block last seen IP in Windows Firewall", disabled=not bool(last_ip)):
        if not last_ip:
            st.warning("No IP found in the most recent log line.")
        else:
            ok, detail = block_ip_windows(last_ip)
            if ok:
                st.success(detail)
            else:
                st.error(detail)

    st.markdown("---")
    st.subheader("📊 Analytics (alerts_history.csv)")
    rows = read_alerts_history(ALERTS_CSV_PATH)
    if not rows:
        st.caption("No alert history yet. Confirmed threats will appear here.")
    else:
        by_ip: Dict[str, int] = {}
        sev_dist: Dict[str, int] = {}
        for r in rows:
            ip = (r.get("ip") or "unknown").strip()
            by_ip[ip] = by_ip.get(ip, 0) + 1
            sev = (r.get("severity") or "").strip()
            sev_key = sev if sev else "unknown"
            sev_dist[sev_key] = sev_dist.get(sev_key, 0) + 1

        c_a, c_b = st.columns(2)
        with c_a:
            st.caption("Threats by IP")
            st.bar_chart(by_ip)
        with c_b:
            st.caption("Severity distribution")
            st.bar_chart(sev_dist)

        # Export for report
        try:
            with open(ALERTS_CSV_PATH, "rb") as f:
                st.download_button(
                    label="Download CSV",
                    data=f.read(),
                    file_name=os.path.basename(ALERTS_CSV_PATH),
                    mime="text/csv",
                )
        except OSError:
            st.caption("CSV export unavailable (file could not be read).")

time.sleep(3)
st.rerun()