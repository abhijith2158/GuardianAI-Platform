import csv
import os
import re
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Deque, Dict, Iterable, List, Optional, Tuple

import requests
import streamlit as st


@dataclass(frozen=True)
class LogEvent:
    path: str
    offset: int
    line: str
    ingested_at: float


class TailReader:
    """
    File pointer tailer (tell/seek/readline) that returns every appended line.
    The (path, offset) tuple can be used as a stable dedupe key.
    """

    def __init__(self, path: str, *, start_at_end: bool = True):
        self.path = path
        self._pos = 0
        if start_at_end and os.path.exists(self.path):
            try:
                self._pos = os.path.getsize(self.path)
            except OSError:
                self._pos = 0

    @property
    def pos(self) -> int:
        return self._pos

    def read_new_lines(self) -> List[LogEvent]:
        if not os.path.exists(self.path):
            self._pos = 0
            return []

        try:
            size = os.path.getsize(self.path)
        except OSError:
            return []

        if size < self._pos:
            self._pos = 0

        events: List[LogEvent] = []
        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._pos)
                while True:
                    start_offset = f.tell()
                    line = f.readline()
                    if not line:
                        break
                    clean = line.strip("\r\n")
                    if clean.strip():
                        events.append(
                            LogEvent(
                                path=self.path,
                                offset=start_offset,
                                line=clean.strip(),
                                ingested_at=time.time(),
                            )
                        )
                self._pos = f.tell()
        except OSError:
            return []

        return events


def _load_dotenv(path: str = ".env") -> Dict[str, str]:
    if not os.path.exists(path):
        return {}
    out: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw in f.readlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k:
                    out[k] = v
    except OSError:
        return {}
    return out


def load_telegram_secrets(*, required: bool) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (telegram_token, telegram_chat_id).
    Priority: Streamlit secrets.toml -> .env -> process env.

    - If required=True and missing, shows UI error and stops the app.
    - If required=False and missing, shows a warning and continues (offline mode).
    """
    token = None
    chat_id = None

    # 1) Streamlit secrets (expects .streamlit/secrets.toml)
    try:
        token = st.secrets.get("TELEGRAM_TOKEN")  # type: ignore[attr-defined]
        chat_id = st.secrets.get("TELEGRAM_CHAT_ID")  # type: ignore[attr-defined]
    except Exception:
        token = None
        chat_id = None

    # 2) .env
    if not token or not chat_id:
        env_file = _load_dotenv(".env")
        token = token or env_file.get("TELEGRAM_TOKEN")
        chat_id = chat_id or env_file.get("TELEGRAM_CHAT_ID")

    # 3) process env
    token = token or os.getenv("TELEGRAM_TOKEN")
    chat_id = chat_id or os.getenv("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        msg = (
            "Telegram credentials are not configured.\n\n"
            "Add them in either:\n"
            "- `.streamlit/secrets.toml` (recommended), or\n"
            "- `.env`, or\n"
            "- your environment variables.\n\n"
            "Keys: `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`."
        )
        if required:
            st.error(msg)
            st.stop()
        st.warning(msg + "\n\nContinuing in offline mode (no Telegram alerts).")
        return None, None

    return str(token), str(chat_id)


def load_required_secrets() -> Tuple[str, str]:
    token, chat_id = load_telegram_secrets(required=True)
    # for type checkers; required=True means they exist.
    return str(token), str(chat_id)


def load_optional_secrets() -> Tuple[Optional[str], Optional[str]]:
    return load_telegram_secrets(required=False)


def read_alerts_history(csv_path: str) -> List[Dict[str, str]]:
    if not os.path.exists(csv_path):
        return []
    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace", newline="") as f:
            r = csv.DictReader(f)
            return [row for row in r if row]
    except OSError:
        return []


FAILED_LOGIN_RE = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})(?:\s+(?P<time>\d{2}:\d{2}:\d{2}))?.*?"
    r"failed\s+login.*?(?:user\s+)?'?(?P<user>[A-Za-z0-9._-]+)'?.*?"
    r"(?:from\s+ip|ip)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)


def parse_event_time(line: str) -> datetime:
    m = re.search(r"(\d{4}-\d{2}-\d{2})(?:\s+(\d{2}:\d{2}:\d{2}))?", line)
    if not m:
        return datetime.now()
    date_s, time_s = m.group(1), m.group(2)
    if time_s:
        try:
            return datetime.strptime(f"{date_s} {time_s}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return datetime.now()
    try:
        return datetime.strptime(date_s, "%Y-%m-%d")
    except ValueError:
        return datetime.now()


def parse_failed_login(line: str) -> Optional[Tuple[str, str, datetime]]:
    m = FAILED_LOGIN_RE.search(line)
    if not m:
        return None
    return m.group("user"), m.group("ip"), parse_event_time(line)


def trim_deque(dq: Deque[datetime], window_s: int, now: datetime) -> None:
    cutoff = now - timedelta(seconds=window_s)
    while dq and dq[0] < cutoff:
        dq.popleft()


KEYWORD_WEIGHTS: Dict[str, int] = {
    "unauthorized": 2,
    "forbidden": 2,
    "denied": 2,
    "failed login": 1,
    "invalid password": 1,
    "brute": 4,
    "spray": 4,
    "sql injection": 6,
    "sqli": 6,
    "xss": 5,
    "rce": 7,
    "command injection": 7,
    "path traversal": 6,
    "directory traversal": 6,
    "exploit": 6,
    "payload": 4,
    "shell": 4,
    "webshell": 7,
    "malware": 7,
    "cve-": 7,
    "root": 2,
    "admin": 2,
}


def suspicion_score(line: str) -> int:
    s = 0
    line_lc = line.lower()
    for k, w in KEYWORD_WEIGHTS.items():
        if k in line_lc:
            s += int(w)
    if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line):
        s += 1
    return s


def ai_classify_batched(
    *,
    model: str,
    recent_lines: List[str],
    ip: Optional[str],
    user: Optional[str],
    fail_count: Optional[int],
    window_s: Optional[int],
    heuristic_score: int,
) -> str:
    context = "\n".join(f"- {l}" for l in recent_lines[-25:])
    # Try to help the model by providing explicit inter-arrival intervals.
    # If timestamps can't be parsed for some lines, we omit intervals safely.
    intervals_hint: Optional[str] = None
    try:
        ts_list: List[Optional[datetime]] = []
        for l in recent_lines[-10:]:
            # Only parse if a date pattern is present.
            if not re.search(r"\d{4}-\d{2}-\d{2}", l):
                ts_list.append(None)
                continue
            # Use the existing parser; when it fails, it returns datetime.now().
            # To reduce noise, treat "now-like" fallback as parse failure by verifying the date substring.
            ts = parse_event_time(l)
            ts_list.append(ts)

        parsed_ts = [t for t in ts_list if t is not None]
        if len(parsed_ts) >= 2:
            deltas = []
            for a, b in zip(parsed_ts, parsed_ts[1:]):
                dt = (b - a).total_seconds()
                if 0 <= dt <= 86400:
                    deltas.append(int(dt))
            if deltas:
                intervals_hint = f"Inter-arrival intervals (seconds) between batch events: {deltas}"
    except Exception:
        intervals_hint = None
    meta = {
        "ip": ip,
        "user": user,
        "failures_in_window": fail_count,
        "window_seconds": window_s,
        "heuristic_score": heuristic_score,
        "batch_lines": len(recent_lines),
    }
    prompt = (
        "You are a SOC analyst. Decide whether to send a phone alert.\n"
        "Rules:\n"
        "1) 1-2 isolated failed logins => HUMAN_ERROR.\n"
        "2) Patterned automation (brute force/spraying/scanning/exploitation) => CONFIRMED_THREAT.\n"
        "3) If uncertain => SUSPICIOUS (no phone alert).\n"
        "Important: Look at the TIME INTERVAL between events in the batch. Very short, regular intervals (e.g., many attempts per second)\n"
        "or many attempts in a tight window strongly suggests Bot/Automation. Sparse, irregular attempts suggest Human Typos.\n"
        f"{'\\n' + intervals_hint if intervals_hint else ''}\n"
        "Output format:\n"
        "First line must be exactly one of: HUMAN_ERROR | SUSPICIOUS | CONFIRMED_THREAT\n"
        "Then include lines:\n"
        "- reason: <short>\n"
        "- severity: <1-10>\n"
        "- recommended_action: <short>\n\n"
        f"Meta: {meta}\n"
        "Evidence (batched log lines):\n"
        f"{context}\n"
    )

    # Ollama HTTP call with explicit timeout so the UI can't hang indefinitely.
    ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    # Keep these defaults conservative so the UI never appears "hung".
    timeout_s = float(os.getenv("OLLAMA_TIMEOUT_S", "15"))
    num_predict = int(os.getenv("OLLAMA_NUM_PREDICT", "160"))
    temperature = float(os.getenv("OLLAMA_TEMPERATURE", "0.1"))

    url = f"{ollama_host}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_predict": num_predict,
            "temperature": temperature,
        },
    }

    try:
        r = requests.post(url, json=payload, timeout=timeout_s)
        r.raise_for_status()
        data = r.json()
        return (data.get("response") or "").strip()
    except Exception:
        # Keep output format stable to avoid breaking downstream parsing.
        return (
            "SUSPICIOUS\n"
            "reason: Ollama classification timed out or failed.\n"
            "severity: 2\n"
            "recommended_action: Monitor and correlate with other events.\n"
        )


def parse_ai_verdict_and_severity(analysis: str) -> Tuple[str, Optional[int]]:
    lines = [l.strip() for l in (analysis or "").splitlines() if l.strip()]
    verdict = (lines[0] if lines else "").upper()
    if verdict not in {"HUMAN_ERROR", "SUSPICIOUS", "CONFIRMED_THREAT"}:
        verdict = "SUSPICIOUS"

    sev = None
    m = re.search(r"\bseverity\b\s*[:=]\s*(\d{1,2})\b", analysis, re.IGNORECASE)
    if m:
        try:
            sev = int(m.group(1))
        except ValueError:
            sev = None
    if sev is not None:
        sev = max(1, min(10, sev))
    return verdict, sev


def append_alert_history_csv(
    *,
    csv_path: str,
    timestamp: datetime,
    ip: str,
    verdict: str,
    severity: Optional[int],
) -> None:
    new_file = not os.path.exists(csv_path)
    try:
        with open(csv_path, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new_file:
                w.writerow(["timestamp", "ip", "verdict", "severity"])
            w.writerow(
                [
                    timestamp.isoformat(timespec="seconds"),
                    ip,
                    verdict,
                    "" if severity is None else int(severity),
                ]
            )
    except OSError:
        # Avoid crashing SOC loop on disk issues.
        return
