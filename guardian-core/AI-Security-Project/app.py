import os
import re
import subprocess
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Deque, Dict, List, Optional, Tuple

import streamlit as st

from soc_engine import (
    ai_classify_batched,
    append_alert_history_csv,
    load_optional_secrets,
    read_alerts_history,
    parse_ai_verdict_and_severity,
    parse_failed_login,
    suspicion_score,
    trim_deque,
)


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


# --- UI SETUP ---
st.set_page_config(page_title="AI Cyber-Guard Pro", page_icon="🛡️")
st.title("🛡️ AI Cyber-Guard Pro (SOC-grade Scan)")

TELEGRAM_TOKEN, TELEGRAM_CHAT_ID = load_optional_secrets()

OLLAMA_MODEL = st.sidebar.text_input("Ollama model", value="llama3.2")
ALERTS_CSV_PATH = st.sidebar.text_input("Alerts CSV path", value="alerts_history.csv")

st.sidebar.subheader("⚙️ Scan Settings")
window_s = st.sidebar.number_input("Window (seconds)", min_value=10, max_value=600, value=60, step=10)
fail_threshold = st.sidebar.number_input("Failures to flag as attack", min_value=3, max_value=50, value=6, step=1)
score_threshold = st.sidebar.number_input("Heuristic score threshold (LLM gate)", min_value=1, max_value=30, value=4, step=1)
max_batch_lines = st.sidebar.number_input("Max lines per IP batch", min_value=5, max_value=200, value=50, step=5)

uploaded_file = st.sidebar.file_uploader("Upload Server Logs", type=["txt", "log"])

if uploaded_file:
    log_data = uploaded_file.read().decode("utf-8", errors="replace")
    lines = [l.strip() for l in log_data.splitlines() if l.strip()]

    col1, col2 = st.columns([1, 1.2])

    with col1:
        st.subheader("📄 Raw Log Stream")
        st.code(log_data, language="bash")

    with col2:
        st.subheader("🧠 SOC-grade Results")

        if st.button("Run SOC-grade Scan"):
            failures: Dict[Tuple[str, str], Deque[datetime]] = defaultdict(deque)
            batches: Dict[str, List[str]] = defaultdict(list)
            batch_meta: Dict[str, Dict[str, Optional[str]]] = defaultdict(dict)
            max_score_by_ip: Dict[str, int] = defaultdict(int)

            confirmed: List[Dict[str, object]] = []
            suspicious: List[Dict[str, object]] = []

            for line in lines:
                score = suspicion_score(line)
                parsed = parse_failed_login(line)
                if parsed:
                    user, ip, ts = parsed
                    dq = failures[(ip, user)]
                    dq.append(ts)
                    trim_deque(dq, int(window_s), ts)
                    count = len(dq)

                    if score >= int(score_threshold) or count >= int(fail_threshold):
                        if len(batches[ip]) < int(max_batch_lines):
                            batches[ip].append(line)
                        max_score_by_ip[ip] = max(max_score_by_ip[ip], int(score))
                        batch_meta[ip]["user"] = user
                        batch_meta[ip]["fail_count"] = str(count)
                else:
                    if score >= int(score_threshold):
                        ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)
                        ip = ip_match.group(0) if ip_match else "unknown"
                        if len(batches[ip]) < int(max_batch_lines):
                            batches[ip].append(line)
                        max_score_by_ip[ip] = max(max_score_by_ip[ip], int(score))

            with st.status("Analyzing batches with LLM…", expanded=True) as status:
                for ip, batch_lines in batches.items():
                    if not batch_lines:
                        continue
                    user = batch_meta.get(ip, {}).get("user")
                    fail_count = batch_meta.get(ip, {}).get("fail_count")
                    fail_count_int = int(fail_count) if isinstance(fail_count, str) and fail_count.isdigit() else None

                    analysis = ai_classify_batched(
                        model=OLLAMA_MODEL,
                        recent_lines=batch_lines,
                        ip=None if ip == "unknown" else ip,
                        user=user,
                        fail_count=fail_count_int,
                        window_s=int(window_s) if fail_count_int is not None else None,
                        heuristic_score=int(max_score_by_ip.get(ip, 0)),
                    )
                    verdict, severity = parse_ai_verdict_and_severity(analysis)
                    record = {
                        "ip": ip,
                        "user": user or "unknown",
                        "verdict": verdict,
                        "severity": severity,
                        "analysis": analysis,
                        "evidence_count": len(batch_lines),
                    }

                    if verdict == "CONFIRMED_THREAT":
                        confirmed.append(record)
                        append_alert_history_csv(
                            csv_path=ALERTS_CSV_PATH,
                            timestamp=datetime.now(),
                            ip=ip,
                            verdict=verdict,
                            severity=severity,
                        )
                    elif verdict == "SUSPICIOUS":
                        suspicious.append(record)

                status.update(label="Scan complete", state="complete")

            if confirmed:
                st.error(f"🚨 Confirmed threats: {len(confirmed)}")
                for rec in confirmed:
                    st.markdown(f"**IP**: `{rec['ip']}`  **Severity**: `{rec['severity']}`  **Evidence**: `{rec['evidence_count']}`")
                    st.text(rec["analysis"])
                    st.markdown("---")
            else:
                st.success("No confirmed threats found by SOC-grade engine.")

            if suspicious:
                with st.expander(f"SUSPICIOUS ({len(suspicious)})"):
                    for rec in suspicious:
                        st.markdown(f"**IP**: `{rec['ip']}`  **Evidence**: `{rec['evidence_count']}`")
                        st.text(rec["analysis"])
                        st.markdown("---")

        st.subheader("🛠️ Immediate Action (optional)")
        ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", log_data)
        target_ip = ip_match.group(0) if ip_match else None
        st.caption("Firewall blocking requires Administrator privileges on Windows.")
        if st.button("⛔ Block first IP found in logs", disabled=not bool(target_ip)):
            if not target_ip:
                st.warning("Could not find a valid IP in the log file.")
            else:
                ok, detail = block_ip_windows(target_ip)
                if ok:
                    st.success(detail)
                else:
                    st.error(detail)

st.markdown("---")
st.subheader("📊 Analytics (alerts_history.csv)")
rows = read_alerts_history(ALERTS_CSV_PATH)
if not rows:
    st.caption("No alert history yet. Confirmed threats will be appended during scans.")
else:
    by_ip: Dict[str, int] = {}
    sev_dist: Dict[str, int] = {}
    for r in rows:
        ip = (r.get("ip") or "unknown").strip()
        by_ip[ip] = by_ip.get(ip, 0) + 1
        sev = (r.get("severity") or "").strip()
        sev_key = sev if sev else "unknown"
        sev_dist[sev_key] = sev_dist.get(sev_key, 0) + 1

    st.caption("Threats by IP")
    st.bar_chart(by_ip)

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

# Refresh analytics charts periodically so new alerts appended by live_monitor appear.
if os.path.exists(ALERTS_CSV_PATH):
    time.sleep(3)
    st.rerun()