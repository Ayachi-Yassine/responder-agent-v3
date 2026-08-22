"""
Responder Agent (v3 - autonomous, self-monitoring)
----------------------------------------------------
Runs on any target Linux machine as a systemd service.
No longer depends on Wazuh or any external orchestrator.

Two modes run concurrently in the same process:

1. SELF-MONITORING LOOP (background thread, new in v3)
   Cheap, deterministic detectors run every SCAN_INTERVAL seconds:
     - SSH brute force: counts failures per source IP in a rolling window
     - New listening port: diffs ss -tlnp snapshots
     - New suspicious process: diffs ps aux snapshots
   When a detector fires, it calls the AI reasoning pipeline (its own
   Groq call + playbook + live recon) to decide and act. No external
   trigger needed.

2. HTTP API (FastAPI, kept from v1/v2)
   GET  /health        -- service health check
   POST /execute       -- manually directed action (v1 compatible)
   POST /respond       -- hand off a summary, agent decides (v2 compatible)

AI reasoning (shared by all three paths):
   a. Load playbook.md
   b. Gather live system state (fixed read-only recon allowlist)
   c. Call Groq with playbook + recon + incident description
   d. Parse the JSON decision (action, ip, command, reasoning)
   e. Execute via dispatch_action(), verify effect
   f. Log everything to AGENT_LOG_FILE
"""

import os
import json
import logging
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import requests
from fastapi import FastAPI, Header, HTTPException, Request
import uvicorn

# ---------------------------------------------------------------------------
# Config (from environment / agent.env)
# ---------------------------------------------------------------------------
API_KEY          = os.getenv("AGENT_API_KEY", "")
HOST             = os.getenv("AGENT_HOST", "0.0.0.0")
PORT             = int(os.getenv("AGENT_PORT", "9100"))
LOG_FILE         = os.getenv("AGENT_LOG_FILE", "/var/log/responder-agent.log")
GROQ_API_KEY     = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL       = os.getenv("GROQ_MODEL", "groq/openai/gpt-oss-20b").replace("groq/", "")
GROQ_URL         = "https://api.groq.com/openai/v1/chat/completions"
DRY_RUN          = os.getenv("DRY_RUN", "true").lower() == "true"
SCAN_INTERVAL    = int(os.getenv("SCAN_INTERVAL", "15"))   # seconds between scans
SSH_FAIL_WINDOW  = int(os.getenv("SSH_FAIL_WINDOW", "60")) # rolling window (seconds)
SSH_FAIL_THRESH  = int(os.getenv("SSH_FAIL_THRESH", "5"))  # failures before trigger

PLAYBOOK_PATH    = Path(__file__).parent / "playbook.md"
NEVER_BLOCK      = {"127.0.0.1", "::1", "", None}
VALID_ACTIONS    = {"block_ip", "unblock_ip", "run_command", "none"}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("responder-agent")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _run(cmd: list, timeout: int = 15) -> tuple:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)

def _load_playbook() -> str:
    try:
        return PLAYBOOK_PATH.read_text()
    except Exception as e:
        logger.error(f"Could not load playbook.md: {e}")
        return "(playbook unavailable)"

# ---------------------------------------------------------------------------
# Action implementations (shared by all callers)
# ---------------------------------------------------------------------------
def block_ip_action(ip: str) -> dict:
    if not ip or ip in NEVER_BLOCK:
        return {"status": "error", "detail": f"Refusing to block {ip!r}"}
    code, _, _ = _run(["sudo", "-n", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
    if code == 0:
        logger.info(f"block_ip: {ip} already blocked")
        return {"status": "ok", "action": "block_ip", "ip": ip, "already_blocked": True, "verified": True}
    code, _, err = _run(["sudo", "-n", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    if code != 0:
        logger.error(f"block_ip: iptables failed for {ip}: {err}")
        return {"status": "error", "detail": f"iptables: {err}"}
    vcode, _, _ = _run(["sudo", "-n", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
    verified = vcode == 0
    logger.info(f"block_ip: {ip} blocked, verified={verified}")
    return {"status": "ok", "action": "block_ip", "ip": ip, "already_blocked": False, "verified": verified}

def unblock_ip_action(ip: str) -> dict:
    if not ip:
        return {"status": "error", "detail": "Missing ip"}
    code, _, err = _run(["sudo", "-n", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    removed = code == 0
    logger.info(f"unblock_ip: {ip} removed={removed}")
    return {"status": "ok", "action": "unblock_ip", "ip": ip, "removed": removed}

def run_command_action(command: str) -> dict:
    if not command:
        return {"status": "error", "detail": "Missing command"}
    logger.warning(f"run_command: {command}")
    code, out, err = _run(["/bin/sh", "-c", command], timeout=20)
    return {
        "status": "ok" if code == 0 else "error",
        "action": "run_command",
        "returncode": code,
        "stdout": out,
        "stderr": err,
    }

def dispatch_action(action: str, ip: str = "", command: str = "") -> dict:
    if action == "block_ip":     return block_ip_action(ip)
    if action == "unblock_ip":   return unblock_ip_action(ip)
    if action == "run_command":  return run_command_action(command)
    if action == "none":         return {"status": "ok", "action": "none"}
    return {"status": "error", "detail": f"Unknown action: {action}"}

# ---------------------------------------------------------------------------
# Recon (fixed read-only allowlist -- the LLM never chooses these)
# ---------------------------------------------------------------------------
RECON_CMDS = {
    "iptables_input": ["sudo", "-n", "iptables", "-L", "INPUT", "-n"],
    "top_processes":  ["sh", "-c", "ps aux --sort=-%cpu | head -20"],
    "who":            ["who"],
    "last_logins":    ["sh", "-c", "last -n 10"],
    "listening_ports":["sh", "-c", "ss -tlnp"],
}

def gather_recon() -> dict:
    out = {}
    for name, cmd in RECON_CMDS.items():
        code, stdout, err = _run(cmd, timeout=10)
        out[name] = stdout if code == 0 else f"(failed: {err})"
    return out

# ---------------------------------------------------------------------------
# AI reasoning (shared by monitor loop, /respond, and /execute-from-summary)
# ---------------------------------------------------------------------------
def call_groq(description: str, src_ip: str, recon: dict) -> dict:
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY not set")

    playbook   = _load_playbook()
    recon_text = "\n\n".join(f"### {k}\n{v}" for k, v in recon.items())

    system = (
        "You are an autonomous incident response agent running directly on "
        "the machine under investigation. Decide ONE action. "
        "Reply with ONLY a JSON object, no other text:\n"
        '{"action":"block_ip"|"unblock_ip"|"run_command"|"none",'
        '"ip":"<ip or empty>","command":"<command or empty>",'
        '"reasoning":"<1-2 sentences>"}\n\n'
        "PLAYBOOK:\n" + playbook
    )
    user = (
        f"Incident: {description}\n"
        f"Source IP (if any): {src_ip or 'none'}\n\n"
        f"Live system recon:\n{recon_text}\n\n"
        "Decide the single best action per the playbook and recon. "
        "Reply with only the JSON object."
    )

    resp = requests.post(
        GROQ_URL,
        headers={"Authorization": f"Bearer {GROQ_API_KEY}",
                 "Content-Type": "application/json"},
        json={
            "model": GROQ_MODEL,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            "temperature":      0.2,
            "max_tokens":       2048,
            "reasoning_effort": "low",
        },
        timeout=30,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"Groq error {resp.status_code}: {resp.text}")

    content = resp.json()["choices"][0]["message"].get("content") or ""
    start, end = content.find("{"), content.rfind("}")
    if start == -1 or end == -1:
        logger.error(f"No JSON in Groq output: {content!r}")
        raise RuntimeError("No JSON object in model output")

    decision = json.loads(content[start:end + 1])
    decision["action"]    = decision.get("action")    if decision.get("action") in VALID_ACTIONS else "none"
    decision["ip"]        = decision.get("ip")        or ""
    decision["command"]   = decision.get("command")   or ""
    decision["reasoning"] = decision.get("reasoning") or "(no reasoning)"
    return decision

def reason_and_act(description: str, src_ip: str = "") -> dict:
    """Full pipeline: recon -> Groq -> execute -> verify. Returns complete result dict."""
    recon = gather_recon()
    try:
        decision = call_groq(description, src_ip, recon)
    except Exception as e:
        logger.error(f"Groq call failed: {e}")
        return {"status": "error", "detail": str(e)}

    logger.info(f"Decision: {decision}")

    if DRY_RUN:
        msg = (f"[DRY RUN] Would execute action='{decision['action']}' "
               f"ip='{decision['ip']}' command='{decision['command']}' "
               f"reasoning='{decision['reasoning']}'")
        logger.info(msg)
        return {"status": "dry_run", "decision": decision, "message": msg}

    result = dispatch_action(decision["action"],
                             ip=decision["ip"],
                             command=decision["command"])
    return {"status": "ok", "decision": decision, "execution_result": result}

# ---------------------------------------------------------------------------
# Self-monitoring detectors (cheap, deterministic -- no LLM)
# ---------------------------------------------------------------------------

# Shared state for detectors
_port_snapshot:    set   = set()
_proc_snapshot:    set   = set()
_ssh_failures:     dict  = defaultdict(list)   # ip -> [timestamp, ...]
_triggered_ips:    set   = set()               # IPs already acted on this session
_monitor_lock:     threading.Lock = threading.Lock()

def _get_listening_ports() -> set:
    code, out, _ = _run(["sh", "-c", "ss -tlnp | awk 'NR>1 {print $4}'"], timeout=10)
    if code != 0:
        return set()
    return set(line.strip() for line in out.splitlines() if line.strip())

def _get_process_set() -> set:
    code, out, _ = _run(["sh", "-c", "ps aux | awk 'NR>1 {print $1,$11}'"], timeout=10)
    if code != 0:
        return set()
    return set(line.strip() for line in out.splitlines() if line.strip())

def _parse_ssh_failures():
    """Read recent SSH failures from journalctl and update rolling window."""
    code, out, _ = _run(
        ["sh", "-c", "journalctl -u ssh --since '2 minutes ago' --no-pager -q 2>/dev/null | "
                      "grep -i 'Failed password\\|authentication failure'"],
        timeout=10
    )
    if code != 0 or not out:
        return

    now = datetime.now()
    window_start = now - timedelta(seconds=SSH_FAIL_WINDOW)

    for line in out.splitlines():
        # Extract source IP from log line
        for token in line.split():
            if token.startswith("rhost=") or token.startswith("from"):
                ip = token.split("=")[-1].strip()
                if ip and ip not in NEVER_BLOCK:
                    with _monitor_lock:
                        _ssh_failures[ip] = [
                            t for t in _ssh_failures[ip] if t > window_start
                        ]
                        _ssh_failures[ip].append(now)
                break

def _check_ssh_brute_force() -> Optional[tuple]:
    """Return (ip, count) if any IP exceeds threshold, else None."""
    _parse_ssh_failures()
    with _monitor_lock:
        for ip, timestamps in _ssh_failures.items():
            if ip in _triggered_ips:
                continue
            if len(timestamps) >= SSH_FAIL_THRESH:
                return ip, len(timestamps)
    return None

def _check_new_port() -> Optional[str]:
    """Return newly appeared port string if detected, else None."""
    global _port_snapshot
    current = _get_listening_ports()
    with _monitor_lock:
        new_ports = current - _port_snapshot
        _port_snapshot = current
    if not new_ports:
        return None
    # Filter out the agent's own port
    filtered = {p for p in new_ports if not p.endswith(str(PORT))}
    return ", ".join(sorted(filtered)) if filtered else None

def _check_new_process() -> Optional[str]:
    """Return description of new processes if detected, else None."""
    global _proc_snapshot
    current = _get_process_set()
    with _monitor_lock:
        new_procs = current - _proc_snapshot
        _proc_snapshot = current
    if not new_procs:
        return None
    # Filter out very short-lived trivial processes
    meaningful = {p for p in new_procs
                  if not any(x in p for x in ("ps ", "awk ", "sh ", "sudo ", "ss "))}
    return ", ".join(sorted(meaningful)) if meaningful else None

def _monitor_loop():
    """Background thread: runs cheap detectors on SCAN_INTERVAL, triggers AI when needed."""
    global _port_snapshot, _proc_snapshot

    logger.info(f"Self-monitoring loop started (interval={SCAN_INTERVAL}s, "
                f"ssh_thresh={SSH_FAIL_THRESH}/{SSH_FAIL_WINDOW}s, dry_run={DRY_RUN})")

    # Initialize snapshots silently
    _port_snapshot = _get_listening_ports()
    _proc_snapshot = _get_process_set()

    while True:
        time.sleep(SCAN_INTERVAL)
        try:
            # --- Detector 1: SSH brute force ---
            result = _check_ssh_brute_force()
            if result:
                ip, count = result
                logger.info(f"[DETECTOR] SSH brute force: {ip} -> {count} failures in {SSH_FAIL_WINDOW}s")
                with _monitor_lock:
                    _triggered_ips.add(ip)
                reason_and_act(
                    description=(
                        f"SSH brute force detected: {count} failed authentication attempts "
                        f"from {ip} within the last {SSH_FAIL_WINDOW} seconds."
                    ),
                    src_ip=ip,
                )

            # --- Detector 2: New listening port ---
            new_port = _check_new_port()
            if new_port:
                logger.info(f"[DETECTOR] New listening port(s): {new_port}")
                reason_and_act(
                    description=(
                        f"New network listener(s) appeared on this machine: {new_port}. "
                        "This was not present in the previous scan. Could indicate a backdoor, "
                        "reverse shell, or unexpected service."
                    ),
                    src_ip="",
                )

            # --- Detector 3: New suspicious process ---
            new_proc = _check_new_process()
            if new_proc:
                logger.info(f"[DETECTOR] New process(es): {new_proc}")
                reason_and_act(
                    description=(
                        f"New process(es) appeared since the last scan: {new_proc}. "
                        "Investigate whether this is expected or potentially malicious."
                    ),
                    src_ip="",
                )

        except Exception as e:
            logger.error(f"Monitor loop error: {e}")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(title="Responder Agent")

def _auth(x_api_key: Optional[str]):
    if not API_KEY:
        raise HTTPException(status_code=500, detail="AGENT_API_KEY not configured")
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

@app.get("/health")
def health():
    return {
        "status": "ok",
        "dry_run": DRY_RUN,
        "groq_configured": bool(GROQ_API_KEY),
        "scan_interval": SCAN_INTERVAL,
        "self_monitoring": True,
    }

@app.post("/execute")
async def execute(request: Request,
                  x_api_key: Optional[str] = Header(default=None)):
    """v1 compat: manually specify action + params."""
    _auth(x_api_key)
    body   = await request.json()
    action = body.get("action")
    params = body.get("params", {})
    logger.info(f"[/execute] action={action} params={params}")
    if action not in VALID_ACTIONS:
        raise HTTPException(status_code=400, detail=f"Unknown action: {action}")
    result = dispatch_action(action,
                             ip=params.get("ip", ""),
                             command=params.get("command", ""))
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("detail", "failed"))
    return result

@app.post("/respond")
async def respond(request: Request,
                  x_api_key: Optional[str] = Header(default=None)):
    """v2 compat: receive a summary from the orchestrator, agent decides."""
    _auth(x_api_key)
    body     = await request.json()
    summary  = body.get("summary", "")
    src_ip   = body.get("src_ip", "")
    logger.info(f"[/respond] src_ip={src_ip} summary={summary!r}")
    result = reason_and_act(summary, src_ip)
    if result.get("status") == "error":
        raise HTTPException(status_code=502,
                            detail=f"Reasoning failed: {result.get('detail')}")
    return result

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    monitor_thread = threading.Thread(target=_monitor_loop, daemon=True)
    monitor_thread.start()
    uvicorn.run(app, host=HOST, port=PORT)
