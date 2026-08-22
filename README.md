# Responder Agent (v3 — autonomous, self-monitoring)

Replaces the Wazuh-dependent pipeline with a fully self-contained agent that
watches the machine itself, decides, and acts — no external orchestrator needed.

## What's new vs v2

v2 waited to be called via `/respond`. v3 adds a background monitoring loop
that runs cheap, deterministic detectors every `SCAN_INTERVAL` seconds and
only wakes the AI when something actually changes:

| Detector | Trigger |
|---|---|
| SSH brute force | ≥ `SSH_FAIL_THRESH` failures from same IP in `SSH_FAIL_WINDOW` seconds |
| New listening port | A port appears that wasn't in the previous scan |
| New suspicious process | A process appears that wasn't in the previous scan |

The AI (Groq call + playbook + live recon) is called **only when a detector
fires** — not on a timer. An idle machine generates zero Groq calls.

`/execute` and `/respond` endpoints are kept for backward compatibility and
manual testing.

## Install (fresh, or upgrade from v2)

### 1. Copy files to the machine

```bash
scp -r responder-agent yassine@192.168.111.139:~/
```

### 2. Stop the old service (if running)

```bash
sudo systemctl stop ubuntu-action-agent 2>/dev/null || true
```

### 3. Install files

```bash
sudo mkdir -p /opt/responder-agent /etc/responder-agent
sudo cp ~/responder-agent/agent_service.py /opt/responder-agent/
sudo cp ~/responder-agent/playbook.md      /opt/responder-agent/
```

### 4. Create/update the venv

```bash
sudo python3 -m venv /opt/responder-agent/venv
sudo /opt/responder-agent/venv/bin/pip install -r ~/responder-agent/requirements.txt
```

### 5. Configure

If upgrading from v2 (you already have `/etc/ubuntu-action-agent/agent.env`):
```bash
sudo cp /etc/ubuntu-action-agent/agent.env /etc/responder-agent/agent.env
sudo nano /etc/responder-agent/agent.env
```

Add the new vars (append to the existing file):
```
SCAN_INTERVAL=15
SSH_FAIL_WINDOW=60
SSH_FAIL_THRESH=5
```

If installing fresh:
```bash
sudo cp ~/responder-agent/agent.env.example /etc/responder-agent/agent.env
sudo nano /etc/responder-agent/agent.env
# fill in AGENT_API_KEY and GROQ_API_KEY
```

### 6. Sudoers (skip if already done in v1/v2)

```bash
sudo visudo -f /etc/sudoers.d/responder-agent
```
Add:
```
yassine ALL=(ALL) NOPASSWD: /usr/sbin/iptables
```

### 7. Install and start the systemd service

```bash
sudo cp ~/responder-agent/responder-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable responder-agent
sudo systemctl start responder-agent
```

### 8. Verify

```bash
sudo systemctl status responder-agent
curl http://localhost:9100/health
```

Expect:
```json
{
  "status": "ok",
  "dry_run": true,
  "groq_configured": true,
  "scan_interval": 15,
  "self_monitoring": true
}
```

### 9. Watch the log live

```bash
sudo tail -f /var/log/responder-agent.log
```

With `DRY_RUN=true`, you will see `[DETECTOR]` lines when something is found
and `[DRY RUN] Would execute ...` for each decision — no real action taken.

## Test it — SSH brute force

From Kali (or any machine):
```bash
for i in $(seq 1 15); do echo "wrongpass$i"; done > /tmp/w.txt
hydra -l yassine -P /tmp/w.txt ssh://192.168.111.139 -t 4
```

Watch the log on Ubuntu — within `SCAN_INTERVAL` seconds you should see:
```
[DETECTOR] SSH brute force: 192.168.111.131 -> 5 failures in 60s
Decision: {'action': 'block_ip', 'ip': '192.168.111.131', ...}
[DRY RUN] Would execute action='block_ip' ...
```

Set `DRY_RUN=false` and restart to see real blocking.

## Test it — backdoor listener

```bash
nohup nc -lvp 4444 > /dev/null 2>&1 &
```

Within `SCAN_INTERVAL` seconds the log should show the new port detected and
the AI deciding to investigate/kill it.

## Safety notes

- Start with `DRY_RUN=true`. Watch several full detection cycles. Only flip to
  `false` once you trust the decisions.
- `run_command` is unrestricted shell execution, gated by the API key and the
  LLM's judgment (informed by the playbook). Keep this service on an isolated
  lab network only.
- The SSH brute-force detector tracks IPs across scans and only triggers once
  per IP per service run (`_triggered_ips` set) — avoids spamming the AI with
  the same event repeatedly.
