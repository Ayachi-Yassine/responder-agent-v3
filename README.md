# SentinelX Responder

**Autonomous host-based monitoring, AI-assisted investigation, and controlled incident response for Linux.**

SentinelX Responder is the host-side response component of the SentinelX lab project. It runs on a Linux machine, periodically checks selected host signals, and invokes a Groq-hosted model only when a detector reports a change or when the service receives an authenticated incident request.

It can also operate independently of the companion intelligence service: the `/respond` endpoint accepts an incident summary, gathers local reconnaissance, consults a response playbook, and returns a decision or executes it according to its configured mode.

> **Project status:** experimental / educational. Keep `DRY_RUN=true` and deploy only on an isolated lab network until the command-execution path, API access, and response policy have been hardened and tested.

## Capabilities currently implemented

| Capability | Current behavior |
|---|---|
| SSH authentication monitoring | Reads recent SSH failure messages from systemd journal and counts failures by source IP within a configurable window |
| New listener detection | Compares listening socket snapshots between scans |
| New process detection | Compares process snapshots between scans |
| Host reconnaissance | Collects firewall rules, process information, logged-in users, recent logins, and listening sockets |
| AI-assisted decision | Sends the incident, playbook, and reconnaissance output to Groq |
| IP blocking | Adds an iptables INPUT DROP rule and checks whether the rule is present |
| IP unblocking | Attempts to remove the matching iptables INPUT DROP rule |
| Dry-run mode | Logs the model's proposed action without executing it in the main reasoning path |
| HTTP API | Provides health, response, and manual execution endpoints |

The background monitor runs every `SCAN_INTERVAL` seconds. It initializes listener and process snapshots at startup, then compares subsequent scans. SSH failures are read from the journal using a rolling time window. The current implementation tracks already-triggered SSH source IPs in memory for the lifetime of the process.

## Architecture

```text
                    Optional companion service
                 SentinelX Intelligence (Wazuh)
                              |
                              | POST /respond
                              v
+-------------------------------------------------------+
|                 SentinelX Responder                   |
|                                                       |
|  FastAPI endpoints                                    |
|    /health                                            |
|    /respond  <--- authenticated incident handoff      |
|    /execute  <--- authenticated manual action API      |
|                                                       |
|  Background monitor                                   |
|    +--> SSH failed-login detector                     |
|    +--> new listening-port detector                   |
|    +--> new-process detector                          |
|                                                       |
|  On detected event / /respond                         |
|    +--> read playbook                                 |
|    +--> collect live host reconnaissance              |
|    +--> ask Groq for one proposed action               |
|    +--> DRY_RUN gate (reasoning path)                  |
|    +--> dispatch action when dry-run is disabled       |
|    +--> return result                                  |
+-------------------------------------------------------+
                              |
                              v
                     Linux host controls
                   iptables / local processes
```

## Repository contents

```text
agent_service.py          FastAPI service, detectors, recon, reasoning, actions
playbook.md               response guidance supplied to the model
agent.env.example         example environment configuration
responder-agent.service   systemd unit
requirements.txt          Python dependencies
```

## Requirements

- Linux host with systemd and `journalctl`
- Python 3 and Python virtual-environment support
- iptables, if IP blocking/unblocking is to be used
- A Groq API key
- A dedicated service account (the example systemd unit uses `yassine`)
- Network isolation and a firewall policy appropriate for a security lab

The SSH detector currently queries the journal using `journalctl -u ssh`. Some distributions use a different SSH service unit name (for example, `sshd`); verify the unit name on the target host and adjust the detector if needed.

## Install

The following follows the paths used by the included systemd unit. Run commands on the Linux target.

### 1. Copy the project to the host

For example, from your workstation:

```bash
scp -r responder-agent-v3 yassine@<LINUX_HOST>:~/
```

### 2. Create the installation directories and virtual environment

```bash
sudo mkdir -p /opt/responder-agent /etc/responder-agent
sudo cp ~/responder-agent-v3/agent_service.py /opt/responder-agent/
sudo cp ~/responder-agent-v3/playbook.md /opt/responder-agent/
sudo python3 -m venv /opt/responder-agent/venv
sudo /opt/responder-agent/venv/bin/pip install -r ~/responder-agent-v3/requirements.txt
```

### 3. Configure environment variables

```bash
sudo cp ~/responder-agent-v3/agent.env.example /etc/responder-agent/agent.env
sudo nano /etc/responder-agent/agent.env
```

Set a strong random `AGENT_API_KEY` and a valid `GROQ_API_KEY`. Keep:

```dotenv
DRY_RUN=true
```

The example file also defines the bind address, port, log path, model, scan interval, and SSH failure threshold/window. Protect the environment file because it contains credentials:

```bash
sudo chown root:root /etc/responder-agent/agent.env
sudo chmod 600 /etc/responder-agent/agent.env
```

### 4. Configure the narrowly required sudo permission

The current IP-blocking implementation invokes iptables through `sudo -n`. If you choose to test this capability, configure only the required permission using `visudo` and verify the actual iptables path on your host. The example unit runs as `yassine`; adapt the sudoers rule if you use another dedicated account.

Do not grant broad passwordless sudo access to the service account.

### 5. Install and start the systemd service

```bash
sudo cp ~/responder-agent-v3/responder-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now responder-agent
sudo systemctl status responder-agent
```

### 6. Verify the service

```bash
curl http://127.0.0.1:9100/health
sudo tail -f /var/log/responder-agent.log
```

The health endpoint reports whether the service is running in dry-run mode, whether the Groq key is configured, the scan interval, and whether self-monitoring is enabled. A healthy response does not prove that every detector or response action works correctly.

## API endpoints

| Endpoint | Purpose | Authentication |
|---|---|---|
| `GET /health` | Basic service/configuration status | No API key in current implementation |
| `POST /respond` | Gather recon, ask the model for a decision, then dry-run or dispatch | `X-API-Key` |
| `POST /execute` | Directly dispatch a supplied action and parameters | `X-API-Key` |

The response and manual execution endpoints expect the API key in the `X-API-Key` header.

Example health check:

```bash
curl http://127.0.0.1:9100/health
```

## Detection test ideas

Use only systems and accounts you own in an isolated lab.

- **SSH detector:** generate controlled failed SSH logins from a lab client and inspect the responder log for a detector event.
- **Listener detector:** start a temporary test listener on the target and check whether the next scan detects the new listening socket.
- **Process detector:** start a benign, identifiable test process and check whether it appears in the process snapshot difference.

Do not assume a detector event proves malicious activity. A new listener or process may be legitimate; the model's output should be reviewed as a hypothesis.

## Important security limitations

These are material limitations of the current code, not merely general deployment advice:

1. **The `/execute` endpoint bypasses the AI and dry-run gate.** It directly dispatches the requested action after API-key authentication. In particular, a caller with the API key can request `run_command` even when `DRY_RUN=true`. Do not expose this endpoint to untrusted networks. A safer next step is to remove or disable it by default, restrict it to a strict action allowlist, and require an independent authorization policy.
2. **`run_command` executes shell input.** The model-proposed command is passed to `/bin/sh -c`. This is high risk and should be replaced with narrowly defined, parameterized actions. Do not use this capability on production hosts.
3. **The API key is the primary API access control.** Use a long random secret, TLS or a trusted private network, key rotation, and network-level restrictions. The example service binds to `0.0.0.0`.
4. **Dry-run is not a global execution safety switch.** It gates the normal `reason_and_act` path, but not the direct `/execute` endpoint. Keep the service isolated even while dry-run is enabled.
5. **Detector state is in memory.** Listener/process snapshots, SSH failure counts, and the set of already-triggered IPs are lost when the service restarts.
6. **Detection heuristics need validation.** Process/listener changes are not inherently malicious. Journal parsing and service-unit names vary across Linux distributions.
7. **Action verification is incomplete.** IP blocking checks the iptables rule; the current unblocking and command paths do not provide equivalent independent verification.
8. **No automated test suite is currently included in this repository.** Add unit tests with mocked subprocess, journal, HTTP, and LLM boundaries before expanding deployment.

## Roadmap

- Make `/execute` disabled by default or remove it; enforce a strict action allowlist and authorization policy.
- Eliminate arbitrary shell execution in favor of parameterized response actions.
- Add persistent incident journaling and structured JSON logs.
- Add event IDs and correlation IDs across detections, model decisions, and action results.
- Add tracing and metrics for detector runs, LLM requests, and action execution.
- Persist detector state or explicitly document restart semantics.
- Add automated tests for detectors, API authentication, dry-run behavior, and action verification.
- Add service-specific journal configuration and improve IPv4/IPv6 parsing and validation.

## Companion project

[SentinelX Intelligence](https://github.com/Ayachi-Yassine/threat-intel-agent) receives Wazuh alerts, performs multi-agent analysis and graph correlation, and can hand qualifying incidents to this service.

## Disclaimer

SentinelX Responder is an experimental defensive security project for controlled labs. It can modify host firewall rules and, in its current implementation, execute shell commands. Do not deploy it on production systems without substantial security redesign, code review, testing, and explicit operational safeguards.
