# Incident Response Playbook

Reference knowledge for deciding how to respond to security alerts.
Match the incoming summary against the closest pattern below — but
always confirm against the machine's ACTUAL live state (given to you
below as recon output) before deciding, since the summary may be
incomplete or wrong.

---

## Pattern: SSH brute force / repeated failed logins

**Signals:** "authentication fail", "multiple failed logins", "brute
force", high frequency of failures from one source IP.

**Recommended action:** block_ip on the offending source IP.

**Check first:** the recon's iptables output — if that IP is already
blocked, action should be "none" (already handled, don't duplicate).
Check the recon's `last`/`who` output — if that IP achieved a
*successful* login, treat this as more serious (possible compromise,
not just an attempt); still block_ip, but say so clearly in reasoning.

**Never block:** loopback (127.0.0.1, ::1) or an empty/missing IP.

---

## Pattern: Suspicious or runaway local process

**Signals:** unexpected process activity, high CPU/resource abuse,
unfamiliar binary names, local privilege escalation (not network-sourced).

**Recommended action:** run_command with a narrow, targeted kill (e.g.
"kill -9 <pid>") — pick the PID from the recon's process list, don't
guess. Never use broad commands like "killall" or anything affecting
processes not clearly implicated.

---

## Pattern: File integrity / rootcheck anomalies
(e.g. "Trojaned version of file detected")

**Signals:** rootcheck alerts about modified system binaries.

**Recommended action:** none, by default — these are frequently false
positives from signature heuristics matching legitimate tools. Only
recommend action if corroborated by other clearly suspicious recon
findings (unexpected process, unexpected listening port).

---

## Pattern: Low-severity / routine noise

**Signals:** isolated single events, routine login/logout sessions,
AppArmor/audit messages with no corroborating attack pattern.

**Recommended action:** none.

---

## General principles

1. Trust your OWN recon output over the incoming summary when they
   disagree — you have direct access to this machine right now.
2. Prefer the narrowest effective action. One IP, not a subnet. One
   process, not a service restart, if a process kill is sufficient.
3. When genuinely uncertain, choose "none" and explain why in reasoning
   — an unnecessary action has a real cost.
4. Your action will be verified after execution; be precise so
   verification can succeed.
