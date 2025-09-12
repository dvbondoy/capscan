### Authenticated Scans via SSH — Implementation Plan

#### High-level rationale
Adding SSH-authenticated scans augments Nmap’s network discovery with host-level facts (packages, kernel, configs, running services), improving detection accuracy and enabling misconfiguration checks. Trade-offs include secure credential handling, host key verification, performance, and strict scoping.

#### Capabilities to deliver
- **Richer inventory**: kernel, distro, packages, services, users, key configs.
- **Higher-confidence vulns**: CVE matching on exact package versions; misconfig checks.
- **Fewer false positives**: confirm local versions vs banner guessing.

#### Architecture choice
- Keep Nmap (python-nmap) for discovery.
- For hosts with TCP/22 open, run a post-scan SSH enrichment module.
- Prefer direct SSH via Paramiko (depth/control) over NSE `ssh-run` (limited ergonomics).

#### Minimal viable flow
1. Run Nmap as today.
2. Filter hosts with port 22 open; enqueue SSH enrichment with bounded concurrency.
3. Authenticate via password, key file, or agent; optional `sudo -n` for specific read commands.
4. Collect data (Linux-first):
   - System info: `uname -a`, `cat /etc/os-release`
   - Packages: `dpkg -l` (Debian/Ubuntu) or `rpm -qa` (RHEL/CentOS/Fedora)
   - Services/ports: `ss -tulpen`, `systemctl list-units --type=service --state=running`
   - Configs: `/etc/ssh/sshd_config` (hash + excerpt)
5. Parse outputs, normalize schema, persist to `sqlcipher3`.
6. Surface in GUI: credentialed status per host + “Credentialed Findings” tab.
7. Optionally summarize findings via tgpt with redaction.

#### Security considerations
- **Credential storage**
  - Default in-memory only. If persisted, encrypt with `sqlcipher3` using a user-supplied master passphrase; derive key via PBKDF2/Argon2.
  - Support key-based auth; ensure private keys are protected (0600) and never stored unencrypted.
- **Host key verification**
  - Verify host keys. Provide TOFU (trust-on-first-use) toggle with explicit UX.
- **Least privilege and scope**
  - Restrict to a curated command allowlist; avoid secrets. Optional `sudo` for readonly commands with `NOPASSWD` policy.
- **Privacy with tgpt**
  - Redact usernames, paths, keys, tokens before sending to tgpt.
- **Operational safety**
  - Per-command timeouts, exponential backoff, concurrency limits.

#### GUI/UX (ttkbootstrap)
- Add an “Authenticated scan” panel:
  - **Auth method**: Password | Key | Agent
  - **Username**, **Password** (masked), **Key file**, optional **Passphrase**
  - **Sudo**: checkbox + readonly command set
  - **Concurrency** and **Timeouts** controls
  - Profile save/load (encrypted)
- Results tab: “Credentialed Findings” with host-level status (Succeeded/Failed/Partial), quick filters, and details panes.

#### Database extensions (sqlcipher3)
- Tables (suggested):
  - `credentialed_runs(host_id, status, error, started_at, finished_at)`
  - `hosts_osinfo(host_id, kernel, distro, version, last_seen)`
  - `hosts_packages(host_id, name, version, manager)`
  - `hosts_services(host_id, name, port, proto, origin)` where `origin` ∈ {`nmap`,`local`}
  - `hosts_configs(host_id, path, hash, excerpt)`
- Index on `host_id` and `name` where appropriate.

#### Implementation sketch (Python, Paramiko)
```python
import paramiko, socket

def ssh_run(host, user, password=None, keyfile=None, commands=None, timeout=8):
    out = {}
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.RejectPolicy())
        c.load_system_host_keys()
        kw = {"hostname": host, "username": user, "timeout": timeout, "banner_timeout": timeout}
        if keyfile:
            kw["key_filename"] = keyfile
        else:
            kw["password"] = password
        c.connect(**kw)
        for cmd in commands or []:
            stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
            out[cmd] = {
                "rc": stdout.channel.recv_exit_status(),
                "out": stdout.read().decode(errors="replace"),
                "err": stderr.read().decode(errors="replace"),
            }
        c.close()
        return True, out
    except (paramiko.SSHException, socket.error) as e:
        return False, {"error": str(e)}
```

#### Example command sets
- Debian/Ubuntu:
  - `uname -a`
  - `cat /etc/os-release`
  - `dpkg -l`
  - `ss -tulpen`
  - `systemctl list-units --type=service --state=running`
  - `test -f /etc/ssh/sshd_config && cat /etc/ssh/sshd_config`
- RHEL/Fedora:
  - `rpm -qa`

#### Optional Nmap NSE adjuncts
```bash
nmap -p22 --script ssh2-enum-algos,ssh-hostkey <host>
nmap -p22 --script ssh-run --script-args "ssh.user=USER,ssh.pass=PASS,command='uname -a'" <host>
```

#### Roadmap
- Phase 1: Paramiko enrichment after Nmap discovery; GUI inputs; store osinfo/services; basic redaction.
- Phase 2: Package inventory + distro-aware parsing; credential profiles; host key management UI.
- Phase 3: Vuln correlation (OSV/NVD or distro advisories); misconfiguration checks; reporting.
- Phase 4: Windows support (WinRM/SSH), broader config checks, policy baselines.

#### Testing
- Use containers/VMs across Debian/Ubuntu and RHEL/Fedora.
- Simulate failures: bad creds, host key mismatch, timeouts.
- Verify DB migrations and GUI flows; ensure no sensitive data reaches tgpt.

#### Performance
- Cap concurrent SSH sessions (e.g., 5–10); per-command timeout (e.g., 8–15s).
- Cache distro detection to pick command set; avoid long `dpkg -l` on slow hosts unless requested.

#### Risks
- Credential handling pitfalls; mitigate with encryption and minimal retention.
- Host key verification friction; mitigate with TOFU option and clear UX.
- Parsing variability across distros; mitigate with adapters and robust regex.
