# HTB Sherlock: CrashDump — Writeup

**Category:** Memory Forensics / Malware Analysis
**Difficulty:** Easy
**Rating:** 4.6 (24)
**XP Reward:** 355

---

## Scenario

> A suspicious executable was identified running on one of the compromised endpoints. Initial triage suggests that this process may have been leveraged by the threat actor to establish a foothold on the system. To support further malware analysis and behavioral reconstruction, a user-mode process dump of the suspected executable has been provided.

The provided archive (`CrashDump.zip`) contains two Windows minidump files:

- `update.DMP` — 72 MB, Mini DuMP crash report, 15 streams
- `notepad.DMP` — 100 MB, Mini DuMP crash report, 15 streams

Both dumps are timestamped within ~3 minutes of each other on the same host, strongly suggesting a single, connected incident rather than two unrelated crashes.

---

## Environment / Tools Used

- Kali Linux (analysis host)
- Python 3 + [`minidump`](https://github.com/skelsec/minidump) library (`pip install minidump --break-system-packages`)
- `strings` (with `-el` flag for UTF-16LE Windows process memory strings)
- `exiftool` / `file` (initial triage — limited value on `.DMP` files)

```bash
pip install minidump --break-system-packages
```

---

## Investigation Walkthrough

### 1. Initial Triage

`file` confirms both are Windows minidumps (15 streams each), but `exiftool` can't parse minidump-specific metadata — the `minidump` Python library is required to pull process, module, thread, and memory-region data.

### 2. Loaded Modules — Identifying the Two Processes

Parsing `SystemInfoStream` and `ModuleListStream` from each dump revealed:

**`update.DMP`** — main module:
```
C:\Users\s1rx\Downloads\update.exe   (base 0x400000)
```
An executable running from the `Downloads` folder and named to impersonate a Windows update — classic user-executed dropper / initial access vector.

**`notepad.DMP`** — main module:
```
C:\Windows\System32\notepad.exe   (base 0x7ff78dc10000)
```
A legitimate system binary, at its legitimate path — but its process memory contained network beacon strings that have no business being in a text editor.

### 3. Network String Analysis

UTF-16LE string extraction (`strings -el`) on both dumps surfaced C2-style HTTP indicators:

```
update.DMP:   http://101.10.25.4:8023/j.ad
              http://101.10.25.4:8023/submit.php?id=2080607144

notepad.DMP:  http://101.10.25.4:8891/ca
              http://101.10.25.4:8891/submit.php?id=1019752184
              http://101.10.25.4:8891/w2pD
```

Same C2 IP, same `submit.php?id=` beacon pattern, different ports — confirming `update.exe` and the code running inside `notepad.exe` are part of the same C2 channel.

### 4. Process Injection Confirmed

`update.exe` is the dropper/loader; it injects into a legitimate `notepad.exe` process to blend in with normal system activity, inherit its trust/privilege context, and beacon out from a process that looks clean in Task Manager.

Confirmed via the `MemoryInfoListStream` in `notepad.DMP`: several memory regions are `MEM_PRIVATE` (not backed by any file or loaded module) and `PAGE_EXECUTE_READWRITE` (the classic shellcode fingerprint — executable + writable + not part of a legitimate image).

```bash
python3 -c "
from minidump.minidumpfile import MinidumpFile
mf = MinidumpFile.parse('notepad.DMP')
for region in mf.memory_info.infos:
    protect = str(region.Protect)
    mtype = str(region.Type)
    state = str(region.State)
    if 'MEM_PRIVATE' in mtype and 'EXECUTE' in protect and 'MEM_COMMIT' in state:
        print(hex(region.BaseAddress), hex(region.RegionSize), state, mtype, protect)
"
```

Three RWX private regions were found; the smallest (a single 4KB page) is the initial injected stager — subsequent larger regions are the unpacked payload/beacon loaded by that stager.

### 5. Named Pipe (IPC Channel)

```bash
strings -el update.DMP | grep -i "\\\\pipe\\\\"
```

Surfaced:
```
\\.\pipe\postex_3d6e
\??\pipe\postex_3d6e
```

The `postex_` naming convention is characteristic of post-exploitation job/output pipes used by a well-known red-team C2 framework for passing command output between an injected process and its parent beacon.

### 6. PID of the Injected Process

Confirmed two independent ways:
1. String evidence in `update.DMP`: `Command Prompt - procdump.exe -ma 2336 notepad.DMP`
2. `MinidumpMiscInfoStream` in `notepad.DMP` directly reports `ProcessId 2336`

```bash
python3 -c "
from minidump.minidumpfile import MinidumpFile
mf = MinidumpFile.parse('notepad.DMP')
print(mf.misc_info)
"
```

---

## Answers Summary

| # | Task | Answer |
|---|------|--------|
| 1 | Operating System version | `10.0.10240.16384` (Windows 10, Build 10240 / v1507 RTM) |
| 2 | Malicious executable full path | `C:\Users\s1rx\Downloads\update.exe` |
| 3 | Thread count (malicious process) | `6` |
| 4 | Named pipe (IPC channel) | `postex_3d6e` |
| 5 | PID of injected process | `2336` |
| 6 | Last thread creation time (UTC) | *Pending — see Open Items* |
| 7 | BaseAddress of injected shellcode | `b1` + `20870000` (WinDbg format: b1\`20870000) |
| 8 | C2 server IP address | `101.10.25.4` |
| 9 | C2 framework | Cobalt Strike |

---

## Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| Malicious file path | `C:\Users\s1rx\Downloads\update.exe` |
| Injected/masqueraded process | `C:\Windows\System32\notepad.exe` (PID 2336) |
| C2 IP | `101.10.25.4` |
| C2 ports observed | `8023`, `8891` |
| C2 URI pattern | `/submit.php?id=<random>` |
| Named pipe | `\\.\pipe\postex_3d6e` |
| Injected memory region | `0xb120870000` (size `0x1000`, `RWX`, `MEM_PRIVATE`) |
| Victim username | `s1rx` |

---

## Open Items

- **Task 6** (last thread creation time for the injected process) requires parsing raw `CreateTime` FILETIME values out of the `ThreadInfoListStream`. The high-level `minidump` library object model doesn't expose a `thread_info_list` attribute directly — `mf.thread_info.infos[N]` needs to be inspected field-by-field to find the correct attribute name before this can be extracted and converted from Windows FILETIME (100ns ticks since 1601-01-01) to a UTC timestamp.

---

## Key Takeaways

- Minidumps (`.DMP`) require dump-aware tooling (WinDbg, or the Python `minidump` library) — Volatility is built for live memory/full-system captures (`.mem`/`.lime`) and will fail on user-mode crash dumps.
- A process running from `Downloads` and named after a legitimate update is a strong initial-access red flag.
- Cross-referencing shared C2 infrastructure (IP + beacon URI pattern) across two separate dumps is what proved the link between the dropper and the injected process.
- `MEM_PRIVATE` + `PAGE_EXECUTE_READWRITE` memory regions not backed by any loaded module are the definitive fingerprint of injected shellcode.
- Named pipes with attacker-controlled naming conventions (e.g., `postex_*`) are a reliable artifact for identifying the specific C2 framework in play.
