# BTLO Reverse Engineering — "A Classic Injection"

**Challenge:** BlueTeamLabs Online — A Classic Injection
**Sample:** `analyseme.exe` (delivered as `analyseme.zip`)
**Category:** Windows PE reverse engineering / classic process injection

> This challenge is owned and provided by [blueteamlabs.online](https://blueteamlabs.online). Files are not redistributed here — this document only records the analysis process and findings.

---

## 1. Extraction

The archive is password protected. Malware-sample zips conventionally use the password `infected`:

```bash
unzip -P infected analyseme.zip
```

```
Archive:  analyseme.zip
  inflating: analyseme.exe
```

```bash
file analyseme.exe
```

```
analyseme.exe: PE32 executable for MS Windows 6.00 (console), Intel i386, 5 sections
```

---

## 2. Static Triage

### 2.1 Strings

```bash
strings analyseme.exe
```

Notable findings:
- Import names: `WriteProcessMemory`, `WaitForSingleObject`, `Sleep`, `VirtualAllocEx`, `CreateProcessW`, `CreateRemoteThread` — the classic process-injection API set.
- A PDB path: `C:\Users\echo\source\repos\btlo\Release\btlo.pdb`
- Plaintext strings: `btlo`, `Easy! Try again`

### 2.2 PE header / import table

```bash
objdump -x analyseme.exe > disasm.txt
```

Key details extracted:

| Property | Value |
|---|---|
| Linker version | 14.28 (MSVC v142 toolset) |
| Compiler | **Microsoft Visual C++ (Visual Studio 2019)** |
| Subsystem | Windows CUI (console) |
| Entry point | `0x00401fce` |
| Imported DLLs | `KERNEL32.dll`, `MSVCP140.dll`, `VCRUNTIME140.dll`, `api-ms-win-crt-*.dll` |

The compiler identification is confirmed by:
- Linker version 14.28 → MSVC v142 toolset (VS2019)
- Rich header present (MS-linker-only artifact)
- C++ name mangling (Microsoft ABI, not Itanium/GCC)
- Runtime DLLs matching the VC++ 2015–2019 redistributable set
- PDB path following the default VS `source\repos` project layout

---

## 3. Disassembly with radare2

```bash
r2 -A analyseme.exe
[0x00401fce]> afl
[0x00401fce]> pdf @ main
```

### 3.1 Sleep timer

```asm
0x0040124d  push 0x2bf20          ; dwMilliseconds
0x00401252  call Sleep
```

`0x2BF20` = 180,000 ms = 180 s = **3 minutes**

### 3.2 Password prompt & check

After the sleep, `cin >>` reads user input into a buffer, which is then compared byte-by-byte against a hardcoded string:

```asm
0x004012c1  mov edx, str.btlo     ; "btlo"
0x004012d0  mov eax, dword [ecx]  ; loop comparing input vs "btlo"
0x004012d2  cmp eax, dword [edx]
...
0x0040131a  xor eax, eax          ; eax = 0 -> match
0x0040131c  test eax, eax
0x0040131e  jne 0x40142f          ; mismatch -> print "Easy! Try again"
```

**Correct password: `btlo`**

Confirmed via xref lookup:
```bash
r2 -A analyseme.exe
[0x00401fce]> axt str.btlo
```

### 3.3 Injection sequence (on correct password)

```asm
0x0040137d  push str.C:\Windows\System32\nslookup.exe
0x004013c2  call CreateProcessW          ; spawn victim process

0x004013db  push 0x1d9                   ; size = 473 bytes
0x004013ed  call VirtualAllocEx          ; allocate RWX memory in victim

0x004013fd  push 0x1d9                   ; size = 473 bytes
0x0040140a  call WriteProcessMemory      ; write shellcode into victim

0x00401421  call CreateRemoteThread      ; execute shellcode remotely
```

| Detail | Value |
|---|---|
| **Victim / target process** | `C:\Windows\System32\nslookup.exe` |
| **Shellcode size** | `0x1D9` = **473 bytes** |
| **Injection APIs used** | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` |
| Shellcode source location | `.rdata`, offset `0x403260` |

This is the textbook **"classic" process injection** pattern: allocate → write → execute in a remote process, using a legitimate system binary (`nslookup.exe`) as camouflage.

---

## 4. Shellcode Extraction

The shellcode blob was pulled directly out of the `.rdata` section using `pefile`:

```bash
python3 -c "
import pefile
pe = pefile.PE('analyseme.exe')
data = pe.get_data(0x403260 - 0x400000, 0x1d9)
open('shellcode.bin','wb').write(data)
"
```

### 4.1 Initial disassembly attempt

```bash
objdump -D -b binary -m i386 -M intel shellcode.bin
```

The output was mostly garbage/invalid opcodes past the first few instructions:

```asm
0x00: dbce         fcmovne st(0), st(6)
0x02: b895c7fa03   mov eax, 0x3fac795
0x07: d97424f4     fnstenv [esp-0xc]
0x0b: 5b           pop ebx
0x0c: 31c9         xor ecx, ecx
0x0e: b170         mov cl, 0x70      ; loop counter = 112
```

The `fnstenv [esp-0xc]` immediately followed by `pop ebx` is the classic **"GetPC" trick** (leaking EIP via the FPU state, then popping it into a register). Combined with the XOR-loop that follows, this identifies the blob as a **self-decoding shellcode stub** — the visible bytes are an encoder/decoder loop that unpacks the real payload at runtime, which is why static disassembly of the remainder produces invalid instructions.

### 4.2 Dynamic emulation with Speakeasy

Rather than manually decode the XOR loop, the shellcode was emulated directly:

```bash
pip install speakeasy-emulator --break-system-packages
speakeasy -t ./shellcode.bin -r -a x86 -o report.json -z ./dropped_files
```

Emulator output:
```
0x10b4: kernel32.WinExec("powershell.exe -enc <base64>", 0x1) -> 0x20
0x10c0: kernel32.GetVersion() -> 0x1db10106
0x10d3: kernel32.ExitProcess(0x0) -> 0x0
```

The decoder stub unpacks into a call to `WinExec`, launching a Base64-encoded PowerShell command.

### 4.3 Decoding the PowerShell payload

PowerShell `-enc` arguments are UTF-16LE Base64:

```bash
echo "TgBlAHcALQBJAHQAZQBtACAAQwA6AFwAVwBpAG4AZABvAHcAcwBcAHQAZQBtAHAAXABiAHQAbABvAC4AdAB4AHQACgBTAGUAdAAtAEMAbwBuAHQAZQBuAHQAIABDADoAXABXAGkAbgBkAG8AdwBzAFwAdABlAG0AcABcAGIAdABsAG8ALgB0AHgAdAAgACcAVwBlAGwAYwBvAG0AZQAgAHQAbwAgAEIAVABMAE8AIQAnAA==" | base64 -d | iconv -f UTF-16LE -t UTF-8
```

Decoded result:

```powershell
New-Item C:\Windows\temp\btlo.txt
Set-Content C:\Windows\temp\btlo.txt 'Welcome to BTLO!'
```

| Detail | Value |
|---|---|
| **File created** | `C:\Windows\temp\btlo.txt` |
| **File content** | `Welcome to BTLO!` |
| **Execution method** | `WinExec` → `powershell.exe -enc <base64>` |

---

## 5. Full Attack Chain Summary

```
analyseme.exe
   │
   ├─ Sleep(180000ms)                     [3-minute delay]
   │
   ├─ Prompt for password
   │     └─ correct password: "btlo"
   │
   ├─ CreateProcessW("nslookup.exe")      [spawn victim process]
   ├─ VirtualAllocEx(473 bytes)           [allocate memory in victim]
   ├─ WriteProcessMemory(shellcode)       [write 473-byte shellcode]
   ├─ CreateRemoteThread(...)             [execute shellcode remotely]
   │
   └─ [inside nslookup.exe]
        └─ Shellcode self-decodes (GetPC/XOR stub)
              └─ WinExec("powershell.exe -enc ...")
                    └─ New-Item C:\Windows\temp\btlo.txt
                    └─ Set-Content ... 'Welcome to BTLO!'
```

---

## 6. Answers Reference Table

| Question | Answer |
|---|---|
| Compiler used | Microsoft Visual C++ (Visual Studio 2019, MSVC v142, linker 14.28) |
| Sleep time | 3 minutes (180,000 ms) |
| Password | `btlo` |
| Shellcode size | 473 bytes (`0x1D9`) |
| Injection APIs | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` |
| Victim process | `nslookup.exe` |
| File created | `C:\Windows\temp\btlo.txt` (content: `Welcome to BTLO!`) |

---

## 7. Tools Used

| Tool | Purpose |
|---|---|
| `unzip` | Password-protected archive extraction |
| `file` / `strings` | Initial static triage |
| `objdump -x` | PE header, import table, relocations |
| `radare2` (`r2 -A`) | Full disassembly, function analysis, xrefs |
| `pefile` (Python) | Raw byte extraction from `.rdata` (shellcode dump) |
| `objdump -D -b binary` | Raw shellcode disassembly attempt |
| `speakeasy` | Windows shellcode emulation — resolved API calls without manual XOR decoding |
| `base64` / `iconv` | Decoding the PowerShell `-enc` payload |
