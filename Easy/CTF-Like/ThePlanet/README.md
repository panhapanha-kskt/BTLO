# ThePlanet — Email Forensics Investigation

**Case file:** `A Hope to CoCanDa.eml`
**Analyst:** Panha
**Environment:** Kali Linux (DESKTOP-G17QB9R)
**Working directory:** `/home/Panha/blueteamlab/ThePlanet`

## Scenario Summary

An `.eml` file was received claiming to be a ransom note from an alien abductor demanding "1 Billion CoCanDs" for the safe return of abducted CoCanDians, including the President's daughter. The email contains an attachment disguised as a PDF, which unravels into a multi-layered puzzle. This document walks through the full investigation, step by step, from initial triage to final attribution.

---

## Q1: What is the email service used by the malicious actor?

### Steps

1. Inspected the raw `.eml` headers:
   ```bash
   cat "A Hope to CoCanDa.eml"
   ```

2. Identified the key routing headers:
   ```
   Received: from localhost (emkei.cz. [93.99.104.210])
           by mx.google.com with ESMTPS id s16si170171wmj...
   Return-Path: <billjobs@microapple.com>
   Received-SPF: fail (google.com: domain of billjobs@microapple.com does not designate 93.99.104.210 as permitted sender)
   ```

3. **SPF failure** confirms the `From` address (`billjobs@microapple.com`) is **spoofed** — the sending IP (`93.99.104.210`) is not authorized to send mail on behalf of `microapple.com`.

4. The originating host resolved to **`emkei.cz`** — a well-known free, anonymous fake-mail sending service ("Emkei's Fake Mailer") that allows anyone to forge the `From:` name/address without authentication.

### Answer
> **emkei.cz** (Emkei's Fake Mailer) — an anonymous web-based mail relay used to spoof the sender identity `billjobs@microapple.com`.

---

## Q2: What is the filetype of the received attachment which helped continue the investigation?

### Steps

1. The email declared the attachment as:
   ```
   Content-Type: application/pdf; name="PuzzleToCoCanDa.pdf"
   Content-Disposition: attachment; filename="PuzzleToCoCanDa.pdf"
   ```

2. Extracted the attachment using `ripmime`:
   ```bash
   apt install ripmime -y
   ripmime -i "A Hope to CoCanDa.eml" -d ./mime_out/
   ls ./mime_out/
   ```
   Output:
   ```
   PuzzleToCoCanDa.pdf  textfile0  textfile1
   ```

3. Verified the true filetype via magic bytes (ignoring the misleading extension/MIME header):
   ```bash
   cd mime_out
   file PuzzleToCoCanDa.pdf
   ```
   Output:
   ```
   PuzzleToCoCanDa.pdf: Zip archive data, made by v2.0, extract using at least v2.0,
   last modified Jan 25 2021 16:41:00, uncompressed size 18662, method=deflate
   ```

4. Confirmed via base64 magic-byte inspection: base64 `UEsDBBQ...` decodes to hex `50 4B 03 04` (`PK\x03\x04`), the **ZIP local file header signature** — not `%PDF-`.

### Answer
> The attachment is **not a PDF**, despite its name and declared MIME type — it is a **ZIP archive** (`PuzzleToCoCanDa.zip`), disguised as a PDF to bypass casual inspection or mail filtering.

---

## Q3: What is the name of the malicious actor?

### Steps

1. Extracted the ZIP archive:
   ```bash
   mv PuzzleToCoCanDa.pdf PuzzleToCoCanDa.zip
   7z l PuzzleToCoCanDa.zip
   7z x PuzzleToCoCanDa.zip -o./puzzle_extracted/
   ```

2. Identified the true filetypes of all extracted (extensionless) files:
   ```bash
   find ./puzzle_extracted -type f -exec file {} \;
   ```
   Output:
   ```
   ./puzzle_extracted/PuzzleToCoCanDa/GoodJobMajor: PDF document, version 1.5, 1 page(s)
   ./puzzle_extracted/PuzzleToCoCanDa/DaughtersCrown: JPEG image data, 822x435
   ./puzzle_extracted/PuzzleToCoCanDa/Money.xlsx: Microsoft Excel 2007+
   ```

3. Pulled metadata from `GoodJobMajor` (the PDF):
   ```bash
   exiftool GoodJobMajor
   ```
   Output:
   ```
   Author                       : Pestero Negeja
   Producer                     : Skia/PDF m90
   ```

4. Cross-referenced against the email's `Reply-To` header (captured earlier during header analysis):
   ```
   Reply-To: negeja3921@pashter.com
   ```

5. **Correlation:** The surname **"Negeja"** appears independently in two separate artifacts — the PDF author metadata and the email's Reply-To mailbox username. This is a strong, non-coincidental link, since the Reply-To is where actual attacker communication would route (unlike the spoofed `From` address).

### Answer
> **Pestero Negeja** — identified via PDF author metadata (`GoodJobMajor`), corroborated by the `Reply-To: negeja3921@pashter.com` header in the original email. The `"Bill" <billjobs@microapple.com>` identity is a decoy persona built on a spoofed domain, not the real actor.

---

## Q4: Locate the hidden "next location" from the puzzle (Money.xlsx)

### Steps

1. Inspected the ZIP-internal file listing of `Money.xlsx` (OOXML files are ZIP containers):
   ```bash
   unzip -l Money.xlsx
   ```
   Noted: no `docProps/core.xml` present (no author metadata embedded in this file), 2 worksheets, 2 (empty) drawing placeholders.

2. Checked sheet visibility state (relevant since the ZIP listing earlier showed a Windows **hidden** attribute flag `..H.A` on this file):
   ```bash
   cat Money_extracted/xl/workbook.xml
   ```
   Output confirmed both sheets are `state="visible"` — no hidden-sheet trick:
   ```xml
   <sheet state="visible" name="Sheet1" sheetId="1" r:id="rId4"/>
   <sheet state="visible" name="Sheet3" sheetId="2" r:id="rId5"/>
   ```

3. Checked the drawings for embedded images — both were empty placeholder XML with no `<xdr:pic>` elements or media references, ruling out image-based clues in this file.

4. Extracted all text content directly from the workbook's shared strings table:
   ```bash
   cat Money_extracted/xl/sharedStrings.xml | grep -oP '(?<=<t>).*?(?=</t>)'
   ```
   Output:
   ```
   Whatever you have seen or read till now is fake. Our intension was not for money.
   It is the beginning of the WAR WITH CoCanDians
   Location
   I will also stay in the same location but I bet CoCanDian's cant do anything in my planet😂
   Find and come ASAP I'm Waiting!
   VGhlIE1hcnRpYW4gQ29sb255LCBCZXNpZGUgSW50ZXJwbGFuZXRhcnkgU3BhY2Vwb3J0Lg==
   ```

5. Decoded the base64 string found in the "Location" cell:
   ```bash
   echo "VGhlIE1hcnRpYW4gQ29sb255LCBCZXNpZGUgSW50ZXJwbGFuZXRhcnkgU3BhY2Vwb3J0Lg==" | base64 -d
   ```
   Output:
   ```
   The Martian Colony, Beside Interplanetary Spaceport.
   ```

### Answer
> **The Martian Colony, Beside Interplanetary Spaceport.** — revealed to be the true motive/location twist: the ransom was never about money, it's framed as the opening move of a declared "war," and the actor is waiting at this location.

---

## Q5: What could be the probable C&C domain to control the attacker's autonomous bots? (2 points)

### Steps

1. Reviewed the two domains present across the collected artifacts:
   | Domain | Source | Status |
   |---|---|---|
   | `microapple.com` | `From:` header | **Spoofed** — SPF fail confirms attacker does not control this domain |
   | `pashter.com` | `Reply-To:` header (`negeja3921@pashter.com`) | Functionally live — where actual replies/communication route |

2. Ruled out `microapple.com` as attacker-controlled infrastructure:
   - SPF explicitly failed for this domain against the sending IP.
   - The domain name itself is a satirical mashup (Bill Gates/Microsoft + Steve Jobs/Apple), consistent with being a throwaway joke identity for the "Bill" ransom persona rather than real infrastructure.

3. Identified `pashter.com` as the credible candidate:
   - Unlike `From`, the `Reply-To` field must be functional for the attacker to receive responses — it cannot be arbitrarily spoofed without losing the ability to communicate.
   - The mailbox username `negeja3921` matches the PDF author surname `Negeja`, tying this domain directly to the confirmed actor identity (Q3).
   - Attackers commonly reuse a single controlled domain for both operator communications and bot/C2 check-in infrastructure, since it is already established and low-cost to repurpose.

4. Recommended (optional) verification commands to further substantiate this in a live investigation:
   ```bash
   whois pashter.com
   dig pashter.com ANY
   dig microapple.com ANY
   ```
   Comparing registration/DNS activity between the two domains would further confirm `pashter.com` as real, actor-controlled infrastructure versus `microapple.com` being unregistered/parked and used only as a cosmetic spoof.

### Answer
> **pashter.com** — the domain most likely to serve as the C&C for the attacker's autonomous bots, based on its role as the functional `Reply-To` communication channel and its direct correlation with the confirmed actor identity (`Negeja`). `microapple.com` is ruled out as it was proven to be a spoofed, non-attacker-controlled domain via SPF failure.

---

## Investigation Toolchain Reference

| Tool | Purpose |
|---|---|
| `file` | Identify true filetype via magic bytes, regardless of extension/declared MIME type |
| `ripmime` | Extract MIME parts (attachments, text bodies) from `.eml` files |
| `7z` | List/extract ZIP archive contents |
| `exiftool` | Pull embedded metadata (author, producer, timestamps) from images/PDFs/documents |
| `pdfinfo` | PDF-specific metadata and structural info |
| `base64 -d` | Decode base64-encoded strings/blobs |
| `unzip` | Extract OOXML (`.xlsx`) internals for direct XML inspection |
| `openpyxl` / `ssconvert` | Read spreadsheet cell content programmatically |
| `whois` / `dig` | Domain registration and DNS reconnaissance |

---

## Summary of Findings

| # | Question | Answer |
|---|---|---|
| 1 | Email service used | `emkei.cz` (Emkei's Fake Mailer) |
| 2 | Attachment filetype | ZIP archive (disguised as `.pdf`) |
| 3 | Malicious actor name | Pestero Negeja |
| 4 | Hidden location | The Martian Colony, Beside Interplanetary Spaceport |
| 5 | Probable C&C domain | `pashter.com` |
