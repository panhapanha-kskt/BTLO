# BTLO Challenge Write-up: Melissa

## Overview

**Melissa** (aka `W97M.Melissa.A` per Symantec, or `Virus:W32/Melissa` per F-Secure) is a Microsoft Word macro virus/worm first observed on March 26, 1999. It spreads by embedding a malicious VBA macro inside a Word document (`LIST.DOC`), which — when opened — mass-mails a copy of the infected document to the first 50 entries in each Outlook address list on the victim's machine.

This write-up documents static analysis of the sample using `oledump.py` to extract and read the embedded VBA macro source directly, rather than executing the malware.

⚠️ **This analysis should always be performed in an isolated VM**, as the sample is live, functional malware.

---

## Tools Used

- `unzip` — extract the password-protected sample archive
- `file` — identify file type / OLE metadata
- `strings` — quick surface-level string extraction
- [`oledump.py`](https://blog.didierstevens.com/programs/oledump-py/) — parse OLE Compound File streams and extract/decompress VBA macro source

---

## Methodology

### 1. Extract the sample
```bash
unzip Sample.zip
cd Sample/
file LIST.DOC
```
Confirms `LIST.DOC` is a Composite Document File V2 (legacy `.doc` binary format), created in Microsoft Word 8.0.

### 2. Initial recon with `strings`
```bash
strings LIST.DOC
```
This surfaces a lot of the macro's plaintext content (registry paths, hardcoded strings like `Kwyjibo`, email subject/body text) even before formally extracting the macro, because VBA source is stored in a lightly-compressed but partially readable format inside the OLE stream.

### 3. Enumerate OLE streams with oledump
```bash
python3 oledump.py LIST.DOC
```
Output:
```
  1:       106 '\x01CompObj'
  2:       576 '\x05DocumentSummaryInformation'
  3:       512 '\x05SummaryInformation'
  4:      4113 '1Table'
  5:       331 'Macros/PROJECT'
  6:        26 'Macros/PROJECTwm'
  7: M    6544 'Macros/VBA/Melissa'
  8:      3946 'Macros/VBA/_VBA_PROJECT'
  9:      1407 'Macros/VBA/__SRP_0'
 10:        98 'Macros/VBA/__SRP_1'
 11:       178 'Macros/VBA/__SRP_2'
 12:        64 'Macros/VBA/__SRP_3'
 13:       633 'Macros/VBA/dir'
 14:      9253 'WordDocument'
```
The `M` flag on stream **7** marks it as containing VBA macro code — this is `Macros/VBA/Melissa`, the actual malicious module.

### 4. Decompress and dump the macro source
```bash
python3 oledump.py -s 7 -v LIST.DOC > melissa_macro.txt
```
`-s 7` selects the stream, `-v` decompresses the VBA source (VBA source is stored using a proprietary MS-OVBA compression scheme, not plaintext), redirected to a file for further searching.

### 5. Confirm specific strings with grep
```bash
grep -n "Melissa?" melissa_macro.txt
grep -n "Kwyjibo" melissa_macro.txt
```
This pinpoints the exact registry value name and comparison string used in the infection-check logic, with line numbers for context — confirming the literal source text rather than relying on possibly-mangled `strings` output.

---

## Answers & Explanations

### Q1. Submit the stream number that contains the Melissa macro in the LIST.DOC file
**Answer: `7`**

Identified via `oledump.py LIST.DOC` — stream 7 (`Macros/VBA/Melissa`) is the only stream flagged with `M`, indicating it holds VBA macro code.

### Q2. After identifying which version of word, Melissa will enable all macros from registry
**Answer: `9.0`**

The macro checks:
```vba
HKEY_CURRENT_USER\Software\Microsoft\Office\9.0\Word\Security
```
The `9.0` subkey corresponds to **Word 2000**. If this key exists and has a `Level` value, Melissa sets `Level = 1` (Low security, no macro warning prompts) and disables the Security button in the Macro toolbar. If the key doesn't exist (i.e. running under Word 97 instead), it falls into the `Else` branch and disables the Tools → Macro menu item plus turns off `ConfirmConversions`, `VirusProtection`, and `SaveNormalPrompt` directly via the Options object.

### Q3. What is the email service targeted by Melissa
**Answer: `Outlook`**

```vba
Set UngaDasOutlook = CreateObject("Outlook.Application")
Set DasMapiName = UngaDasOutlook.GetNameSpace("MAPI")
```
Melissa automates Microsoft Outlook via COM automation and its MAPI namespace to enumerate address books and send mail — it does not target any other mail client.

### Q4. How many number of email addresses were collected
**Answer: `50`**

```vba
For oo = 1 To AddyBook.AddressEntries.Count
    ...
    x = x + 1
    If x > 50 Then oo = AddyBook.AddressEntries.Count
Next oo
```
For each address list in Outlook, Melissa adds recipients until the counter `x` exceeds 50, then breaks out of the loop by forcing `oo` to the list's max count — capping the sample at 50 recipients per address list.

### Q5. What is the string used by Melissa to identify whether a PC is infected or not and decide whether to collect email addresses or not
**Answer: `Melissa?`** (the registry value name)

```vba
If System.PrivateProfileString("", "HKEY_CURRENT_USER\Software\Microsoft\Office\", "Melissa?") <> "... by Kwyjibo" Then
```
Melissa reads the registry value named **`Melissa?`** under `HKEY_CURRENT_USER\Software\Microsoft\Office\`. If this value does not equal `... by Kwyjibo`, the machine is considered *not yet infected*, and the mass-mailing routine runs. Afterward, the macro sets that same value to `... by Kwyjibo` (confirmed via `grep -n "Melissa?" melissa_macro.txt`, lines 20 and 41) so that on subsequent document opens, the check short-circuits and email collection is skipped.

### Q6. What is the variable responsible for identifying the email username of the infected PC
**Answer: `Application.UserName`**

```vba
BreakUmOffASlice.Subject = "Important Message From " & Application.UserName
```
`Application.UserName` pulls the registered user name configured in Word/Office settings on the victim's machine, used to personalize the outgoing email subject line.

### Q7. What is the text in email body used for spreading Melissa
**Answer:**
```
Here is that document you asked for ... don't show anyone else ;-)
```
Set directly as the `.Body` property of the outgoing mail item, designed as basic social engineering to get the recipient to open the attached infected document.

### Q8. What is the text that is inserted by Melissa in an open Word document?
**Answer:**
```
Twenty-two points, plus triple-word-score, plus fifty points for using all my letters.  Game's over.  I'm outta here.
```
This is a reference to a Scrabble bonus-score quote from *The Simpsons*, matching the virus author's alias "Kwyjibo" (also a Simpsons reference — Bart's fake Scrabble word). It only triggers under a specific condition:
```vba
If Day(Now) = Minute(Now) Then Selection.TypeText " Twenty-two points, plus triple-word-score, plus fifty points for using all my letters.  Game's over.  I'm outta here."
```
i.e., only when the current day-of-month numerically matches the current minute-of-the-hour — an easter egg/payload rather than a core spreading mechanism.

---

## Key Takeaways

- Melissa is a **macro virus + mass-mailing worm hybrid** — self-replicating via document infection (macro copies itself into `Normal.dot` and other open documents) *and* self-propagating via email.
- It relies entirely on **social engineering and default trust settings** (Word 97/2000 macro security being weak/off by default) rather than any software exploit.
- Static analysis via `oledump.py` is sufficient to fully understand its behavior without ever executing the payload — the preferred and safer approach for this kind of legacy OLE-based malware.
