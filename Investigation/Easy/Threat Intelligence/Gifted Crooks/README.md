# BTLO Lab Investigation: Gifted Crooks (MISP Threat Intelligence)

## Overview

This document summarizes the investigation of **MISP Event ID 10128**, part of the BTLO
"Gifted Crooks" lab. The lab introduces MISP (Malware Information Sharing Platform) as a
Threat Intelligence Platform (TIP) and walks through the fields, objects, and attributes
CTI analysts use for enrichment, correlation, and reporting.

The event is based on a real-world advisory published by **CERT-UA** (Ukraine's national
Computer Emergency Response Team), tracking a cyber-espionage campaign (**UAC-0226**)
that used the **GIFTEDCROOK** infostealer against Ukrainian innovation centers, government
bodies, and law enforcement agencies.

Reference advisory: https://cert.gov.ua/article/6282946

---

## Event Metadata

| Field | Value |
|---|---|
| Event ID | 10128 |
| Issuing Country | Ukraine (CERT-UA) |
| Campaign Type | Cyber Espionage |
| Published Date | 2025-04-08 08:43:37 |
| Creator Organization | rosti.bin.re |
| TLP Tag | tlp:clear |
| Attributes | 56 |
| Objects | 21 |
| Unique Categories | 4 (Payload Delivery, Network Activity, Artifacts Dropped, External Analysis) |

---

## Indicators of Compromise (IOCs)

### File Extensions Observed
- `.ps1`
- `.xlsm`
- `.zip`

### Office Documents
- **Total:** 9 malicious Office documents (Excel-based, `.xlsm`)

### Scripts Identified
- `kpbkewt32mm.ps1`
- `nnnnrth.ps1`

### Dropped Artifact
| File Name | Path |
|---|---|
| `status.zip` | `%TMP%\nmpoyqv5l0ig\` |

### Command-and-Control (C2) Infrastructure

| C2 | IP:Port (Defanged) | Country (via ICANN Lookup) |
|---|---|---|
| 1st C2 | `89[.]44[.]9[.]186:3240` | France |
| 2nd C2 | `37[.]120[.]239[.]187:6501` | Netherlands |

---

## Investigation Workflow

1. **Locate the event** — opened Event ID 10128 in MISP and reviewed the title/tags
   referencing CERT-UA, UAC-0226, and GIFTEDCROOK.
2. **Review metadata** — captured publish date, creator org, and TLP classification.
3. **Expand all objects** — used MISP's "Expand All Objects" view to enumerate
   attributes/objects and identify category groupings.
4. **Extract file-based IOCs** — identified unique file extensions, counted Office
   documents, and recorded script file names.
5. **Identify dropped artifacts** — located the initial-infection artifact and its
   drop path.
6. **Extract network IOCs** — pulled both C2 IP/port pairs and defanged them using
   CyberChef's "Defang IP Address" recipe.
7. **Enrich IOCs** — ran both C2 IPs through ICANN IP Lookup to determine hosting
   country for each.
8. **Confirm sharing classification** — checked the event's TLP tag to determine
   how the intelligence may be shared.

---

## Key Takeaways

This lab is less about malware reverse engineering and more about the core CTI
analyst workflow: **collecting, correlating, enriching, and reporting** on
adversary infrastructure and behavior using a structured platform like MISP.
Skills exercised include:

- Navigating MISP events, attributes, and objects
- Categorizing IOCs by type (payload delivery, network activity, dropped artifacts)
- Enriching network indicators with external lookup tools (ICANN, CyberChef)
- Understanding TLP (Traffic Light Protocol) sharing classifications

---

## Answer Key (Quick Reference)

| # | Question | Answer |
|---|---|---|
| 1 | Country / campaign type | Ukraine, Cyber-Espionage |
| 2 | Published date / creator org | 2025-04-08 08:43:37, rosti.bin.re |
| 3 | Attributes / Objects count | 56, 21 |
| 4 | Unique categories | 4 |
| 5 | Unique file extensions | .ps1, .xlsm, .zip |
| 6 | Office documents count | 9 |
| 7 | Script file names | kpbkewt32mm.ps1, nnnnrth.ps1 |
| 8 | Dropped artifact / path | status.zip, %TMP%\nmpoyqv5l0ig\ |
| 9 | First C2 (IP:Port) | 89[.]44[.]9[.]186:3240 |
| 10 | Second C2 (IP:Port) | 37[.]120[.]239[.]187:6501 |
| 11 | First C2 country | France |
| 12 | Second C2 country | Netherlands |
| 13 | TLP tag | tlp:clear |

---

*Prepared as investigation notes for the BTLO "Gifted Crooks" MISP lab.*
