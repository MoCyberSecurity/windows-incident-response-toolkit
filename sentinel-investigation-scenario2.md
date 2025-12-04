# OPERATION SILENT BEACON  
### Azure Sentinel SOC Investigation Scenario  

**Author:** *Mo – SOC Analyst | Log Analysis | KQL & PowerShell Forensics*

---

---

## 🎯 Scenario Overview

**Company:** CompanyX Logistics Ltd  
**Environment:** Hybrid Windows Active Directory + Azure Cloud  
**Defensive Stack:** Microsoft Defender for Endpoint + Microsoft Sentinel  
**SOC Role:** Tier 2 Incident Response Analyst

On **2025-03-04 at 08:32 UTC**, Microsoft Sentinel produced multiple alerts indicating suspicious PowerShell activity across several corporate workstations.

Triggered detections included:

- PowerShell executed using **encoded Base64 commands**
- DNS queries to **recently registered domains**
- Unusual outbound HTTPS communication
- Process chain anomalies originating from Microsoft Office attachments

The objective of the investigation was to:

- Identify the **initial access vector**
- Reconstruct the **attack timeline**
- Extract **Indicators of Compromise (IOCs)**
- Scope impacted endpoints and users
- Perform **containment and eradication**
- Produce a professional SOC incident report

---

---

## 🛠 Tools

This scenario evidences professional SOC capabilities including:

✅ Sentinel hunting and detection engineering (KQL)  
✅ Cross-telemetry log correlation  
✅ ScriptBlock payload reconstruction  
✅ PowerShell forensic automation  
✅ IOC extraction and scoping  
✅ Incident containment workflows  
✅ Technical SOC reporting

---

---

## 🚨 Phase 1 – Alert Triage

Sentinel alerts were generated for PowerShell executions with encoded commands and suspicious outbound connections.

---

### KQL – Initial Alert Validation

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("-enc","EncodedCommand","FromBase64String")
| project TimeGenerated, DeviceName, AccountName, FileName,
          InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated asc
```
### Finding

Four workstations executed PowerShell with encoded commands.
The parent process on all systems was:

WINWORD.EXE


This strongly suggested phishing email delivery with a malicious macro attachment.

---

## 📎 Phase 2 – Initial Access Identification

Following confirmation of suspicious PowerShell activity in Phase 1, the investigation pivoted into email telemetry to determine the initial infection vector and locate the delivery mechanism responsible for the malware execution.

Given the consistent parent process observed (`WINWORD.EXE`) across infected endpoints, phishing with a malicious Microsoft Office attachment was suspected.

---

### KQL – Email Investigation

The following query was run against the **EmailEvents** table to locate potentially malicious messages containing attachments that aligned with the detection time window:

```kql
EmailEvents
| where Subject has_any ("Invoice", "Delivery", "Shipping", "Update")
| where AttachmentCount > 0
| project Timestamp,
          SenderFromAddress,
          RecipientEmailAddress,
          Subject,
          AttachmentNames,
          DeliveryLocation
| order by Timestamp asc
```

### Findings

Several recipients received emails purporting to be shipment notifications or logistics invoices.

Messages originated from visually similar but unauthenticated domains attempting to impersonate business partners.

All confirmed malicious messages included macro-enabled Office attachments (e.g. .docm files).

### Observed Attack Vector

The phishing attachments contained VBA macros programmed to execute upon document enable-content prompts. Once macros were activated, the following execution chain was observed:

WINWORD.EXE
   └── powershell.exe (encoded command execution)


This execution chain validated the presence of a macro-to-PowerShell delivery mechanism designed to bypass traditional antivirus static detection.

Confirmed Malicious Attachments

Sample filenames recovered from logs:

Shipping_Update_9042.docm

Delivery_Notice_Q1.docm

Invoice_Tracking_5521.docm

### User Impact

Based on telemetry pivoting:

Four user accounts opened malicious attachments.

Those interactions directly correlated with the endpoints identified during Phase 1 alert triage.

No evidence of additional recipients interacting with the phishing payload was detected beyond these systems.

### Conclusion 

Initial access was achieved through a phishing campaign utilizing macro-enabled Office documents.
User interaction triggered embedded macros executing encoded PowerShell payloads, initiating the malware dropper stage observed in later investigation phases.

- This established a clear and defensible initial access narrative aligned with the MITRE ATT&CK technique:

         - T1566.001 — Phishing: Spearphishing Attachment

         - T1059.001 — Command and Scripting Interpreter: PowerShell


---

## ⚙ Phase 3 – Payload Collection

PowerShell ScriptBlock logs were extracted to recover encoded malware payloads.

---

### KQL – ScriptBlock Extraction

```kql
DeviceEvents
| where ActionType == "PowerShellScriptBlockExecuted"
| where AdditionalFields has "FromBase64String"
| project TimeGenerated,
          DeviceName,
          InitiatingProcessFileName,
          AdditionalFields
```
Base64 strings were exported for offline forensic decoding.

---

## 🧪 Phase 4 – PowerShell Payload Decoding

---

### PowerShell – Decode Payload Script

```powershell
param (
    [Parameter(Mandatory)]
    [string]$EncodedInputFile
)

$rawData = Get-Content $EncodedInputFile -Raw

$decoded = [System.Text.Encoding]::Unicode.GetString(
    [Convert]::FromBase64String($rawData)
)

$decoded | Out-File ".\decoded_script.txt"

Write-Host "[+] Payload successfully decoded"
```
### Analysis Results

- DNS-over-HTTPS beacon creation

- HTTP POST data exfiltration attempts

- Registry persistence modification

- Periodic C2 check-ins



---

## 🌐 Phase 5 – Command & Control Detection

After extracting candidate domains from payload analysis, Sentinel telemetry was used to identify beaconing behavior.

---

### KQL – DNS Beacon Detection

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName == "powershell.exe"
| summarize QueryCount=count() by DeviceName, RemoteUrl
| where QueryCount between (7..30)
| sort by QueryCount desc
```
### Suspicious Domain Identified
- Domain age: < 72 hours

- VPS hosting provider linked to prior abuse

- Low-volume periodic callbacks indicative of beaconing

---

## 🔁 Phase 6 – Lateral Scope Analysis

Using IOC pivoting across the DNS telemetry:

---

### KQL – Endpoint Pivot

```kql
DeviceNetworkEvents
| where RemoteUrl contains "sync-data-cloud"
| summarize CompromisedDevices=make_set(DeviceName)
```

- Confirmed Compromised Devices
  - FIN-WS-02
  - OPS-WS-07
  - LOG-WS-12
  - HR-WS-04

- Total affected endpoints: 4
---

## 🧾 Phase 7 – Hash Collection

To document forensic artifacts for threat intelligence sharing:

---

### PowerShell – Hash Extraction Script

**hash-validation.ps1**

```powershell
param(
    [string]$PathToArtifact
)

$hashResults = @{
    "MD5"    = (Get-FileHash $PathToArtifact -Algorithm MD5).Hash
    "SHA1"   = (Get-FileHash $PathToArtifact -Algorithm SHA1).Hash
    "SHA256" = (Get-FileHash $PathToArtifact -Algorithm SHA256).Hash
}

$hashResults | ConvertTo-Json | Out-File "artifact_hashes.json"

Write-Host "[+] Artifact hashes saved"
```
### Sample Output
```jason{
  "MD5": "bf92c19df77f08acb17c8ea9d9fd4d41",
  "SHA1": "d367a9c9f1b41d8f87a088f52820be0475de3705",
  "SHA256": "f1bc22345e74f6bd3c760c8678bc7ba71f44f205c4b14c8473dd918693fba7cc"
```


