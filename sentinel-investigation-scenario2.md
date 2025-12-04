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
# Findings

Four workstations executed PowerShell with encoded commands.
The parent process on all systems was:

WINWORD.EXE


This strongly suggested phishing email delivery with a malicious macro attachment.


