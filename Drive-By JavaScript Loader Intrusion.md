# 🚨 JS#SMUGGLER → NetSupport RAT  
### ** Scenario 3 – Drive-By JavaScript Loader Intrusion**

---

## Scenario Background

An end-user visits a **legitimate but compromised website** hosting a hidden, heavily obfuscated JavaScript loader known as **JS#SMUGGLER**.  
The loader dynamically injects an invisible iframe that pulls down a malicious **HTA payload** hosted on attacker infrastructure.

The HTA is executed by **mshta.exe**, spawning an **in-memory PowerShell stager** that retrieves and executes **NetSupport RAT**.

Once deployed, the RAT establishes outbound C2 communication over HTTPS, providing the attacker full remote desktop–style access to the compromised host.

The attack leverages **Living-Off-the-Land Binaries (LOLBins)**, fileless execution, and browser-based delivery to evade traditional perimeter malware detection.

---

---

## Investigation Objectives

- Detect anomalous script-based process execution originating from a browsing session  
- Identify abuse of `mshta.exe` spawning PowerShell stagers  
- Detect in-memory payload execution without file-based signatures  
- Identify installation and persistence mechanisms related to NetSupport RAT  
- Correlate host telemetry, network activity, and threat behavior across the incident lifecycle

---

---

## Initial Alert

### Sentinel Analytics Rule  
**Name:** Suspicious mshta.exe PowerShell Execution  
**Severity:** High  
**Intent:** Detect HTA execution followed by PowerShell staged payload downloads

---

### Detection Logic (KQL)

```kusto
DeviceProcessEvents
| where FileName == "mshta.exe"
| where ProcessCommandLine has_any ("http://","https://",".hta")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, ParentProcessName
```
### Investigation Workflow
### Step 1 – Validate Initial Trigger

Confirm:

- mshta.exe launched by browser context or user session

- Command-line references to remote .hta payload or obfuscated URLs

- Parent processes related to browser activity or HTML execution
