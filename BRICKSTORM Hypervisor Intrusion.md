# 🛡️ Operation Silent Beacon – BRICKSTORM Hypervisor Intrusion

---

## Scenario Overview

A mid-sized cloud services provider begins receiving alerts for **suspicious outbound DNS and HTTPS traffic originating from a VMware ESXi hypervisor host**.  
The affected host is part of the company’s internal virtualisation platform and is **not expected to communicate directly with the public internet** except for approved updates and management services.

Additional telemetry quickly reveals:

- Unauthorized **VM snapshot creation** across several production workloads  
- **Anomalous administrative login activity** into the vCenter management console from unfamiliar geographic locations  
- Evidence of potential **credential misuse and lateral movement attempts**

These indicators align with public intelligence describing **BRICKSTORM malware**, a stealth backdoor capable of targeting hypervisor infrastructure to maintain persistence, exfiltrate sensitive data via snapshot harvesting, and enable long-term undetected access across virtualized environments.

This scenario documents the **SOC investigation workflow** used to:

- Triage alerts in Microsoft Sentinel  
- Conduct targeted threat hunting using KQL  
- Support forensic data collection with PowerShell  
- Extract Indicators of Compromise (IOCs)  
- Perform containment actions  
- Produce a full incident timeline and report

---

---

## Phase 1 – Detection & Alert Triage

### Objective  
Validate alerts and identify the **initial signs of hypervisor compromise**.

---

### Alert Trigger

Microsoft Sentinel generated multiple alerts for:

- **Unusual outbound DNS-over-HTTPS (DoH) traffic**
- **Sustained external connections** from the ESXi management interface
- **Network beaconing patterns inconsistent with baseline activity**

These indicators suggested possible C2 (Command-and-Control) communication.

---

### KQL – Outbound Traffic Analysis

```kql
DeviceNetworkEvents
| where DeviceType == "VMwareESXi"
| summarize ConnCount = count() by RemoteIP, bin(TimeGenerated, 5m)
| where ConnCount > 100
```
# Phase 2: Initial Access and Compromise

## Objective
Identify the initial entry point and method of compromise to understand how the attacker gained access to the virtual infrastructure.

## Actions Taken
- Reviewed perimeter and edge device logs for unusual authentication attempts.
- Correlated firewall, VPN, and RDP logs to pinpoint suspicious connections.
- Identified unauthorized administrative access attempts originating from external IP addresses.
- Analyzed ESXi host logs for abnormal login events and failed authentication attempts.
- Detected suspicious payload deployment targeting VM snapshots and configuration files.

## Observations
- Attack originated from an untrusted external IP range.
- Brute-force attempts on ESXi administrative accounts were observed prior to payload execution.
- Payload delivery was automated, leveraging default or weak configurations on the vCenter and ESXi hosts.
- Early indicators suggest reconnaissance was performed prior to the actual compromise.

## KQL – Privileged vCenter Authentication Review

```kql
SigninLogs
| where AppDisplayName contains "vCenter"
| where ConditionalAccessStatus == "success"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    LocationDetails,
    UserAgent
```
# Phase 3: Payload Collection and Analysis

## Objective
Collect and analyse the malicious payloads deployed to understand the attacker’s capabilities and potential impact on the virtual infrastructure.

## Actions Taken
- Extracted suspicious files from ESXi hosts and guest VMs.
- Collected PowerShell scripts, backdoor binaries, and configuration snapshots.
- Captured network traffic associated with the payload to identify C2 communication patterns.
- Examined file hashes and compared against threat intelligence feeds for known malware signatures.
- Isolated affected systems to prevent further spread during analysis.

## Observations
- Malicious payloads included custom backdoor binaries capable of persistent access.
- PowerShell scripts were obfuscated and executed automatically on VM snapshots.
- Network traffic revealed encrypted communications to external C2 servers.
- Several indicators of compromise (IOCs) were identified, including IP addresses, file hashes, and domain names used for remote control.
## KQL – Unauthorized Snapshot Activity Detection

```kql
AzureDiagnostics
| where Category == "VMWareEventLog"
| where Message has_any ("Snapshot Created", "CreateSnapshot")
| project
    TimeGenerated,
    Computer,
    Message,
    InitiatingUser
```


# Phase 4: C2 Detection and Lateral Movement

## Objective
Identify command-and-control communications and track lateral movement to assess the scope of compromise.

## Actions Taken
- Monitored network logs for anomalous outbound traffic patterns from ESXi hosts and VMs.
- Detected connections to suspicious external domains and IP addresses.
- Correlated unusual administrative activity across multiple hosts.
- Reviewed event logs for unexpected process execution and remote commands.
- Tracked lateral movement attempts from compromised VMs to other hosts within the environment.

## Observations
- Persistent encrypted communications with external C2 servers were confirmed.
- Attackers attempted lateral movement using compromised credentials and administrative tools.
- Several VMs were accessed and manipulated, including unauthorised snapshot downloads.
- The compromise affected multiple hosts, indicating a coordinated and automated attack.

### KQL – Snapshot Activity Outside Maintenance Windows

```kql AzureDiagnostics
| where Category == "VMWareEventLog"
| where Message has "Snapshot"
| extend Hour = datetime_part("hour", TimeGenerated)
| where Hour < 7 or Hour > 19
| project TimeGenerated, Computer, Message
```
### KQL – Data Exfiltration Correlation
```kql
DeviceNetworkEvents
| where InitiatingProcessFileName has_any ("vmtoolsd.exe", "vmware-vmx.exe")
| where RemoteIP !startswith "10."
| summarize ConnCount=count() by DeviceName, RemoteIP
| where ConnCount > 100
```
### PowerShell – Recent Script & Binary Discovery
```powerhsell
Get-ChildItem "C:\ProgramData" -Recurse |
Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-5) } |
Select-Object FullName, CreationTime, Length

PowerShell – Staged Payload Identification
Get-Process |
Where-Object { $_.Path -like "*ProgramData*" }
```
# Phase 5 – Hash Collection & IOC Documentation

## Objective
Collect and document all relevant Indicators of Compromise (IOCs) to support threat intelligence correlation, enhanced detection coverage, and remediation activities.

---

## Investigation Actions

- Calculated cryptographic hashes of suspected malware binaries and scripts.
- Extracted network indicators including C2 IP addresses and suspicious domains.
- Documented compromised administrative user activity.
- Cross-referenced collected artifacts with internal and external threat intelligence sources.
- Structured IOC findings into a formatted detection reference list.

---

## PowerShell – Suspicious File Hash Collection

```powershell
Get-ChildItem "C:\ProgramData" -Recurse |
Where-Object { $_.Extension -match "exe|ps1|dll" } |
Get-FileHash -Algorithm SHA256 |
Select-Object Path, Hash
```
# Phase 6 – Lateral Movement Investigation
Goal

Find attempts to pivot from the hypervisor to internal VM workloads.

### SMB & RDP Burst Detection
```kql
DeviceNetworkEvents
| where Protocol in ("SMB","RDP")
| summarize AccessCount = count() by RemoteIP, DeviceName
| where AccessCount > 50
```

### Finding:

- Connection bursts from ESXi to production VMs.

- Access to finance servers not normally managed via hypervisor shell.

# Phase 7 – IOC Extraction
Goal

Prepare threat feed for containment and sharing.

### PowerShell Artifact Extraction
```powershell
Get-FileHash -Path "C:\ProgramData\*.exe"
```

Indicators extracted:

- C2 IP addresses

- Backdoor binary hashes

- Snapshot file names

- Compromised admin accounts

# Phase 8 – Containment Actions
Applied Actions:

✅ Hypervisor isolation from external networks
✅ Forced credential reset for all vCenter administrators
✅ Block C2 IPs at firewall & WAF
✅ Disable snapshot-permission roles except for backup service
✅ Rebuild affected hypervisor nodes

# Phase 9 – Timeline Reconstruction
Key Events
Time	Observed Event
T0	DNS beacon seen from ESXi host
T1	Unusual admin authentication from foreign IP
T2	VM snapshot creation across sensitive workloads
T3	PowerShell artifacts identified
T4	Lateral connections to internal VMs
T5	ESXi isolation and credential resets initiated
# Phase 10 – Final SOC Incident Report
Report Sections:

- Executive Summary

- Attack Vector Analysis

- Affected Assets

- Threat Attribution: BRICKSTORM

- IOC Lists

- Detection Queries

- Containment and Recovery Actions

- Recommendations

### Key Recommendations

- Restrict hypervisor internet access

- Enforce MFA for all virtualization admins

- Monitor snapshot creation via SIEM

- Deploy EDR or telemetry collectors to ESXi management zones

## Detection Coverage Mapping – BRICKSTORM Hypervisor Intrusion

| Detection Logic | ATT&CK Technique | Technique ID | Description |
|------------------|------------------|----------------|----------------|
| Abnormal DoH beaconing from ESXi hosts | Application Layer Protocol: DNS | T1071.004 | Detects encrypted outbound DNS-over-HTTPS communication from hypervisor management interfaces, consistent with C2 beaconing behavior. |
| Unapproved external HTTPS connections from vSphere services | Application Layer Protocol: Web | T1071.001 | Flags sustained HTTPS sessions from ESXi or vCenter services to untrusted IP ranges indicating possible command-and-control traffic. |
| Unauthorized vCenter administrative logins | Valid Accounts | T1078 | Identifies successful use of compromised or brute-forced administrator credentials outside approved geographic locations and business hours. |
| Snapshot creation outside maintenance windows | Virtualization/SaaS: Snapshot Abuse | T1526 | Detects attackers abusing snapshot functionality to extract VM disk images, harvest credentials, or stage payload persistence. |
| Snapshot downloads to unmanaged endpoints | Exfiltration Over C2 Channel | T1041 | Monitors outbound data transfers associated with snapshot export workflows and abnormal download activity tied to suspicious network destinations. |
| Payload staging within guest VM directories | Tool Transfer | T1105 | Detects delivery of backdoor binaries and scripts staged inside production VM file systems to establish persistence and enable lateral access. |
| ESXi-to-VM lateral movement via administrative protocols | Lateral Tool Transfer | T1570 | Detects internal SMB and RDP bursts initiated from compromised hypervisors attempting to pivot into guest workloads. |
| Abnormal execution of remote administrative commands | Remote Services | T1021 | Flags suspicious command execution on multiple VMs initiated from the hypervisor management zone indicating coordinated lateral movement. |
| Sustained encrypted sessions to low-reputation IP ranges | Command and Control | T1071 | Correlates long-duration encrypted network sessions associated with known BRICKSTORM infrastructure patterns used for remote tasking. |
| Repeated failed and successful admin authentications | Brute Force | T1110 | Detects credential stuffing and password-guessing activity targeting ESXi and vCenter accounts preceding initial compromise. |

