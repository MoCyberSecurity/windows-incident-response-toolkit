# 🛡️ Operation Silent Beacon – BRICKSTORM Hypervisor Intrusion

---

## Scenario Overview

A mid-sized cloud services provider begins receiving alerts for **suspicious outbound DNS and HTTPS traffic originating from a VMware ESXi hypervisor host**.  
The affected host is part of the company’s internal virtualization platform and is **not expected to communicate directly with the public internet** except for approved update and management services.

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


# Phase 3: Payload Collection and Analysis

## Objective
Collect and analyze the malicious payloads deployed to understand the attacker’s capabilities and potential impact on the virtual infrastructure.

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
