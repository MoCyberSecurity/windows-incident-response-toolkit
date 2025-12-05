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
