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
### Detection Logic (Splunk)

```kusto
index=endpoint
| search process_name="mshta.exe"
| search process_command_line="*http://*" OR process_command_line="*https://*" OR process_command_line="*.hta*"
| table _time host user process_name process_command_line parent_process_name

```

### Investigation Workflow
### Step 1 – Validate Initial Trigger

Confirm:

- mshta.exe launched by browser context or user session

- Command-line references to remote .hta payload or obfuscated URLs

- Parent processes related to browser activity or HTML execution

### Step 2 – Correlate Browser Telemetry

Objective:

- Identify **recent browsing activity** to potentially compromised websites preceding execution
- Extract suspicious iFrame or script execution patterns where logs are available

---

**KQL Sample:**

```kusto
DeviceNetworkEvents
| where DeviceName == "<Affected-Host>"
| where RemoteUrl !contains "known_safe_domain"
| where Timestamp between (ago(30m)..now())
```

**SPL Sample:**
```
index=endpoint
| search host="<Affected-Host>"
| where NOT like(RemoteUrl, "%known_safe_domain%")
| where _time >= relative_time(now(), "-30m")

```
### Step 3 – Detect PowerShell Stager Execution

Analyse PowerShell command-lines for:

- `Invoke-Expression (IEX)`
- `DownloadString`
- `Invoke-WebRequest`
- Base64 or gzip encoded payload delivery

---

**KQL Query:**

```kusto
DeviceProcessEvents
| where FileName in ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine contains "DownloadString"
   or ProcessCommandLine contains "Invoke-WebRequest"
   or ProcessCommandLine contains "IEX"
```
**SPL Query:**

```
index=endpoint
| search process_name IN ("powershell.exe","pwsh.exe")
| search process_command_line="*DownloadString*"
    OR process_command_line="*Invoke-WebRequest*"
    OR process_command_line="*IEX*"
```
### Step 4 – NetSupport RAT Artefact Detection

Search for file system indicators and persistence mechanisms related to NetSupport deployments.

---

**KQL Example:**

```kusto
DeviceFileEvents
| where FolderPath contains "ProgramData\\NetSupport"
   or FileName == "winsvcmgr.exe"
```
**SPL Example:**
```
index=wineventlog EventCode=4663
| search Object_Name="*\\ProgramData\\NetSupport\\*" OR Object_Name="*\\winsvcmgr.exe"

```

Persistence hunting:

**KQL:**
```
DeviceRegistryEvents
| where RegistryKey contains "Run"
| where RegistryValueData contains "NetSupport"
```
**SPL:**
```
index=wineventlog EventCode=4657 OR EventCode=4663
| search Object_Name="*\\Run\\*" AND Object_Value="*NetSupport*"
| table _time, ComputerName, Subject_User_Name, Object_Name, Object_Value

```
### Step 5 – Network Command-and-Control Validation

Inspect outbound sessions from the endpoint for:

- Rare or newly registered domains  
- Dynamic DNS patterns  
- Encrypted sessions to unknown IPs  
- Geographically anomalous C2 destinations

---
**KQL**
```kusto
DeviceNetworkEvents
| where DeviceName == "<Affected-Host>"
| where RemotePort == 443
| where not(RemoteUrl contains "trusted_provider")
```
**SPL**
```
index=wineventlog EventCode=5156
| where ComputerName="<Affected-Host>" AND Dest_Port=443
| where NOT like(Dest_Host,"*trusted_provider*")
| table _time, ComputerName, Application_Name, Dest_IP, Dest_Host, Dest_Port
```
### Step 6 – Incident Enrichment

In Microsoft Sentinel:

- Link entity relationships:
  - User account
  - Infected device
  - Malicious domain/IP
  - Executed processes
- Visualize chain: **Browser → mshta.exe → PowerShell → NetSupport RAT → C2**


In Splunk:

- Link entity relationships:
  - **User account:** `Subject_User_Name`
  - **Infected device:** `ComputerName`
  - **Malicious domain/IP:** `Dest_IP`, `Dest_Host`
  - **Executed processes:** `New_Process_Name`, `Parent_Process_Name`

- Visualize chain: **Browser → mshta.exe → PowerShell → NetSupport RAT → C2**

```spl
(index=wineventlog EventCode=4688 | search New_Process_Name="*mshta.exe" OR New_Process_Name="*powershell.exe" OR New_Process_Name="*pwsh.exe")
 OR
(index=wineventlog EventCode=5156 Dest_Port=443)
| table _time, ComputerName, Subject_User_Name, New_Process_Name, Parent_Process_Name, Dest_IP, Dest_Host
| sort _time
```
---
---

### Step 7 – Containment Actions

SOC analyst response:

- Immediately isolate affected endpoint

- Kill malicious PowerShell and RAT processes

- Block identified attacker domains/IPs

- Remove registry persistence entries

- Reset impacted user credentials

- Scoped hunting for lateral movement

### Adversary Tradecraft Summary
Kill Chain

1. Initial Access: Compromised website + obfuscated JavaScript loader

2. Execution: HTA launched using mshta.exe

3. Payload Delivery: PowerShell stager downloads RAT

4. Persistence: Registry run-keys or scheduled task creation

5. C2: Encrypted HTTPS sessions to external servers

6. Impact: Full remote access, surveillance, and credential theft

## MITRE ATT&CK Mapping

| Phase           | Technique              | ID        | Description                                   |
|-----------------|-------------------------|-----------|-----------------------------------------------|
| Initial Access  | Drive-by Compromise    | T1189     | Malicious JavaScript loader via compromised site |
| Execution       | Mshta LOLBin            | T1218.005 | HTA execution via system binary |
| Execution       | PowerShell              | T1059.001 | Stager execution and payload loader |
| Command & Control | Ingress Tool Transfer | T1105     | Download RAT from attacker infrastructure |
| Persistence     | Registry Run Keys       | T1547.001 | Auto-start execution |
| Remote Control  | Remote Access Software | T1219     | NetSupport RAT deployment |
| C2               | Encrypted Channel     | T1573     | RAT beaconing over HTTPS |

