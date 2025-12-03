# 🚨 Suspicious DLL Load Detection  
### SIEM Detection – KQL | Splunk | Sigma | MITRE ATT&CK

---

## 1. Detection Objective

Detect **malicious or abnormal DLL loading activity** commonly associated with:

- **DLL Side-Loading**
- **Proxy DLL loading**
- **Hijack Execution Flow**
- **Persistence via Shared Modules**
- **Living-Off-The-Land abuse (LOLbins)**

DLL abuse is highly effective because:

- Windows follows predictable DLL search paths
- Signed binaries often load attacker-controlled DLLs
- Detection can blend with legitimate application behavior

---

---

## 2. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|--------|-------------|----|--------------|
| Execution | Shared Modules | **T1129** | Execution via malicious DLL loading |
| Persistence | DLL Search Order Hijacking | **T1574.001** | Replacement of legitimate DLL dependencies |
| Defense Evasion | Hijack Execution Flow | **T1574** | Proxy DLL loading to evade AV |
| Privilege Escalation | Hijack Execution Flow | **T1574** | Elevated binaries loading rogue DLLs |
| Lateral Movement | Shared Modules | **T1129** | DLL load triggered remotely |

---

---

## 3. High-Risk Detection Indicators

DLL activity becomes suspicious when:

### 📂 Execution Location
DLLs loaded from **user-writable or untrusted directories**:

- `C:\Users\`
- `%AppData%`
- `%Temp%`
- `%Public%`
- `%Downloads%`
- Network shares (`\\`)

---

### ⚠️ Parent Process Anomalies

DLL loaded by shells or LOLbins:

- `powershell.exe`
- `cmd.exe`
- `wscript.exe`
- `cscript.exe`
- `mshta.exe`
- `rundll32.exe`

---

### 🧾 Signing Mismatch

- **Unsigned DLL** loaded by **signed parent binary**
- Certificate chain mismatch

---

### 🪪 Filename Masquerading

System DLL names loaded outside trusted locations:

- `version.dll`
- `wininet.dll`
- `bcrypt.dll`
- `kernel32.dll`
- `cryptbase.dll`

---

---

## 4. Microsoft Sentinel / Defender KQL Queries

---

### 🧠 Detection – DLL Loaded from Writable Directories

```kql
DeviceImageLoadEvents
| where FolderPath has_any (
  "Users\\", "AppData\\", "Temp\\", "Downloads\\", "Public\\"
)
| where FileName endswith ".dll"
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          SHA256
```
## 🧠 Detection - LOLBins Performing DLL Side-Loading

```kql
DeviceImageLoadEvents
| where InitiatingProcessFileName in~ (
  "rundll32.exe","mshta.exe","powershell.exe","cmd.exe","wscript.exe"
)
| where FolderPath !startswith "C:\\Windows\\System32\\"
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName,
          SHA256
```

## 🧠 Detection - Unsigned DLL Loaded by Signed Binary
```kql
DeviceImageLoadEvents
| where IsUnsigned == true
| where InitiatingProcessSignatureStatus == "Signed"
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName,
          SHA256
```
## 🧠 Detection – System DLL Name Loaded Outside System32
```kql
let SYSTEM_DLLS = dynamic([
  "dbghelp.dll","version.dll","wininet.dll",
  "bcrypt.dll","cryptbase.dll","kernel32.dll"
]);

DeviceImageLoadEvents
| where FileName in~ (SYSTEM_DLLS)
| where FolderPath !startswith "C:\\Windows\\System32\\"
| project Timestamp, DeviceName,
          InitiatingProcessFileName,
          FileName,
          FolderPath,
          SHA256
```
## 5. Splunk Detection Queries
## 🔍 DLL Loaded from User-Writable Paths
```kql
index=endpoint ImageLoaded="*.dll"
| search ImageLoaded="*\\Users\\*" OR
         ImageLoaded="*\\Temp\\*" OR
         ImageLoaded="*\\AppData\\*" OR
         ImageLoaded="*\\Downloads\\*"
| table _time host ParentImage ImageLoaded CommandLine SHA256
```
## 🔧 Rundll32 Side-Load Detection
```kql
index=endpoint ParentImage="*rundll32.exe"
ImageLoaded!="*\\Windows\\System32\\*"
| table _time host ParentImage ImageLoaded CommandLine SHA256
```
## Unsigned DLL Triggered by Signed Process
```kql
index=endpoint SignatureStatus="Unsigned"
ParentSignatureStatus="Signed"
| table _time host ParentImage ImageLoaded SHA256
```
## 6. Sima Detection Rule
```yaml
title: Suspicious DLL Loaded From Writable Directory
id: mo-4f21c110-dll-sideload
status: stable
description: >
  Detects DLL loading from user-writable or temporary paths.
  Common in DLL side-loading and execution flow hijacking.
author: MoCyberSecurity
date: 2025-11-30

references:
  - https://attack.mitre.org/techniques/T1574/001/

logsource:
  product: windows
  category: image_load

detection:
  writable_paths:
    ImageLoaded|contains:
      - '\Users\'
      - '\Temp\'
      - '\Downloads\'
      - '\AppData\'

  dll_extension:
    ImageLoaded|endswith: '.dll'

  condition: writable_paths and dll_extension

level: high

tags:
  - attack.t1574.001
  - attack.defense_evasion
  - detection.dll_sideloading
```
## 7. SOC Analyst Triage Workflow
✅ Step 1 — Validate Load Location

Was the DLL loaded from a legitimate vendor directory?

Does the parent binary normally load this module?

✅ Step 2 — Review Process Lineage

Parent fired by Office or browser?

Involved LOLbins or script engines?

Elevated token presence?

✅ Step 3 — Reputation Analysis

Check SHA256 on VirusTotal / Hybrid-Analysis

Verify digital signature & certificate trust chain

✅ Step 4 — Host Investigation

File creation events for DLL drop

Registry autoruns or services for persistence

Network connections following execution

Lateral movement evidence

✅ Step 5 — Response Actions

Isolate device via EDR

Quarantine DLL and parent binary

Block hashes exposure-wide

Credential reset if compromise confirmed

## 8. False Positive Tuning

Expected benign triggers:

Software installers and updaters

Electron & app extensions in %AppData%

Internally developed business applications

Filtering strategies:

Maintain vendor DLL allowlists

Exclude trusted signed hashes

Limit to abnormal parent + anomalous path combinations

## 9. Detection Coverage Summary
# 9. Detection Coverage Summary

This section maps each detection logic to the corresponding MITRE ATT&CK technique, providing clear coverage for SOC analysts.

| Detection Logic | ATT&CK Technique | Technique ID | Description |
|-----------------|-----------------|--------------|-------------|
| User-writable DLL Paths | DLL Search Order Hijacking | **T1574.001** | Detects DLLs loaded from user-writable or temporary directories, often used in side-loading attacks. |
| LOLBins DLL loading | Shared Modules | **T1129** | Detects abnormal DLL loads by living-off-the-land binaries like rundll32.exe, mshta.exe, powershell.exe, etc. |
| Signed binary loading unsigned DLL | Hijack Execution Flow | **T1574** | Detects unsigned DLLs loaded by signed binaries to evade defenses. |
| DLL filename masquerading | DLL Search Order Hijacking | **T1574.001** | Detects system DLL names loaded from non-standard locations, a common persistence or evasion technique. |

---

### Notes:

- This summary helps map detection rules to MITRE ATT&CK for reporting and SOC alignment.
- Ensures coverage across **Execution, Persistence, Defense Evasion, and Lateral Movement** tactics.
- Supports both technical investigations and management reporting for security operations.
