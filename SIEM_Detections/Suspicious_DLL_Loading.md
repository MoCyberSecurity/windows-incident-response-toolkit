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
## 5. LOLBins Performing DLL Side-Loading

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

