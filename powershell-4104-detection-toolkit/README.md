# PowerShell Script Block Logging & Suspicious Keyword Detection

This repository provides educational resources and examples for understanding **PowerShell Script Block Logging** and detecting **suspicious keywords** in scripts.

---

## Overview

PowerShell includes built-in mechanisms to detect potentially malicious activity in scripts through **Script Block Logging**.

### PowerShell Suspicious Keywords

PowerShell has an internal list of keywords considered suspicious, including:

- `Add-Type`
- `DllImport`
- `DefineMethod`
- `Invoke-Expression (IEX)`
- `New-Object` with `System.Reflection`

These keywords are often associated with advanced or potentially malicious activities like:

- Dynamic code execution  
- Assembly manipulation  
- Post-exploitation activity

---

### Event ID 4104

- When PowerShell detects a suspicious keyword in a script block, it generates **Event ID 4104**.  
- Level 3 (Warning) events are created **even if Script Block Logging is disabled**.  
- Applies to **PowerShell 5 and 7**.  

This provides defenders with **automatic visibility into potentially malicious activity**, regardless of logging configuration.

---

### Security Implications

- Scripts containing suspicious keywords trigger logging, allowing security teams to **detect abnormal behavior**.  
- Event ID 4104 can be monitored in:
