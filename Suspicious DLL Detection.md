# Suspicious DLL Detection

This repository is part of the **Windows Incident Response Toolkit** and provides tools and techniques to detect suspicious or malicious DLLs on Windows systems using native commands and scripting methods.

## Overview

Dynamic Link Libraries (DLLs) are commonly used to extend Windows functionality, but they can also be abused by attackers to execute malicious code, inject into processes, or persist on a system. Detecting suspicious DLLs is a crucial step in incident response and threat hunting.

This repository focuses on identifying DLLs loaded via unusual methods such as:

- **`Add-Type`** in PowerShell  
- **`DllImport`** in .NET applications  
- **`DefineMethod`** or runtime-generated methods  
- Other suspicious techniques used to load code dynamically  

## Detection Techniques via Windows CMD / PowerShell

Here are some methods to detect suspicious DLLs:

### 1. Using PowerShell `Add-Type`

`Add-Type` allows scripts to compile and load C# code on the fly. Attackers can abuse this to load malicious DLLs:


```powershell
# List loaded assemblies
[AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object {
    $_.Location
}
```

### 2. Monitoring DLL Import

`DllImport` is an attribute in .NET that allows managed code to call functions from unmanaged DLLs. While commonly used by legitimate applications, it can be leveraged by attackers to:

- Load malicious DLLs dynamically  
- Execute code in memory without writing to disk  
- Bypass traditional antivirus and monitoring tools
```powershell
# List all DLLs loaded by all running processes
Get-Process | ForEach-Object {
    $_.Modules | Select-Object ModuleName, FileName
}
```
### 3. Detect Dynamic Assemblies
`DefineMethod` is part of the .NET `System.Reflection.Emit` namespace. It allows developers—or attackers—to generate methods at runtime, which can:

- Load malicious DLLs directly into memory  
- Execute code without leaving a disk footprint  
- Bypass traditional antivirus and monitoring solutions

Dynamic assemblies often contain runtime-generated methods:

```powershell
# List all dynamic assemblies in the current AppDomain
[AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.IsDynamic }
