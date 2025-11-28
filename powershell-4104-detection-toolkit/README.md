# PowerShell Script Block Logging & Suspicious Keyword Detection

This repository provides educational resources and examples for understanding **PowerShell Script Block Logging** and detecting **suspicious keywords** in scripts.

# 🔍 Incident Response & Threat Hunting Resources

Welcome to this repository! This collection focuses on **PowerShell**, **Sysmon**, and **KQL (Kusto Query Language)** techniques for **incident response**, **threat detection**, and **forensics**.

---

## 📌 Overview

This repo contains:

- ✅ **PowerShell Scripts** for detecting suspicious activities and automating IR tasks.
- ✅ **Sysmon Configurations** for advanced Windows event monitoring.
- ✅ **KQL Queries** for analyzing logs in Microsoft Sentinel or Azure Monitor.

---

## 📂 Contents

### 1. **PowerShell for Incident Response**
- [Suspicious Keywords & Event ID 4104 Detection](powershell-suspicious-keywords.md)
- [PowerShell Logging & Script Block Analysis](powershell-logging-guide.md)

### 2. **Sysmon**
- [Sysmon Configuration for Threat Hunting](sysmon-config.md)
- [Event IDs & Detection Use Cases](sysmon-event-guide.md)

### 3. **KQL Queries**
- [KQL for Sysmon Logs](kql-sysmon.md)
- [KQL for PowerShell Events](kql-powershell.md)

---

## ⚠️ Why This Matters
- **Event ID 4104**: Detect suspicious PowerShell script blocks even if logging is disabled.
- **Sysmon**: Provides granular visibility into process creation, network connections, and file changes.
- **KQL**: Enables powerful log analysis in cloud SIEM environments.

---

## 🔗 Additional Resources
- [Microsoft Sysmon Documentation](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [KQL Reference](https://learn.microsoft.com/azure/data-explorer/kusto/query/)
- [PowerShell Security Best Practices](https://learn.microsoft.com/powershell/security/overview)

---

## ✅ How to Use
Clone the repo and explore each section:

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
```

---

## 📬 Contributions
Feel free to submit **pull requests** or open **issues** for improvements and new detection ideas.

