🔍 PowerShell 4104 Detection Toolkit
Script Block Logging • Suspicious Keywords • Incident Response

This toolkit provides a practical, investigation-ready reference for detecting malicious PowerShell activity using Event ID 4104 — Script Block Logging. It includes the suspicious keyword list, detection queries, and real example script blocks used by attackers.

🛡 Why This Toolkit Exists

PowerShell is widely abused by threat actors. Fortunately, Windows has a built-in safety mechanism:

✔ PowerShell automatically logs certain suspicious script blocks
✔ Event ID 4104 (Level 3 — Warning) is generated
✔ This happens even if Script Block Logging is disabled via GPO
✔ Supported in PowerShell 5+ and PowerShell 7

This gives defenders visibility even in restricted environments.

📂 Toolkit Structure
powershell-4104-detection-toolkit/
│
├── README.md
├── suspicious-keywords.txt
├── queries/
└── examples/

🔥 Suspicious PowerShell Keywords (Why 4104 Triggers)

PowerShell maintains an internal list of high-risk keywords often associated with:

Malware execution

Memory injection

Reflection / assembly loading

Obfuscation

Downloaded payloads

Credential theft

Examples of trigger keywords:

Add-Type

DllImport

DefineMethod

VirtualAlloc

FromBase64String

Reflection

GetProcAddress

When any of these appear in a script block, Windows will log:

Event ID 4104 — Script Block Logging (Warning)

The full keyword list is included in:
suspicious-keywords.txt

📡 Where to Find PowerShell 4104 Logs

Event Viewer Path:

Applications and Services Logs
  → Microsoft
      → Windows
          → PowerShell
              → Operational

🕵️ What 4104 Logs Contain

4104 logs reveal:

The entire decoded script block

User executing the command

Hostname and process information

Suspicious keyword used

Whether the script was obfuscated

Network activity (in some cases)

This makes it one of the best sources for detecting malicious PowerShell usage.

🧪 Detection Use Cases

This toolkit helps detect:

Encoded commands (-enc)

Base64 payloads

AMSI bypass attempts

Reflective PE/assembly loading

Living-off-the-land command execution

Malware loaders using PowerShell

Credential dumping attempts

Download cradle behaviour (IEX, Invoke-WebRequest)

💻 Example Threat Behaviours (Included in /examples)

You will find real-world style script blocks demonstrating:

Malicious payload execution

Obfuscated PowerShell

DLL injection patterns

Mimikatz-like behaviours

Fileless malware execution

PowerShell-based C2 communication

Each example includes notes explaining why it triggers event 4104.

📊 Detection Queries (Included in /queries)

Provided in:

KQL (MDE / Sentinel)

Sigma rule format

Splunk SPL

Elastic Query DSL

Queries include detection for:

Suspicious keywords

Encoded commands

Fileless attack TTPs

Obfuscated PowerShell tokens

Known attacker techniques

🧰 How to Use This Toolkit
Incident Response

Pull 4104 logs from compromised hosts

Identify malicious script blocks

Map behaviours to MITRE ATT&CK

Threat Hunting

Hunt for suspicious keyword frequency

Track encoded or obfuscated commands

Correlate PowerShell activity with network events

Detection Engineering

Build/modify SIEM alerts

Create behaviour-based detection rules

Enrich logs using keyword triggers
