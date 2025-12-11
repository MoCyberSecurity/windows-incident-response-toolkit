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

## 5. Evidence Pack (Log Samples)

## 6. Analyst Decision Tree

## 7. Containment & Eradication

## 8. Lessons Learned & Preventive Controls
