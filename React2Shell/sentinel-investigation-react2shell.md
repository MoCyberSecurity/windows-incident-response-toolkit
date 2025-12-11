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

## 4. Triage Workflow

## 5. Evidence Pack (Log Samples)

## 6. Analyst Decision Tree

## 7. Containment & Eradication

## 8. Lessons Learned & Preventive Controls
