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

## 3. Detection Logic (KQL + Splunk SPL)

## 4. Triage Workflow

## 5. Evidence Pack (Log Samples)

## 6. Analyst Decision Tree

## 7. Containment & Eradication

## 8. Lessons Learned & Preventive Controls
