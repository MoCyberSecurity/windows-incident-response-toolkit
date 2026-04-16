# Post-Authentication Identity Abuse Detections

Detection engineering content for identifying post-authentication identity abuse across Microsoft 365, Splunk, Microsoft Sentinel (KQL), and AWS.

---

## Overview

This repository focuses on a common but under-detected attack pattern:

> The attacker is already authenticated and begins abusing legitimate access.

In these scenarios, authentication succeeds, controls appear to function correctly, and the attacker operates within trusted boundaries. Traditional detections focused on failed logins or unauthorised access provide limited value.

The detection surface shifts to **post-authentication behaviour**.

---

## Detection Focus

The detections in this repository are designed to identify:

- Mailbox control abuse (inbox rules, forwarding, concealment)
- Suspicious sequences following successful authentication
- Behavioural deviations in mailbox access patterns
- Identity persistence and expansion into cloud environments (AWS)

The goal is to move from isolated alerts to **correlated detection of attack behaviour**.

---

## Core Detection Model

All detections are built around a simple correlation chain:
Identity anomaly → Mailbox control change → Behavioural deviation → Persistence / expansion


Individually, these signals may be low confidence.  
Correlated together, they represent a high-confidence indicator of identity compromise.

---

## Repository Structure


detections/
├── splunk/
├── sentinel/
└── aws/

correlations/
mappings/
tuning/
playbooks


---

## Detection Coverage

### Mailbox Control Abuse
- Inbox rule creation and modification
- Suspicious forwarding configuration
- Message concealment patterns

### Identity and Session Context
- Risky or anomalous successful sign-ins
- Unusual device, IP, or session behaviour

### Behavioural Indicators
- Unusual mailbox access patterns
- Spike in interaction volume
- Access to finance or sensitive communication threads

### Cloud Identity Activity (AWS)
- Access key creation (`CreateAccessKey`)
- Suspicious role assumption (`AssumeRole`)
- Discovery and enumeration API activity spikes

---

## Correlation Approach

This repository prioritises **signal correlation over single-event detection**.

Example:

- A successful but anomalous sign-in  
- followed by inbox rule creation  
- followed by unusual mailbox access  

This sequence is treated as a single detection scenario rather than three unrelated alerts.

---

## Usage

Each detection file is designed to be:

- Platform-specific (Splunk, Sentinel, AWS)
- Focused on a single behaviour
- Ready for adaptation into production SIEM rules

Correlation logic should be implemented at the SIEM or SOAR level using:
- time-bound joins
- entity normalisation (user, IP, session, ARN)
- risk scoring or rule chaining

---

## Assumptions

These detections assume:

- Microsoft 365 audit logging is enabled
- Entra ID / sign-in logs are available
- AWS CloudTrail logging is configured
- Logs are ingested into the respective SIEM platforms

---

## Limitations

- Behavioural detections require baseline understanding of user activity
- False positives may occur in high-volume or operational accounts
- Correlation logic must be tuned to the organisation’s environment

---

## Next Steps

- Expand correlation rules across platforms
- Add risk scoring and prioritisation
- Integrate with response playbooks
- Enrich detections with threat intelligence where applicable

---

## Key Principle

> Authentication is not a reliable security boundary.

Detection must continue after access is granted.
