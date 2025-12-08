# Suspicious / Risky OAuth/API Access Behavior Detection

## Summary  
Detect anomalous or risky behavior associated with OAuth-based API access by third-party contractors/mobile-app clients. This includes over-privileged token use, token replay / reuse, unauthorized API function calls, and access post-contract termination.  

## Data Sources  

| Source | Description / What to log |
|--------|--------------------------|
| API Gateway / Reverse Proxy logs (e.g. NGINX + access log, AWS API Gateway, Azure API Management) | Must log client identifier (client_id), OAuth token identifier or hash, timestamp, endpoint/path, HTTP method, response code, authenticated user/contractor ID, IP address, user-agent. |
| Identity Provider / OAuth server logs | Token issuance / refresh events, token revocation events, client registration/deregistration, scope granted, token validity period, client metadata (app name, contractor name, expiration date). |
| Application / backend API logs (business logic) | User context, action performed, object/resource accessed (record ID, tenant/customer ID), success/failure, authorization context (which scope was used), if available. |
| SIEM logs / aggregated logs (after ingestion) | All above logs normalized for correlation across systems. |

## Detection Rules / Use-Cases

# Splunk Detection – OAuth / API Abuse (Quick Guide)

## Objective
Detect suspicious OAuth token usage and third-party API abuse related to:
- Excessive scopes
- Token replay/reuse
- Unauthorized endpoint access
- Orphaned contractor clients

---

## Required Data

- **API Gateway logs:** client_id, token_hash, endpoint, IP, user_agent  
- **OAuth / IdP logs:** token_issued, token_revoked, scopes_granted  
- **Client inventory lookup:** client_id, allowed_scopes, allowed_endpoints, contract_status, contract_end_date

---

## Key Splunk Detections

---

### Excessive OAuth Scopes
```Splunk
index=oauth_logs event_type="token_issued"
| lookup ContractorInventory client_id OUTPUT allowed_scopes
| where NOT like(scopes_granted, "%" . allowed_scopes . "%")
```
### Detects: Over-privileged tokens.

Token Replay / Multi-Origin Use
```Splunk
Copy code
index=api_gateway_logs
| stats dc(ip_address) AS ip_count dc(user_agent) AS ua_count by token_hash
| where ip_count > 1 OR ua_count > 1
```
### Detects: Stolen or reused tokens.

Unauthorised Endpoint Access
```splunk
Copy code
index=api_gateway_logs
| lookup ContractorInventory client_id OUTPUT allowed_endpoints
| where NOT like(endpoint, "%" . allowed_endpoints . "%")
```
### Detects: Broken function-level authorization.

Orphaned Client Activity
```splunk
Copy code
index=api_gateway_logs
| lookup ContractorInventory client_id OUTPUT contract_status contract_end_date
| where contract_status="terminated" OR _time > contract_end_date
```
### Detects: API activity after contractor offboarding.

Token Use After Revocation
```splunk
Copy code
index=api_gateway_logs
| lookup RevokedTokens token_hash OUTPUT revocation_time
| where _time > revocation_time
```
### Detects: Failed token invalidation.

## SOC Triage
1. Identify client_id and check contractor status.

2. Review issued scopes vs role baseline.

3. Validate IP/device behavior for replay indicators.

4. Confirm endpoint or tenant access violations.

5. Revoke tokens, disable clients, escalate incidents if required.
## Severity Guide

| Detection | Severity |
|-----------|------------|
| Revoked token use | Critical |
| Orphaned client activity | Critical |
| Token replay | High |
| Unauthorized endpoints | High |
| Excessive scopes | High |


