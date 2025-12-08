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

### 1. Excessive Scope Assignment or Over-Privileged Token Issuance  
**Purpose:** Detect when a contractor OAuth client is granted unusually broad or high-privilege scopes (beyond standard expected scopes) — which may indicate risky configuration or attempt to escalate privileges.

**Detection Logic (pseudocode / SIEM query):**  
