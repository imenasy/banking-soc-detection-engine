# Tier-1 SOC Alert Triage & Escalation SLA Matrix

## 1. Objective
Establish standard triage procedures and strict Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR) service levels for the 3 Security Operations Centre Analysts under the supervision of the Senior Manager.

## 2. SLA Tiers & Operational Escalation

| Severity | Description / Event Type | Max Triage Time (MTTD) | Max Escalation Time | Assigned Responder | Notification Channels |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **P1 - Critical** | Direct Core Banking DB alteration, RIPPS clearing injection, Active Ransomware beacon | $\le$ 5 minutes | 15 minutes | Tier-2 Incident Commander / Senior Manager CyberSec | SMS, Automated Call, Dedicated Telegram Alert Channel |
| **P2 - High** | Repeated privileged account lockouts, WAF SQLi bursts, Forcepoint DLP exfiltration | $\le$ 15 minutes | 30 minutes | SOC Analyst On-Duty | SOC Dashboard, Email Urgent, Teams/Slack SecOps Channel |
| **P3 - Medium** | Vulnerability scanner activity, internal unauthorized port scanning, expired TLS cert | $\le$ 60 minutes | 4 hours | SOC Analyst Rotating Shift | Ticketing System (Jira/ServiceNow) |
| **P4 - Low** | Routine audit log alerts, isolated endpoint policy violation | $\le$ 4 hours | 24 hours | SOC Analyst Junior | Daily Operational Digest |

## 3. Tier-1 Investigation Checklist
1. Validate alert authenticity against recent scheduled infrastructure maintenance or deployment tickets.
2. Enrich source IP/User with Active Directory and VPN logs.
3. Check target system criticality (CBS, RIPPS gateway, D-SACCO branch edge firewall).
4. If True Positive (P1/P2): Immediately invoke `csirt-incident-response-playbooks`.
