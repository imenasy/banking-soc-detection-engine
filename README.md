markdown
# Banking SOC Detection Engine & Telemetry Correlation

Enterprise SIEM/XDR correlation rules, log processing pipelines, and detection logic mapped to the MITRE ATT&CK framework, customized for Core Banking Systems (CBS) and inter-bank transaction switches.

## Architected Capabilities
- Ingestion pipelines for LogRhythm, Exabeam, and Wazuh SIEM engines.
- Detection use cases for unauthorized database balance alterations, mass privilege abuse, and after-hours transaction anomalies.
- Tier 1–3 operational triage escalation workflows mapped to sub-15 minute Mean Time to Detect (MTTD).



*rules/sigma_core_banking_tampering.yml*:

yaml
title: Unauthorized Direct Core Banking Database Modification
id: 8a4c84e1-7d12-4e90-a3bc-d12f3e829a10
status: production
description: Detects direct DML updates to member balances outside the authorized application connection pool.
references:
  - MITRE ATT&CK: T1565.001 (Data Manipulation: Stored Data Manipulation)
author: Sylvain Imena
logsource:
  product: database
  service: audit_log
detection:
  selection:
    sql_statement|contains:
      - 'UPDATE account_balance'
      - 'UPDATE member_ledger'
      - 'DELETE FROM transaction_journal'
  filter_authorized_pool:
    db_user:
      - 'cbs_app_pool'
      - 'batch_settlement_svc'
  condition: selection and not filter_authorized_pool
falsepositives:
  - Emergency break-glass DBA access (must correlate with approved Change Ticket)
level: critical
tags:
  - attack.impact
  - attack.t1565.001
  - compliance.bnr_cybersecurity



---
