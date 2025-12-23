🛡️ Wazuh SIEM Homelab – Security Monitoring & Compliance
Overview

This project documents the deployment and validation of a self-hosted Wazuh SIEM in a homelab environment. The lab focuses on host-based intrusion detection, security event monitoring, compliance auditing, and MITRE ATT&CK–aligned alert analysis using real system activity.

The goal is to demonstrate practical blue-team skills, including SIEM setup, agent management, alert triage, and security baseline validation.

---

Architecture

# 🛡️ Wazuh SIEM Homelab – Security Monitoring & Compliance

## Overview

This project documents the deployment and validation of a **self-hosted Wazuh SIEM** in a homelab environment. The lab focuses on **host-based intrusion detection**, **security event monitoring**, **compliance auditing**, and **MITRE ATT&CK–aligned alert analysis** using real system activity.

The goal is to demonstrate **practical blue-team skills**, including SIEM setup, agent management, alert triage, and security baseline validation.

---

## Architecture

**Single-node Wazuh deployment** with an enrolled Linux agent:

- Wazuh Manager
- Wazuh Indexer (OpenSearch)
- Wazuh Dashboard
- Wazuh Agent (Ubuntu host)

All components are self-hosted on internal infrastructure with no managed cloud services.

---

## Environment Details

| Component | Details |
|---------|--------|
| SIEM | Wazuh 4.14.1 |
| Manager OS | Ubuntu Server |
| Agent OS | Ubuntu 24.04 LTS |
| Agent Name | `homelab-01` |
| Network | Private LAN |
| Access | HTTPS (Dashboard) |

---

## Features Implemented

### 🔍 Security Event Monitoring
- PAM authentication events
- Privilege escalation detection (`sudo`)
- System login/session tracking
- Rootcheck (host-based anomaly detection)

### 📊 Compliance & Hardening
- CIS Ubuntu Linux 24.04 Benchmark
- Security Configuration Assessment (SCA)
- PCI DSS control mapping
- Continuous baseline validation

### 🧠 Threat Detection Frameworks
- MITRE ATT&CK technique mapping
- Rule-based alert severity levels
- Alert grouping and correlation

---

## Alert Validation Results

### Summary (24-hour window)

- **Total alerts:** 336
- **High severity alerts (≥12):** 0
- **Authentication failures:** 0
- **Authentication successes:** 9
- **Rootcheck detections:** Present
- **Compliance scans:** Successful

This confirms:
- Stable system behavior
- No brute-force or intrusion attempts
- Proper logging and detection coverage

---

## Sample Alerts Observed

### PAM Authentication Events
- Login session opened / closed
- Successful privilege escalation to root

**MITRE ATT&CK:**
- T1078 – Valid Accounts
- Privilege Escalation
- Initial Access

### Rootcheck (Host-Based Anomaly Detection)
- Baseline integrity scans
- System anomaly indicators
- No confirmed malicious persistence

### SELinux / Audit Events
- Policy and permission checks detected
- Audit framework successfully parsed

---

## SOC-Style Alert Analysis

Each alert was reviewed using a basic SOC triage approach:

1. Identify alert type and severity
2. Check authentication context
3. Correlate with other alerts
4. Determine benign vs suspicious behavior
5. Document findings

All observed alerts were determined to be **expected administrative or baseline activity**, demonstrating correct SIEM tuning and deployment.

---

## Key Takeaways

- Successfully deployed a production-style SIEM
- Validated agent enrollment and telemetry flow
- Demonstrated real security event ingestion
- Performed compliance and hardening assessments
- Practiced alert analysis using industry frameworks

This project reflects **entry-level SOC analyst / security engineer** responsibilities rather than a simulated lab.

---

## Next Enhancements

Planned improvements:
- Simulated attack scenarios (brute force, persistence)
- Custom Wazuh rules
- Multiple agents and OS diversity
- Centralized log ingestion (syslog)
- Firewall and network telemetry integration

---

## Skills Demonstrated

- SIEM deployment & management
- Linux system hardening
- Security monitoring & alert triage
- Compliance auditing (CIS, PCI DSS)
- MITRE ATT&CK mapping
- Blue-team operational workflows

---

## Disclaimer

This project is for **educational and defensive security purposes only**.
No production systems were exposed or attacked.
