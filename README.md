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
## 🧪 Attack Simulation & Detection Validation

Controlled attack simulations were performed to validate detection coverage and alert generation. All activities were conducted in a closed lab environment for defensive learning purposes.

### Simulation 1: Privilege Escalation via File Modification

**Technique:**
- Unauthorized modification of a protected system file

**Command Executed:**
```
sudo sh -c 'echo "wazuh-fim-test" >> /etc/passwd'
```
---

### ✅ Expected Detection (Simulation 1)
```markdown
**Expected Detection:**
- File Integrity Monitoring (FIM) alert
- Medium to high severity rule
- MITRE ATT&CK mapping to Privilege Escalation
**Observed Result:**
- FIM alert generated successfully
- File path and modification captured
- Agent name and timestamp correctly recorded
- Alert visible in Wazuh dashboard within 60 seconds

### Simulation 2: Privileged Command Execution

**Technique:**
- Valid account privilege escalation using `sudo`
**Observed Detection:**
- PAM authentication event logged
- Successful privilege escalation recorded
- Session open and close events captured
**MITRE ATT&CK Mapping:**
- T1078 – Valid Accounts
- Privilege Escalation
**Analyst Verdict:**
- Expected administrative activity
- Alert correctly classified as low severity
- No escalation required

### Detection Coverage Summary

| Capability                    | Status      |
|------------------------------|-------------|
| File Integrity Monitoring    | ✅ Verified |
| Privilege Escalation Logging | ✅ Verified |
| PAM Session Tracking         | ✅ Verified |
| MITRE ATT&CK Mapping         | ✅ Verified |
| Alert Visibility             | ✅ Verified |


---

## 📘 Lessons Learned

This project surfaced several real-world operational and architectural lessons commonly encountered in SOC and security engineering environments.

### SIEM Architecture & Operations
- Agent enrollment is **manager-authoritative**; agents cannot self-register without cryptographic trust.
- Version compatibility between manager and agents is strictly enforced to prevent protocol mismatch and data integrity issues.
- Duplicate agent identities are rejected by design, requiring explicit cleanup during redeployment or reimaging scenarios.

### Detection & Alerting
- Initial file integrity scans establish a **baseline** and do not generate alerts.
- Alerts are triggered only on **post-baseline changes**, reducing false positives.
- Time range selection in the dashboard is critical when validating detections.

### Security Monitoring
- Not all alerts indicate malicious behavior; many reflect **expected administrative activity**.
- SOC analysis requires correlation across multiple data points, not single alerts.
- Host-based anomaly detection often flags conditions worth investigation but not immediate escalation.

### Compliance & Hardening
- Default Linux installations typically fail a large portion of CIS controls.
- Compliance scanning provides immediate visibility into security posture gaps.
- Hardening efforts should be incremental and tracked over time to measure improvement.

### Troubleshooting & Reliability
- Firewall rules can silently block access even when services are healthy.
- Networking mode (NAT vs bridged) directly impacts service accessibility.
- Logs are the authoritative source of truth when diagnosing SIEM issues.

These lessons mirror real SOC workflows and reinforce the importance of methodical troubleshooting, documentation, and verification.

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

---

