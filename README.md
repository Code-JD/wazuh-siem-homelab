# Wazuh SIEM Home Lab

## Overview
This project documents the deployment and validation of a Wazuh-based Security Information and Event Management (SIEM) platform in a home lab environment. The goal was to gain hands-on experience with host-based intrusion detection, compliance monitoring, and security event analysis without relying on cloud-managed services.

The lab demonstrates agent enrollment, real-time telemetry ingestion, CIS benchmark scanning, and MITRE ATT&CK-aligned detection.

---

## Architecture

- **Wazuh Manager**
  - Role: Centralized log analysis, rule processing, compliance evaluation
  - OS: Ubuntu Server
  - Services: Wazuh Manager, Indexer, Dashboard

- **Wazuh Agent**
  - Hostname: `homelab-01`
  - OS: Ubuntu 24.04 LTS
  - Function: Log collection, file integrity monitoring, system auditing

- **Network**
  - Local LAN deployment
  - Agent-to-manager encrypted communication
  - No external cloud dependencies

---

## Implemented Capabilities

### Security Monitoring
- Host-based intrusion detection
- Log analysis and normalization
- MITRE ATT&CK technique mapping

### File Integrity Monitoring (FIM)
- Monitoring of sensitive system files
- Detection of unauthorized changes
- Alert generation for privilege escalation indicators

### Compliance & Hardening
- CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0
- Automated Security Configuration Assessment (SCA)
- Baseline scoring and remediation tracking

### Agent Management
- Secure agent enrollment
- Heartbeat monitoring
- Version compatibility enforcement

---

## Validation Results

### Agent Status
- Agent successfully enrolled and active
- Continuous keepalive communication verified
- Dashboard telemetry visible in real time

### CIS Benchmark Results
- Passed: 120
- Failed: 142
- Not applicable: 17
- Initial compliance score: 45%

This baseline reflects a default Ubuntu installation prior to hardening.

---

## Lessons Learned

- Agent enrollment is controlled exclusively by the Wazuh Manager
- Version mismatches between agent and manager prevent registration
- Duplicate agent names are rejected as a security control
- CIS benchmarks provide immediate insight into system hardening gaps
- Local SIEM deployments mirror enterprise SOC tooling patterns

---

## Future Enhancements

- Implement CIS remediation and track score improvement
- Generate custom detection rules
- Add additional monitored endpoints
- Integrate alert response workflows
- Export dashboards for reporting

---

## Skills Demonstrated

- SIEM deployment and configuration
- Linux system security monitoring
- Compliance assessment (CIS benchmarks)
- Security event analysis
- Troubleshooting distributed security systems
