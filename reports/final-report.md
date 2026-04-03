# Windows 11 STIG Remediation — Final Report

---

## Executive Summary

This project demonstrates the end-to-end remediation of Windows 11 DISA STIG findings using PowerShell automation and Tenable vulnerability scans.

Across **6 iterative scans**, multiple security controls were implemented, validated, and documented. The project highlights both successful remediation workflows and real-world operational challenges encountered during security hardening.

---

## Environment

- **Operating System:** Windows 11 (Virtual Machine)
- **Scanner:** Tenable (Authenticated Scans)
- **Methodology:** Iterative remediation + validation
- **Automation:** PowerShell (Verify / Apply / Rollback modes)

---

## Scan Progression

```text
Scan 1 — Baseline
Scan 2 — Secondary Logon Remediation
Scan 3 — Lock Screen Remediation (Initial)
Scan 4 — Lock Screen Remediation (Refined)
Scan 5 — Account Lockout Policy
Scan 6 — Password Policy (Final Validation)
```

Each scan reflects incremental improvements based on targeted remediation efforts.

---

## Remediation Scope

### Primary Controls Remediated

- **Secondary Logon Service**
- **Lock Screen Hardening**
- **Account Lockout Policy**
- **Password Policy**

### Additional Observations

- **WN11-00-000160** was in a *Warning* state during baseline and later validated through policy enforcement
- **SMBv1-related STIGs** were resolved indirectly through system configuration changes
- **Windows Firewall STIG** was implemented but rolled back due to operational impact

---

## Key Remediation Highlights

### 1. Secondary Logon Service

- Disabled insecure service (`seclogon`)
- Validated via Tenable scan transition to compliant state

---

### 2. Lock Screen Hardening

- Initial remediation resulted in partial compliance (*Warning*)
- Refined configuration achieved full compliance (*Passed*)
- Demonstrates iterative tuning approach

---

### 3. Account Lockout Policy

- Configured lockout threshold, duration, and reset counters
- Remediated multiple STIGs as a grouped policy

---

### 4. Password Policy

- Enforced complexity, history, and minimum length
- Validated through final scan results

---

### 5. SMBv1 (Indirect Remediation)

- No direct script applied
- Related STIG findings resolved through broader system hardening
- Demonstrates dependency-based remediation behavior

---

## Windows Firewall — Implementation & Rollback

### Objective

Enable Windows Firewall in compliance with STIG requirements.

---

### Actions Taken

- Implemented firewall enforcement via PowerShell script
- Configured supporting rules:
  - Windows Management Instrumentation (WMI)
  - File and Printer Sharing
  - Remote Event Log Management

---

### Observed Issue

After applying the firewall configuration:

- Tenable authenticated scans completed abnormally fast
- The **Audits** tab disappeared
- Scan data was incomplete or missing

---

### Troubleshooting

- Verified firewall rules required for authenticated scanning
- Adjusted script to allow necessary services
- Re-ran scans after modifications

---

### Outcome

- Issue persisted despite configuration adjustments
- Firewall was **rolled back to its original state (disabled)**

---

### Conclusion

- The control was technically implemented and validated at the OS level
- However, it negatively impacted scan reliability
- A rollback decision was made to preserve assessment integrity

---

## Validation Approach

Each remediation followed a structured validation model:

1. **Verify (Pre-State)**
2. **Apply (Remediation)**
3. **Validate (Post-Scan)**
4. **Rollback (if necessary)**

Evidence includes:

- Tenable scan results (before/after)
- Script execution outputs
- OS-level validation (for firewall)

---

## Key Lessons Learned

### 1. Security vs. Operations Trade-off

Implementing security controls can disrupt monitoring and scanning tools.  
Balance between compliance and operational visibility is critical.

---

### 2. Iterative Remediation is Essential

Some controls require multiple passes to achieve full compliance.

---

### 3. Group Policy Dependencies Matter

Multiple STIGs can be resolved through a single policy configuration.

---

### 4. Indirect Remediation Effects

System-wide changes can resolve unrelated findings (e.g., SMBv1).

---

### 5. Rollback is a Valid Security Decision

Not all technically correct implementations are operationally viable.

---

## Final Status

| Control Area | Status |
|---|---|
| Secondary Logon | ✅ Remediated |
| Lock Screen | ✅ Remediated |
| Account Lockout | ✅ Remediated |
| Password Policy | ✅ Remediated |
| SMBv1 | ✅ Indirectly Remediated |
| Windows Firewall | ⚠️ Implemented → Rolled Back |

---

## Conclusion

This project demonstrates practical experience in:

- vulnerability remediation workflows
- STIG compliance implementation
- PowerShell-based automation
- security validation using Tenable
- troubleshooting real-world configuration issues

It reflects a realistic security engineering process, including both successful implementations and controlled rollbacks based on observed system impact.

---
