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

- **WN11-00-000160** was in a *Warning* state during baseline and later transitioned to compliant state
- **SMBv1-related STIGs** were resolved indirectly through broader system changes
- **Windows Firewall STIG** was implemented, tested, investigated, and rolled back due to operational impact

---

## Key Remediation Highlights

### 1. Secondary Logon Service

- Disabled insecure service (`seclogon`)
- Validated through script execution and post-remediation scan results

**Evidence:**

- [WN11-00-000175 Before](../evidence/secondary-logon/wn11-00-000175-before.png)  
  → Baseline evidence showing the Secondary Logon STIG in a non-compliant state

- [WN11-00-000175 After](../evidence/secondary-logon/wn11-00-000175-after.png)  
  → Post-remediation evidence showing the STIG transitioned to compliant state

- [Secondary Logon Verify Output](../evidence/secondary-logon/secondarylogon-verify.png)  
  → Script output confirming the current configuration before changes

- [Secondary Logon Apply Output](../evidence/secondary-logon/secondarylogon-apply.png)  
  → Script output showing the remediation being applied successfully

---

### 2. Lock Screen Hardening

- Initial remediation resulted in partial compliance (*Warning*)
- Refined remediation achieved full compliance (*Passed*)
- Demonstrates iterative tuning and policy-backed enforcement

**Evidence:**

- [WN11-CC-000010 Failed](../evidence/lock-screen/wn11-cc-000010-failed.png)  
  → Baseline evidence showing the lock screen slideshow control as failed

- [WN11-CC-000010 Warning](../evidence/lock-screen/wn11-cc-000010-warning.png)  
  → Intermediate scan result showing improvement but not full compliance

- [WN11-CC-000010 Passed](../evidence/lock-screen/wn11-cc-000010-passed.png)  
  → Final evidence showing full compliance after refined remediation

- [WN11-CC-000005 Before](../evidence/lock-screen/wn11-cc-000005-before.png)  
  → Baseline evidence for the lock screen camera-related control

- [WN11-CC-000005 After](../evidence/lock-screen/wn11-cc-000005-after.png)  
  → Post-remediation evidence showing the related control in compliant state

- [Lock Screen Verify Output](../evidence/lock-screen/lockscreen-verify.png)  
  → Script validation output confirming pre-remediation state

- [Lock Screen Apply Output](../evidence/lock-screen/lockscreen-apply.png)  
  → Script execution output showing lock screen policy remediation applied

---

### 3. Account Lockout Policy

- Configured lockout threshold, duration, and reset counters
- Remediated multiple STIGs as a grouped policy configuration

**Evidence:**

- [WN11-AC-000005 Before](../evidence/account-lockout/wn11-ac-000005-before.png)  
  → Baseline evidence for account lockout duration

- [WN11-AC-000005 After](../evidence/account-lockout/wn11-ac-000005-after.png)  
  → Post-remediation evidence for account lockout duration

- [WN11-AC-000010 Before](../evidence/account-lockout/wn11-ac-000010-before.png)  
  → Baseline evidence for failed logon attempt threshold

- [WN11-AC-000010 After](../evidence/account-lockout/wn11-ac-000010-after.png)  
  → Post-remediation evidence for failed logon attempt threshold

- [WN11-AC-000015 Before](../evidence/account-lockout/wn11-ac-000015-before.png)  
  → Baseline evidence for reset lockout counter timing

- [WN11-AC-000015 After](../evidence/account-lockout/wn11-ac-000015-after.png)  
  → Post-remediation evidence for reset lockout counter timing

- [Account Lockout Verify Output](../evidence/account-lockout/accountlockout-verify.png)  
  → Script validation output confirming grouped policy state before changes

- [Account Lockout Apply Output](../evidence/account-lockout/accountlockout-apply.png)  
  → Script execution output showing grouped account lockout remediation applied

---

### 4. Password Policy

- Enforced password history, minimum age, minimum length, and complexity
- Validated through grouped remediation and post-remediation scan results

**Evidence:**

- [WN11-AC-000020 Before](../evidence/password-policy/wn11-ac-000020-before.png)  
  → Baseline evidence for password history requirement

- [WN11-AC-000020 After](../evidence/password-policy/wn11-ac-000020-after.png)  
  → Post-remediation evidence for password history requirement

- [WN11-AC-000030 Before](../evidence/password-policy/wn11-ac-000030-before.png)  
  → Baseline evidence for minimum password age

- [WN11-AC-000030 After](../evidence/password-policy/wn11-ac-000030-after.png)  
  → Post-remediation evidence for minimum password age

- [WN11-AC-000035 Before](../evidence/password-policy/wn11-ac-000035-before.png)  
  → Baseline evidence for minimum password length

- [WN11-AC-000035 After](../evidence/password-policy/wn11-ac-000035-after.png)  
  → Post-remediation evidence for minimum password length

- [WN11-AC-000040 Before](../evidence/password-policy/wn11-ac-000040-before.png)  
  → Baseline evidence for password complexity

- [WN11-AC-000040 After](../evidence/password-policy/wn11-ac-000040-after.png)  
  → Post-remediation evidence for password complexity

- [Password Policy Verify Output](../evidence/password-policy/passwordpolicy-verify.png)  
  → Script validation output confirming grouped password policy state before changes

- [Password Policy Apply Output](../evidence/password-policy/passwordpolicy-apply.png)  
  → Script execution output showing grouped password policy remediation applied

---

### 5. SMBv1 (Indirect Remediation)

- No direct remediation script was implemented
- Related STIG findings changed status as a result of broader system hardening
- Demonstrates dependency-based and indirect remediation behavior

**Evidence:**

- [WN11-00-000160 Baseline (Warning)](../evidence/smbv1/wn11-00-000160-before.png)  
  → Baseline scan showing this STIG in a *Warning* state

- [WN11-00-000160 After](../evidence/smbv1/wn11-00-000160-after.png)  
  → Later scan showing transition to compliant state after related remediations

- [WN11-00-000165 Before](../evidence/smbv1/wn11-00-000165-before.png)  
  → Baseline scan showing this STIG in a failed state

- [WN11-00-000165 After](../evidence/smbv1/wn11-00-000165-after.png)  
  → Later scan showing this STIG resolved without direct intervention

- [WN11-00-000170 Baseline (Passed)](../evidence/smbv1/wn11-00-000170-baseline.png)  
  → Baseline scan confirming this STIG was already compliant prior to any remediation activity

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
