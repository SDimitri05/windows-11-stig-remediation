# Remediation Summary

## Overview

This project implemented and validated multiple Windows 11 DISA STIG controls using PowerShell automation and Tenable vulnerability scanning.

## Scope

The following control groups were addressed:

- Secondary Logon Service
- Lock Screen Hardening
- Account Lockout Policy
- Password Policy

Additionally:

- Windows Firewall was implemented, tested, and rolled back due to operational impact
- SMBv1-related STIGs were resolved indirectly through related system changes

## Key Outcomes

- Successful remediation of multiple STIG findings
- Demonstrated FAILED → WARNING → PASSED progression for lock screen controls
- Validated grouped policy remediations (account lockout and password policy)
- Identified and documented tool-impacting behavior from firewall enforcement
- Observed indirect remediation effects across SMBv1-related controls

## Key Insights

- Policy-backed configurations are critical for compliance validation
- Security controls can impact monitoring and scanning tools
- Some STIG findings can be resolved indirectly through system-wide changes
- Rollback is a valid and necessary action when operational impact is identified

## Status

- Primary controls: Remediated and validated
- Windows Firewall: Implemented, tested, rolled back, and documented
- SMBv1 controls: Partially baseline-compliant; remaining findings resolved indirectly
