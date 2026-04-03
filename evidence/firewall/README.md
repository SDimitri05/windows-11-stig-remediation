# Windows Firewall Evidence

This folder contains validation artifacts for:

- WN11-00-000135 — Windows Firewall must be enabled

## Execution Modes

- Verify: baseline firewall state
- Apply: firewall enabled
- Rollback: firewall disabled

## Observations

- Firewall was successfully enabled via script
- However, authenticated scan data (Audits tab) became unavailable
- Scan duration decreased significantly

## Additional Validation

- OS-level firewall state confirmed using system output
- Verified both enabled and disabled states after Apply and Rollback

## Conclusion

The control was implemented and tested, but introduced operational impact on authenticated scanning.  
The system was rolled back to preserve scan integrity.
