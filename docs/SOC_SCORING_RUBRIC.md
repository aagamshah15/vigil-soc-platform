# SOC Scoring Rubric

Phase 6 uses deterministic explainable scoring so analysts can see why an entity is risky.

| Detection | Points | Example |
| --- | ---: | --- |
| Privilege escalation | 25 | Developer added to Domain Admins. |
| Critical/high asset access | 20 | Access to payment database. |
| Outside business hours | 15 | Payment access at unusual time. |
| Failed-login burst | 15 | 5+ failed logins in 15 minutes. |
| Endpoint malware alert | 25 | Suspicious encoded PowerShell. |
| Lateral movement | 30 | Workstation reaches production database by remote admin protocol. |
| Threat-intel outbound | 30 | Connection to known bad IP. |
| Vendor sensitive access | 20 | Contractor account touches high-sensitivity asset. |
| Badge/digital mismatch | 20 | Badge in Austin, VPN in Amsterdam. |

Risk bands:

- `low`: `< 30`
- `medium`: `30-59`
- `high`: `60-79`
- `critical`: `>= 80`

Recommended actions are derived from risk band and shown in API/dashboard outputs.
