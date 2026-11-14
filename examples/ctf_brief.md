# AEGIS-LOOP FIXTURE — Authorized Lab CTF Brief (training use only)

- **Engagement:** internal red-team training, "JuiceConf 2026" CTF.
- **Authorization:** signed rules of engagement for the isolated training
  range 10.10.10.0/24. This range is private lab infrastructure only.
- **Target:** OWASP Juice Shop instance at 10.10.10.15 (vulnerable by design).
- **Objectives:**
  1. Enumerate the application and map its attack surface.
  2. Solve the "Login Admin" challenge and document each step as a writeup.
  3. For every technique used, note the matching ATT&CK technique ID and at
     least one detection opportunity for the blue team.
- **Constraints:** lab network only; nothing leaves the range; reset the
  Juice Shop instance and revert VM snapshots when done.
- **Deliverable:** walkthrough plus detection opportunities (purple-team
  format).
