# Security Policy

`ori-skills-hub` handles community skill packages. Vulnerabilities here can lead
to malicious skill distribution, but [`ori-runtime`](https://github.com/ori-platform/ori-runtime)
must still verify signatures before loading any community skill.

## Report Priority

High-priority findings include:

- unsigned or tampered tarballs accepted by publish flow,
- skill stored before signature verification,
- Tier C/D skill listed without admin approval,
- path traversal in local or object storage,
- executing community skill code inside the Hub,
- private key or secret exposure,
- drift from [`ori-specs`](https://github.com/ori-platform/ori-specs) signing or skill-package contracts.

Do not disclose exploitable findings publicly before remediation.
