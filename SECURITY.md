# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability"). You should get an acknowledgement within 7 days.

Latent parses hostile data by design: evidence from a compromised machine may be crafted to attack the analyst's workstation. Parser crashes, unbounded allocations, path traversal in outputs, or anything that breaks the read-only guarantee are all in scope and taken seriously.

## Supported versions

The project is pre-1.0; only the latest release and the main branch receive fixes.

## Out of scope

Requests to add log manipulation, wiping or forgery capabilities are not vulnerabilities and will be declined. That functionality is permanently out of scope for this project.
