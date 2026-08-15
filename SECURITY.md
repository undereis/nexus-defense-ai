# Security Policy

## Supported scope

Nexus Defense AI `0.1.x` is a controlled research prototype. Security fixes are
applied to the current default branch; there is no production support guarantee
or certification claim.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, customer
data, or infrastructure identifiers. Use a private GitHub security advisory for
this repository. If that channel is unavailable, contact the maintainer through
the LinkedIn profile listed in the root README and request a private reporting
channel.

Please include:

- affected commit or version;
- impacted component and prerequisites;
- reproducible steps with sanitized evidence;
- expected security impact;
- a suggested mitigation, if known.

Never test against systems you do not own or lack explicit permission to assess.

## Security invariants

The following properties are intended to hold:

- the backend starts in `lab` unless an operator deliberately changes mode;
- a missing API token prevents startup rather than creating or printing one;
- state-changing actions pass policy, mode, target, and RBAC checks;
- high-impact actions require approval where classified by policy;
- audit data is redacted before hashing or signing;
- stored honeypot credentials are encrypted or irreversibly redacted;
- the desktop client cannot call arbitrary remote origins;
- passwordless firewall access is limited to a root-owned validating helper;
- secrets, databases, logs, and local captures are excluded from version control.

## Operator checklist

Before a demonstration or authorized lab run:

1. keep `NEXUS_OPERATING_MODE=lab` unless real-state changes are required;
2. create unique API, audit, webhook, and credential-encryption secrets;
3. store secrets with `scripts/nexus_secrets.py`, not in source control;
4. bind the API to `127.0.0.1` unless a reviewed TLS boundary exists;
5. register and verify authorized targets before enabling strict actions;
6. review pending approvals and the audit chain;
7. update dependencies and run the complete CI suite;
8. use only synthetic data for screenshots and portfolio demonstrations.

If a secret may have been exposed, rotate it immediately, invalidate dependent
sessions/webhooks, and inspect audit logs. Removing a value from the current tree
does not remove it from Git history.

## Out of scope for claims

The repository does not claim resistance to a compromised host administrator,
kernel-level malware, malicious dependency maintainers, or a compromised
external provider. Production readiness requires independent assessment and the
additional deployment controls described in [ARCHITECTURE.md](ARCHITECTURE.md).
