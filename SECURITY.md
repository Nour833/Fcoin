# Security policy

## Supported version

Security fixes are applied to the latest `2.x` release.

## Reporting a vulnerability

Report vulnerabilities privately to the repository owner. Do not include live card keys, complete dumps, personal identifiers, or data from systems you do not own.

A useful report contains:

- FCOIN version and operating system.
- A minimal synthetic fixture that reproduces the problem.
- Exact command and observed behavior.
- Expected safety property.
- Potential impact.

## Safety properties

FCOIN treats these as security boundaries:

- No automatic package installation or privilege escalation.
- No network transmission during normal operation.
- Strict supported dump sizes.
- Exact value-block and access-bit redundancy checks.
- Manufacturer block and sector-trailer write refusal.
- Exact UID/profile binding for writable value plans.
- Immutable source-image hashes.
- Exact per-block preconditions.
- Detection of collateral changes.
- Hash-chained durable transaction records.
- Secure session and artifact permissions.

## Sensitive data

MFD dumps can contain authentication keys, identifiers, activity data, and application-specific secrets. Keep them outside source control. FCOIN applies `0600` permissions to artifacts it creates, but users remain responsible for backups, host security, and secure deletion.

## Responsible use

Use FCOIN only with cards and systems you own or have explicit authorization to assess. Do not use it to alter third-party stored value, payment credentials, transit media, access-control credentials, or production systems.
