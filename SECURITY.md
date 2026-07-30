# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues, pull
requests, or discussions.**

Instead, report privately through either channel:

- Email **security@getbusbar.com**, or
- GitHub's [private vulnerability reporting](https://github.com/GetBusbar/store-postgres/security/advisories/new)
  (the **Security** tab on this repository).

Please include:

- A description of the issue and its potential impact.
- Steps to reproduce (proof-of-concept if available).
- Affected version / commit.
- Any suggested mitigation.

We aim to **acknowledge your report within 48 hours**, work with you on a fix, and
coordinate disclosure timing. Confirmed vulnerabilities are published as
[GitHub Security Advisories](https://github.com/GetBusbar/store-postgres/security/advisories),
through which we request and issue **CVE** identifiers. We credit reporters who wish to be
credited once a fix is released.

## Scope

`store-postgres` is a `kind: store` busbar plugin: it persists busbar's governance
data — virtual keys, budgets, and usage — in a shared Postgres database behind a
fleet of busbar nodes. Issues of particular interest include:

- SQL injection or any path where request-derived data reaches a query
  unparameterized.
- Connection-string (`url`) handling that could leak credentials into logs or
  error strings.
- Cross-node data races that corrupt shared governance state (budgets, usage
  ledgers) under concurrent writers.
- A load-time config error surfacing as a silent success instead of a clean
  `Err` across the plugin ABI.

**Known, documented limitation, not a vulnerability report:** this build
connects `NoTls` (see the README's [Known limitations](README.md#known-limitations-documented-honestly-not-papered-over)
section) — run it over a trusted network segment, a local socket, or a
TLS-terminating proxy. This is a deployment consideration, not something we
consider a defect in the plugin itself, but we're glad to hear if you think
otherwise.

See busbar's own [threat model](https://github.com/GetBusbar/busbar/blob/main/THREAT_MODEL.md)
for the trust boundaries this plugin operates inside.

## Supported versions

This plugin is versioned independently of busbar (see the README's
[Versioning](README.md#versioning) section). Security fixes are applied to the
latest `main` and the most recent tagged release of **this repository**. Pin to a
tag for production use.
