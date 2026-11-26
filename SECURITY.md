# Security policy

Keycard sits in the credential path of every tool call an agent makes. A flaw in this module is a flaw in someone's authorization boundary, so we treat reports here as high priority and we would rather hear about a maybe than miss a real one.

## Reporting a vulnerability

Do not open a public issue, pull request, or discussion for a security problem.

Use either channel:

- **GitHub private vulnerability reporting (preferred).** Go to the Security tab of this repository and open a private advisory. This keeps the report, our triage, and the eventual public advisory in one place.
- **Email security@keycard.ai.** If you want to encrypt, say so in a first message with no details and we will send you a key.

You do not need a working exploit to report something. A clear description of the flawed logic is enough.

Before you write it up, the platform's security model, token lifetimes, encryption scheme and threat model are documented in the [security architecture reference](https://docs.keycard.ai/reference/security-architecture/). It will tell you which behaviours are deliberate.

## What to include

The more of this you have, the faster we can act:

- Which package and the module version (including github.com/keycardai/go-sdk/oauth, /mcp, /a2a, /policy, and the separate github.com/keycardai/go-sdk/spiffe module)
- Go version, and the HTTP stack in use if it is not net/http
- What an attacker gains: which token, whose data, which scope they should not have had
- The smallest reproduction you can manage, ideally a failing test
- Whether the issue needs a specific configuration or handler wrapping order, and which

Please test against a zone you control. Do not probe other tenants' zones or use credentials that are not yours.

## What happens next

| Stage | Our commitment |
| --- | --- |
| Acknowledgement | Within 3 business days |
| Initial assessment and severity | Within 10 business days |
| Fix or documented mitigation | Target 30 days for high and critical severity |
| Public advisory | When the fix ships, or 90 days from your report, whichever comes first |

If we need longer than 90 days we will tell you why and agree a date with you rather than let the clock run out silently. If we conclude something is not a vulnerability we will explain the reasoning, and you are welcome to argue with it.

## Scope

### In scope for this repository

Anything that lets a caller obtain, keep, or use authority it should not have. Concretely:

- **Token validation.** Accepting an expired, unsigned, or wrong-algorithm token. Failing to check aud, iss, or the resource indicator. JWKS handling that trusts the wrong key, or a NewZoneTokenVerifier that accepts a token from the wrong zone.
- **Token exchange (RFC 8693).** Scope escalation across an exchange, subject and actor confusion, a delegation chain that is dropped, forged, or not verifiable downstream. In a2a, an agent card that can steer a per-hop exchange somewhere it should not go.
- **Bearer auth and scope enforcement.** A request reaching a wrapped handler without a valid token, or with a token missing the required scope. RequireBearerAuth or Grant granting authority the policy did not permit. Handler wrapping order that a reasonable reader would expect to be safe but is not.
- **Fail-open on a failed exchange.** AccessContext is non-panicking, so a handler that ignores ac.Status() carries on with a missing or failed grant. StatusPartialError is the dangerous one: some grants succeeded and some did not, and code that treats it as success is the bug. A StatusSuccess returned when a grant actually failed is in scope.
- **Authorization server metadata.** Anything in AuthMetadataHandler or the .well-known routes that enables an authorization server mix-up.
- **Credential handling.** Client secrets, access tokens, or refresh tokens appearing in logs, panic output, wrapped errors, or a String() implementation. Auth data reachable from the wrong request context through AuthInfoFromRequest or AuthInfoFromContext. Weak generation, storage, or reuse of the RSA key that NewWebIdentity creates for private_key_jwt (RFC 7523).
- **Concurrency defects with a security consequence.** A data race in a token cache that can serve one caller's token to another is a critical finding, not a flake. Reports backed by -race output are especially welcome.
- **Insecure defaults.** A configuration that most users will reach for and that is weaker than it appears, including in the NewWorkloadIdentity platform paths.
- PKCE, state, and nonce handling that permits replay, fixation, or cross-session confusion.

### Report to us, but not as a repository advisory

Issues in the hosted platform, the zone gateway, Keycard STS, Vault, or the Console, are not defects in this source tree. Email security@keycard.ai and say it concerns the hosted service. We will route it and keep you updated the same way.

This module is the Keycard auth SDK. The generated Management API client lives in keycard-go and has its own policy.

### Out of scope

- Findings that presuppose an already-compromised host, root access, or a client secret the attacker somehow holds
- Documented design choices, unless you can show one is exploitable. Token lifetimes, refresh token reuse, and the fifteen minute data encryption key cache are described in the security architecture reference and were chosen deliberately
- Vulnerabilities in dependencies with no exploitable path through this module. Report those upstream, and tell us so we can bump
- Missing security headers or TLS configuration on documentation sites, with no demonstrated impact
- Rate limiting or resource exhaustion without a concrete, realistic attack
- Scanner or govulncheck output with no analysis of exploitability
- Social engineering of Keycard staff, contributors, or customers

## Supported versions

This module and the spiffe module are pre-1.0. Under Go's compatibility conventions a v0 minor bump may contain breaking changes.

Security fixes land on the latest tagged release of each module. We do not backport to earlier v0 minors. If you are pinned to an older version and cannot move, say so in your report and we will discuss options with you.

The supported Go versions are those declared in go.mod on the latest tagged release: currently Go 1.23 or later for github.com/keycardai/go-sdk and Go 1.25 or later for the spiffe module.

## Coordinated disclosure

We publish fixed vulnerabilities as GitHub Security Advisories on this repository, which also feeds the Go vulnerability database, and request a CVE where one is warranted.

You get credit in the advisory under whatever name or handle you choose, or no credit if you prefer. Tell us which.

We do not currently run a paid bug bounty.

**Safe harbour.** If you make a good-faith effort to follow this policy, we will not pursue or support legal action against you. Good faith means you do not access, modify, or exfiltrate data belonging to anyone else, you do not degrade the service for other users, you stop at the point where you have demonstrated the problem, and you give us a reasonable chance to fix it before going public.

## Regulatory reporting

Keycard Labs, Inc. may be obliged under Article 14 of Regulation (EU) 2024/2847, the EU Cyber Resilience Act, to notify ENISA and a national CSIRT within 24 hours of becoming aware that a vulnerability in one of our products is being actively exploited.

Those notifications describe the vulnerability and the affected products. They do not include your identity or contact details unless you ask us to name you. If a report you send us triggers this obligation, we will tell you that it did.

## Contact

- Security reports: security@keycard.ai
- Everything else: support@keycard.ai

Please keep security matters out of the public issue tracker until an advisory is published.
