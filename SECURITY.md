# Security Policy

## Supported versions

The project currently supports the latest `main` branch. Security updates are provided for the currently maintained release line only.

| Version | Supported |
| --- | --- |
| `main` | Yes |
| other branches | No |

## Reporting a vulnerability

Please do not open a public GitHub issue for any security vulnerability.

Instead, report it privately through the repository's Security tab or contact the maintainer directly using a private communication channel.

When reporting, please include:

- a description of the vulnerability and its impact
- affected component, package, or file(s)
- reproduction steps or proof of concept
- any mitigation suggestions or fixes you have identified
- your preferred contact method for follow-up

We ask that you give maintainers a reasonable amount of time to investigate and remediate the issue before disclosing it publicly.

## Response expectations

We will review security reports as quickly as possible and aim to acknowledge receipt within 5 business days. We appreciate responsible disclosure and will work with you to validate and remediate the issue in good faith.

## Disclosure guidance

- Do not publicly disclose the issue before a fix is available.
- Avoid any action that could harm users or expose sensitive data beyond what is necessary to validate the vulnerability.
- Do not exploit the issue beyond the minimum required to confirm the report.

## Security best practices

- Keep dependencies and package references up to date.
- Use secure defaults for cryptographic configuration.
- Validate all inputs and avoid insecure assumptions in key handling or protocol logic.
- Treat all cryptographic materials as sensitive and do not log or expose them.
- Review changes that affect encryption, authentication, or network data handling with extra care.
