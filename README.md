# WebAuthnTestKit

A **test-side** C# toolkit for driving FIDO2/WebAuthn-protected APIs with a software
(pseudo) authenticator.

> WebAuthnTestKit is **not** a WebAuthn server library.
> It is **not** an HTTP client.
> It is a test-side toolkit that converts application-specific WebAuthn API envelopes
> into standard WebAuthn DTOs, signs them with a software test authenticator,
> and converts the result back into the application's finish JSON shape.

## Why

With ID/password auth, knowing the auth API contract was enough to use it programmatically.
FIDO2/WebAuthn binds credentials to a domain (RP ID), requires a ceremony, and each service
wraps the standard WebAuthn structures in its own JSON envelope. WebAuthnTestKit restores the
"know the contract → use it" experience for **tests** via a **software authenticator** plus a
**JSON envelope descriptor** per service.

## Scope (initial)

- Language: C# / .NET 10
- Attestation: **`none` only** — for test devices / API test bootstrapping, not for testing
  enterprise attestation policy or AAGUID restrictions.
- Descriptor format: JSON
- Surface: **envelope codec layer only** (`JSON ⇄ signature ⇄ JSON`). HTTP transport,
  begin/finish session continuity, and token usage are the consumer's responsibility.

## Layout

```
src/WebAuthnTestKit         library (① virtual authenticator + ② envelope codecs)
tests/WebAuthnTestKit.Tests xUnit tests
docs/design.md              full IF spec and usage walkthrough
```

## Status

Design settled; implementation starting. See [docs/design.md](docs/design.md) for the
interface specification, JSON descriptor schema, and end-to-end usage examples.

## License

MIT
