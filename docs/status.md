# Implementation Status

_Last updated: 2026-06-14_

Core library (① virtual authenticator + ② envelope codecs) is **complete**, with unit tests and
Docker-based integration tests passing against an independent Fido2NetLib server.

## Roadmap (from design.md §9)

| # | Item | Status |
|---|------|--------|
| 1 | Boundary DTOs | ✅ Done |
| 2 | `VirtualAuthenticator` (ES256 / attestation none) | ✅ Done |
| 3 | `EnvelopeEngine` + registration/authentication codecs + facade | ✅ Done |
| 4 | Construction-time descriptor validation + `EnvelopeDebugInfo` | ✅ Done |
| 5 | End-to-end against a real server | ✅ Done (dockerized Fido2NetLib) |

## What works today

### ① VirtualAuthenticator (`src/WebAuthnTestKit/Device`)
- `MakeCredential` — ES256 key, `webauthn.create` clientDataJSON, authenticatorData
  (rpIdHash, flags `UP|UV|AT`, signCount, AAGUID, credentialId, COSE EC2 key),
  `none`-format attestationObject (CBOR).
- `GetAssertion` — `allowCredentials` fail-fast match, `webauthn.get` clientDataJSON,
  DER ES256 signature over `authData ‖ SHA256(clientDataJSON)`, signature counter advance.
- `Export` / `Import` — state snapshot that preserves the signature counter across runs.

### ② Envelope layer (`src/WebAuthnTestKit/{Descriptor,Envelope}`, `TestKit`)
- `ServiceDescriptor.Parse` — JSON descriptor → POCO model.
- `EnvelopeEngine` — minimal JSON path (`$.a.b[0]`), base64url/base64/hex codec,
  `{{var}}` / `{{source.*}}` templating, `successWhen` evaluation. Stateless.
- `RegistrationEnvelopeCodec` / `AuthenticationEnvelopeCodec` — `DecodeOptions`,
  `EncodeFinish`, `DecodeResult`, plus `LastDebug` (`EnvelopeDebugInfo`).
- `DescriptorValidator` — fail-fast at codec construction (service, rp.id, rp.origin URL,
  optionsPath, challengeEncoding, unknown template variables).
- `TestKit` facade — descriptor-bound, per-service codecs.
- Supports both individual-field and whole-object `{{assertionJsonBase64Url}}` finish bodies,
  and `source.*` carry-over from the begin response.

## Tests

| Suite | Count | Notes |
|-------|-------|-------|
| `WebAuthnTestKit.Tests` (unit) | 11 | device crypto round-trip (signature verifies against the registered key), envelope mapping, validation fail-fast |
| `WebAuthnTestKit.IntegrationTests` (Docker) | 2 | Testcontainers builds & runs the Fido2NetLib demo server; register + authenticate + counter progression verified server-side |

Build: 0 warnings. Run fast suite with `dotnet test --filter Category!=Integration`.

## Decisions of record

- `CeremonyResult` = `PrimaryToken` + `Values` dictionary; no typed `AuthSession`.
- Descriptor is **bound** to a codec at construction (public surface) over an internal stateless
  engine (purity).
- `GetAssertion` is mutable (advances signCount); callers `Export` after authentication.
- clientDataJSON `type` and the embedded challenge encoding are spec-fixed, not descriptor-driven.
- Attestation `none` only — out of scope: enterprise attestation / AAGUID-policy testing.

## Not implemented (optional / future)

- Thin ③ flow runner (inject an `HttpClient`, run begin → device → finish in one call) to absorb
  the begin/finish session-continuity glue that currently lives with the consumer.
- Additional algorithms (RS256, EdDSA) and full/packed attestation formats.
- Extensions (credProps, largeBlob, prf, …).
- NuGet publish workflow.

See [design.md](design.md) for the full interface specification and the consumer-side
responsibilities (§6) that the envelope-only surface leaves to the caller.
