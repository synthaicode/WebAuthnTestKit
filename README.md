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

## Quickstart

```csharp
var kit    = TestKit.FromJson(File.ReadAllText("samples/descriptors/fido2-demo.json"));
var device = new VirtualAuthenticator(new());      // a software test authenticator

// Registration — you own the HTTP calls; the kit owns JSON <-> signature <-> JSON.
var reg     = kit.Registration("fido2-demo");
var begin   = await PostJson("/attestation/options", new { username = "alice" });
var opts    = reg.DecodeOptions(begin);            // app envelope -> standard options + context
var att     = device.MakeCredential(opts.Options); // sign with the test device
var finish  = reg.EncodeFinish(att, opts.Context); // standard output -> app finish body
var result  = reg.DecodeResult(await PostJson("/attestation/result", finish));
// ... Authentication is the same shape via kit.Authentication(...).GetAssertion(...)
```

See [docs/design.md](docs/design.md) for the full walkthrough and `samples/` for a runnable
descriptor + demo server.

## Layout

```
src/WebAuthnTestKit                    library (① virtual authenticator + ② envelope codecs)
tests/WebAuthnTestKit.Tests            xUnit unit tests
tests/WebAuthnTestKit.IntegrationTests Docker/Testcontainers tests against a real Fido2NetLib server
samples/descriptors/fido2-demo.json    example JSON envelope descriptor
samples/Fido2DemoServer                dockerized independent WebAuthn server for integration tests
docs/design.md                         full IF spec and usage walkthrough
```

## Testing

```bash
dotnet test --filter Category!=Integration   # fast unit tests only
dotnet test                                   # includes Docker-based integration tests (needs Docker)
```

## Status

Core library (① virtual authenticator + ② envelope codecs) is **complete** and tested —
11 unit tests plus 2 Docker-based integration tests passing against an independent Fido2NetLib
server. See [docs/status.md](docs/status.md) for the detailed breakdown and
[docs/design.md](docs/design.md) for the interface specification and descriptor schema.

Optional/future work (not implemented): a thin HTTP flow runner, more algorithms (RS256/EdDSA),
richer attestation formats, and a NuGet publish workflow.

## License

MIT
