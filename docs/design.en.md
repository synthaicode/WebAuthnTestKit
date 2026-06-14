# WebAuthnTestKit — Interface Spec & Usage

A C# toolkit for automatically testing / programmatically driving FIDO2/WebAuthn-protected APIs
with a **software (pseudo) authenticator**.

> **Status**: this document is **kept in sync with the shipped API** (core ① + ② complete).
> See [status.md](status.md) for progress and `samples/` for runnable examples. The source under
> `src/WebAuthnTestKit/` is the ultimate source of truth.
>
> 日本語版: [design.md](design.md)

---

## 0. What it is — and is not (scope)

> WebAuthnTestKit is **not** a WebAuthn server library.
> It is **not** an HTTP client.
> It is a **test-side toolkit** that converts application-specific WebAuthn API envelopes
> into standard WebAuthn DTOs, signs them with a software test authenticator,
> and converts the result back into the application's finish JSON shape.

- **Not a server verification library** (it is the mirror image of `py_webauthn` / `webauthn4j`).
- **Not an HTTP client.** Calling begin/finish and maintaining session continuity are the
  consumer's responsibility.
- The initial version supports **attestation format `none` only**. Authenticator-attestation
  verification and AAGUID restrictions are out of scope (this is for test devices and API test
  bootstrapping, not for testing enterprise attestation policy).

> **Security note**
> WebAuthnTestKit creates software test authenticators and exportable device states.
> Do not use generated device states, private keys, or credentials as production authenticators.
> The software authenticator has no hardware-backed key protection and does not enforce a real user
> presence/verification gesture (the UP/UV flags are set by configuration). Use it only for testing
> your own or otherwise authorized WebAuthn integrations.

---

## 1. Background and problem

| | ID/password era | FIDO2/WebAuthn |
|---|---|---|
| Credential nature | portable, **domain-independent** | **domain-bound** (RP ID), non-portable |
| Knowledge needed to authenticate | just the auth API contract | + RP domain + ceremony + possessing an authenticator + a human gesture |
| Return value | a token string | the standard WebAuthn structures, **wrapped in each API's own JSON** |

The **core of WebAuthn (clientDataJSON / authenticatorData / signature / CBOR) is standardized**,
but the **server-side envelope that wraps it (JSON shape, challenge encoding, where the returned
token lives, values carried from begin to finish) is per-service**. That is the gap.

The goal of this toolkit is to declaratively restore the old "knowing the auth API contract is
enough" experience via a **software authenticator + an envelope descriptor**.

---

## 2. Concept and scope

- **Represent a pseudo device** — run WebAuthn ceremonies without a physical key (①).
- **Parse / normalize each API's own envelope** — absorbed by a JSON descriptor (②).
- **HTTP flow execution (③) is the consumer's job** — this is a pure-conversion library that
  stops at ②.

### Decisions

| Item | Decision |
|---|---|
| Language | C# (.NET) |
| Attestation | **`none` only** (minimal crypto; authenticity testing out of scope) |
| Descriptor format | JSON |
| Surface | **up to ② (the envelope codec)**. HTTP/session are the consumer's |
| Public API style | descriptor is **bound** (constructor injection) + **fail-fast validation at construction** |

---

## 3. Architecture

```
JSON (each API's own)
   ▲ │
   │ ▼   ┌─ RegistrationEnvelopeCodec ─┐
   ②────┤  AuthenticationEnvelopeCodec │──► standard DTO ──► VirtualAuthenticator (①) ──► crypto
         └─ EnvelopeEngine (shared, stateless)┘                                        (ES256/CBOR)
   ─────────────────────────────────────────────────────────────────
   ③ HTTP transport / begin·finish session continuity / token usage  ← implemented by the consumer
```

- The **boundary DTOs (standard WebAuthn types)** are the shared language between codec ⇄ device.
  - Codec: "app-specific JSON ⇄ standard DTO"
  - Device: "standard DTO ⇄ crypto"
- **`DecodeOptions` returns `Options` together with `Context` (the begin response)** → so finish
  can carry begin values forward.
- **EnvelopeEngine** is stateless. The public surface is the descriptor-bound codec (getting both
  convenience and purity).

---

## 4. Interface specification

### 4.1 Boundary DTOs (API-agnostic, standard WebAuthn)

```csharp
// Ceremony inputs (decoded from the server's begin response).
// Origin = the full origin written into clientDataJSON (from the descriptor's rp.origin);
// distinct from RpId (which becomes rpIdHash).
record CreationOptions(byte[] Challenge, RpEntity Rp, UserEntity User, PubKeyCredParam[] Params, string Origin);
record RequestOptions (byte[] Challenge, string RpId, AllowCredential[] Allow, string Origin);

// Context of the begin response (the source of values carried into finish).
record EnvelopeContext(JsonNode BeginResponse, JsonNode? UserContext = null);

// DecodeOptions returns Options and Context together (so finish can't mix ceremonies up).
record DecodedOptions<TOptions>(TOptions Options, EnvelopeContext Context);

// Ceremony outputs (produced by the device, packed into the finish request).
record AttestationResult(byte[] CredentialId, byte[] ClientDataJson, byte[] AttestationObject);
record AssertionResult  (byte[] CredentialId, byte[] ClientDataJson, byte[] AuthenticatorData,
                         byte[] Signature, byte[]? UserHandle);

// Parsed finish response (not limited to a single token; Values carries varied returns).
record CeremonyResult(
    bool Success,
    string? PrimaryToken,                            // representative token (convenience access)
    IReadOnlyDictionary<string, string> Values,      // accessToken/refreshToken/idToken/sessionId/role/expiresIn...
    JsonNode Raw);

// Helpers
record RpEntity(string Id, string? Name);
record UserEntity(byte[] Id, string Name, string DisplayName);
record PubKeyCredParam(string Type, int Alg);        // Alg = -7 (ES256) only initially
record AllowCredential(string Type, byte[] Id);
```

> **Policy**: the variety of returns (accessToken/refreshToken/idToken/sessionId/role/expiresIn,
> etc.) is received through the `Values` dictionary; only the representative value is exposed via
> `PrimaryToken`. A dedicated typed `AuthSession` is **not** introduced (the dictionary is enough
> and the descriptor picks values flexibly).

### 4.2 Pseudo device (①)

```csharp
class VirtualAuthenticator
{
    // Identity fixed at construction (= the substance of "registering a device").
    public VirtualAuthenticator(VirtualAuthenticatorOptions options);

    AttestationResult MakeCredential(CreationOptions options);  // register. clientData.type = "webauthn.create"
    AssertionResult   GetAssertion (RequestOptions  options);   // authenticate. clientData.type = "webauthn.get"

    // Save/restore state (reuse a device across tests).
    DeviceState Export();
    static VirtualAuthenticator Import(DeviceState state);
}

record VirtualAuthenticatorOptions(
    Guid   Aaguid              = default,    // default: zero GUID
    int    Algorithm           = -7,         // ES256
    bool   SupportsResidentKey = true,
    bool   UserPresent         = true,       // UP flag
    bool   UserVerified        = true);      // UV flag
```

**Contract notes:**

- **`GetAssertion` advances `signCount` (mutable).** Call `Export()` after authentication to save
  state. For reproducible tests, `Import` a known `DeviceState` at the start of each case.
- **`allowCredentials` matching:** when `RequestOptions.Allow` is non-empty and no registered
  credential is included, it **fails fast** (`No matching credential in allowCredentials.`) — a
  common real-world mistake.
- **clientDataJSON `type` is fixed** (register = `webauthn.create` / auth = `webauthn.get`); not
  descriptor-driven.
- **The challenge inside `ClientDataJson` is always base64url per spec** (not subject to the
  descriptor's `challengeEncoding`).
- With attestation `none`, `AttestationObject` is `{ fmt:"none", attStmt:{}, authData }`; no
  certificate chain is produced.

### 4.3 Envelope codecs (②)

```csharp
interface IEnvelopeCodec<TOptions, TFinish>
{
    // begin response → standard options + context (challenge decoded to byte[])
    DecodedOptions<TOptions> DecodeOptions(JsonNode beginResponse);

    // device output + begin context → finish body (enables source.* carry-over)
    JsonNode EncodeFinish(TFinish deviceOutput, EnvelopeContext context);

    // finish response → token + Values + success
    CeremonyResult DecodeResult(JsonNode finishResponse);

    // Diagnostics from the most recent EncodeFinish (for tracking failures)
    EnvelopeDebugInfo? LastDebug { get; }
}

class RegistrationEnvelopeCodec   : IEnvelopeCodec<CreationOptions, AttestationResult>
{
    public RegistrationEnvelopeCodec(ServiceDescriptor descriptor);   // binds + validates at construction
}
class AuthenticationEnvelopeCodec : IEnvelopeCodec<RequestOptions, AssertionResult>
{
    public AuthenticationEnvelopeCodec(ServiceDescriptor descriptor);
}

// For failure tracking (encoding mismatch / rpId mismatch / credentialId mismatch /
// unfilled template / JSON-path miss, etc.)
record EnvelopeDebugInfo(
    string RpId,
    string Origin,
    string ChallengeBase64Url,
    string CredentialIdBase64Url,
    string OptionsPath,
    IReadOnlyList<string> ResolvedTemplateVariables,
    IReadOnlyList<string> UnresolvedTemplateVariables);
```

Each codec has **three responsibilities**: `DecodeOptions` (begin) / `EncodeFinish` (finish
request) / `DecodeResult` (finish response).

### 4.4 Shared engine (stateless) and facade

```csharp
static class EnvelopeEngine          // the codecs' shared internals (no duplication)
{
    JsonNode Resolve(JsonNode root, string path);          // JSON path resolution
    byte[]   Decode (string s, string encoding);           // base64url/base64/hex
    string   Encode (byte[] b, string encoding);
    JsonNode Fill   (JsonNode template, IReadOnlyDictionary<string,string> values);  // {{...}} substitution
    bool     Eval   (JsonNode root, string condition);     // successWhen evaluation
}

class TestKit                         // entry point for many services
{                                     // (named TestKit, not WebAuthnTestKit, to avoid clashing with the namespace)
    public TestKit(IEnumerable<ServiceDescriptor> descriptors);
    public static TestKit FromJson(params string[] descriptorJson);   // load directly from JSON strings
    public RegistrationEnvelopeCodec   Registration(string service);
    public AuthenticationEnvelopeCodec Authentication(string service);
}
```

### 4.5 Descriptor fail-fast validation (at construction)

`new XxxEnvelopeCodec(descriptor)` validates the minimum and **fails at init, not at runtime**:

- `service` is present
- `rp.id` is present / `rp.origin` is a valid URL
- `begin.optionsPath` is present
- `challengeEncoding` is supported (`base64url`/`base64`/`hex`); same for `userIdEncoding` /
  `credentialIdEncoding` (default base64url)
- `finish.body` has **no unknown reserved variables (`{{...}}`)** (only standard variables or
  `source.*` are allowed)
- `result.tokenPath` / `successWhen` / `values` (name → path map) are all optional

### 4.6 JSON descriptor schema

Supports both **filling standard WebAuthn response fields individually** and **packing the whole
assertion/attestation object as base64url into one field**. `{{source.*}}` carries begin-response
values into finish.

```json
{
  "service": "example-api",
  "rp": { "id": "example.com", "origin": "https://example.com" },

  "registration": {
    "begin": {
      "optionsPath": "$.data.publicKey",
      "challengeEncoding": "base64url",
      "userIdEncoding": "base64url"
    },
    "finish": {
      "body": {
        "registrationId": "{{source.registrationId}}",
        "fidoAttestation": "{{attestationJsonBase64Url}}"
      },
      "result": { "tokenPath": "$.data.session.jwt", "successWhen": "$.status == 'ok'" }
    }
  },

  "assertion": {
    "begin": { "optionsPath": "$.publicKey", "challengeEncoding": "base64url", "credentialIdEncoding": "base64url" },
    "finish": {
      "body": {
        "requestId": "{{source.requestId}}",
        "fidoAssertion": "{{assertionJsonBase64Url}}"
      },
      "result": { "tokenPath": "$.token", "successWhen": "$.status == 'ok'",
                  "values": { "refreshToken": "$.refresh", "role": "$.user.role" } }
    }
  }
}
```

Individual-field style (a conventional API that expands `response` directly):

```json
"finish": {
  "body": {
    "credential": {
      "id": "{{credentialId}}", "rawId": "{{rawId}}", "type": "public-key",
      "response": {
        "clientDataJSON": "{{clientDataJSON}}",
        "authenticatorData": "{{authenticatorData}}",
        "signature": "{{signature}}",
        "userHandle": "{{userHandle}}"
      }
    }
  }
}
```

#### Built-in template variables

```
# individual fields
{{credentialId}}
{{rawId}}
{{clientDataJSON}}
{{authenticatorData}}      # assertion only
{{signature}}              # assertion only
{{userHandle}}             # assertion only
{{attestationObject}}      # registration only

# whole object (JSON string / its base64url)
{{assertionJson}}         {{assertionJsonBase64Url}}     # assertion
{{attestationJson}}       {{attestationJsonBase64Url}}   # registration

# carry-over from the begin response (any path)
{{source.<path>}}         # e.g. {{source.requestId}} {{source.transactionId}}
                          #      {{source.state}} {{source.tenantId}} {{source.csrfToken}}
                          #      {{source.challengeId}} {{source.registrationToken}}
```

- `assertionJson` = the whole standard assertion response object
  (`{id,rawId,type,response:{...}}`) as a JSON string; `assertionJsonBase64Url` is its base64url.
  Same for registration.
- `rp.id` / `rp.origin` are **first-class fields**, so domain binding is injected explicitly per API.
- `result.values` (optional) = a name → JSON-path map; extracts multiple values from the finish
  response into `CeremonyResult.Values`. The representative value is `result.tokenPath` →
  `PrimaryToken`.
- Transformations not expressible declaratively are deferred to future hooks (declarative only for now).

---

## 5. Usage

### 5.1 Registration

```csharp
var kit    = new TestKit(descriptors);                 // or TestKit.FromJson(descriptorJson)
var device = new VirtualAuthenticator(new());          // a pseudo device

var reg    = kit.Registration("example-api");          // descriptor-bound (validated at construction)

// ① Consumer: log in beforehand (establish a session) — other auth methods are the consumer's job
var http = new HttpClient(new HttpClientHandler { CookieContainer = jar });
await LoginWithPassword(http, ...);

// ② Call begin (HTTP = consumer)
var beginJson = await http.PostJsonAsync("/register/begin", new { ... });

// ③ Codec → device → Codec (this toolkit). Carry Context into finish.
var decoded = reg.DecodeOptions(beginJson);            // Options + Context
var att     = device.MakeCredential(decoded.Options);  // the pseudo device signs
var body    = reg.EncodeFinish(att, decoded.Context);  // finish body incl. source.*

// ④ Call finish (HTTP = consumer). Cookie/CSRF/state continuity is the consumer's job
var finishJson = await http.PostJsonAsync("/register/finish", body);

// ⑤ Parse result (this toolkit)
var result = reg.DecodeResult(finishJson);
Assert.True(result.Success);

// ⑥ Save device state to carry into the auth flow
var state = device.Export();
```

### 5.2 Authentication

```csharp
var device = VirtualAuthenticator.Import(state);       // restore the registered device
var auth   = kit.Authentication("example-api");

var beginJson  = await http.PostJsonAsync("/assertion/begin", new { ... });
var decoded    = auth.DecodeOptions(beginJson);
var assertion  = device.GetAssertion(decoded.Options); // ← signCount advances
var body       = auth.EncodeFinish(assertion, decoded.Context);
var finishJson = await http.PostJsonAsync("/assertion/finish", body);

var result = auth.DecodeResult(finishJson);
var token  = result.PrimaryToken;                      // also result.Values["refreshToken"], etc.

// Always save state after auth (signCount advanced)
state = device.Export();

// ⑦ Use the token to verify a protected API (the consumer's test body)
http.DefaultRequestHeaders.Authorization = new("Bearer", token);
var protectedResp = await http.GetAsync("/me");
Assert.Equal(HttpStatusCode.OK, protectedResp.StatusCode);
```

### 5.3 Debugging failures

```csharp
var body = auth.EncodeFinish(assertion, decoded.Context);
if (auth.LastDebug is { UnresolvedTemplateVariables.Count: > 0 } dbg)
    throw new InvalidOperationException(
        $"unresolved templates: {string.Join(", ", dbg.UnresolvedTemplateVariables)} / rpId={dbg.RpId}");
```

---

## 6. What the consumer still implements (when stopping at ②)

This toolkit is pure "JSON ⇄ signature ⇄ JSON" conversion only. The following is **the consumer's
job**:

1. **HTTP transport** — actually call begin/finish (`HttpClient`).
2. **Session continuity (the biggest hill)** — the server ties the begin challenge to finish via a
   cookie / server-side state. **Preserving the CookieContainer / CSRF / state blob across the two
   calls** is up to the consumer. (Values that ride in the body via `source.*` are carried by this
   toolkit; headers/cookies are not.)
3. **Orchestration / ordering** — wiring begin → ① → ② → finish and handling aborts.
4. **Bootstrap auth** — registration usually assumes an already-logged-in session or an invite token.
5. **Token usage** — storing it after extraction, attaching `Bearer`, refreshing.
6. **Error/status interpretation and retries** — handling HTTP and server-specific error envelopes.
7. **Device-state persistence IO** — choosing where to save and loading via `Export`/`Import`
   (preserving `signCount`).
8. **Test assertions** — the actual checks ("got a token", "protected API returns 200").

> Items 2–4 (especially begin/finish session continuity) are the most error-prone. A future,
> optional **thin ③ (flow runner)** that injects the consumer's `HttpClient` could confine these
> pitfalls in one place (stopping at ② is fine without it).

---

## 7. C# implementation pieces

| Concern | Technology |
|---|---|
| Key/signature (ES256) | `System.Security.Cryptography.ECDsa` (P-256 / SHA-256) |
| CBOR (COSE key, attestationObject) | `System.Formats.Cbor` (.NET built-in) |
| JSON (descriptor, envelope ops) | `System.Text.Json` / `JsonNode` |
| JSON path resolution | a small hand-rolled resolver (or `JsonPath.Net`) |
| base64url | .NET 9 `Base64Url`, else a manual converter |

---

## 8. Decisions of record

- **Descriptor is "held" (constructor injection) + validated at construction** — test usage is
  mainly "one fixture = one service". Call sites stay quiet; fail-fast. Use the stateless engine
  directly only when dynamic switching is needed.
- **Public = bound facade, internal = stateless engine** — both convenience and purity.
- **`DecodeOptions` returns Options + Context** — so finish carries begin's `source.*` values
  without mixing them up.
- **A codec per ceremony** — registration/authentication payloads differ fundamentally, so this
  avoids a god-class.
- **`GetAssertion` is mutable (advances `signCount`)** — mutable is fine initially; "Export after
  auth" is documented.
- **`CeremonyResult`** — representative value is `PrimaryToken`, the rest is the `Values`
  dictionary. No typed `AuthSession`.
- **clientDataJSON type / challenge are spec-fixed** — not descriptor-driven; a clean boundary that
  prevents mistakes.
- **`allowCredentials` matching fails fast** — rejects auth attempts with an unregistered
  credential at the start.

---

## 9. Implementation status

The core of this design (① + ②) is **complete**; all the original steps are done:

1. ✅ Boundary DTOs finalized (including `Origin`).
2. ✅ `VirtualAuthenticator` (ES256 / none / signCount / allowCredentials matching / Export·Import).
3. ✅ `EnvelopeEngine` + two codecs + the `TestKit` facade.
4. ✅ Construction-time validation + `EnvelopeDebugInfo`.
5. ✅ End-to-end against an independent server (Fido2NetLib) in Docker.

See [status.md](status.md) for detailed status, test layout, and CI/Release.
See `samples/` for the descriptor / demo server / runnable client.
