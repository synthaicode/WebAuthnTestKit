# Thin HTTP Flow Runner (③) — Design Note

Status: **planned** (not yet implemented). This note specifies the optional layer ③ that
[design.en.md §6](design.en.md) and [status.md](status.md) list as future work. The core
① VirtualAuthenticator + ② envelope codecs are unchanged; ③ sits on top of them.

> 日本語版: [flow-runner.md](flow-runner.md)

---

## 0. Goal and non-goals

The codec layer (②) stops at "JSON ⇄ signature ⇄ JSON". Everything around it — calling
begin/finish over HTTP and keeping the two calls on the **same session** — is the consumer's job
today, hand-written in [`samples/DemoClient/Program.cs`](../samples/DemoClient/Program.cs)
(`RegisterFlow` / `AuthFlow`). Per [design.en.md §6](design.en.md), items 2–4 (begin/finish session
continuity above all) are the most error-prone.

**Goal.** A *thin* runner that sequences `begin → device → finish` in one call, over an
HttpClient the **consumer injects**, so the begin and finish requests are guaranteed to share one
`CookieContainer` / handler. It confines the session-continuity pitfall and the failure diagnostics
in one place.

**Non-goals (kept thin on purpose).** The runner does **not** own:

- bootstrap login (the consumer logs in first, on the same HttpClient),
- token usage (attaching `Bearer`, refreshing),
- device-state persistence (`Export`/`Import` — the runner advances `signCount` in memory only),
- test assertions,
- retry/backoff policy.

It also does **not** become "an HTTP client" in the README sense: it issues exactly the two POSTs a
ceremony needs and returns. The "not an HTTP client" scope statement gains one caveat — ③ is an
**opt-in** convenience, isolated in its own namespace.

---

## 1. Where endpoints and the begin body come from

The descriptor knows where options live in the begin **response** (`begin.optionsPath`) but carries
**no** endpoint URLs and **no** begin **request body**. DemoClient hardcodes `/attestation/options`,
`/assertion/options`, and `{ "username": ... }`.

Decision (v1): **the caller passes these as method parameters.** This keeps the descriptor schema
untouched, the change fully backward-compatible, and the runner a single file. A future declarative
`transport` descriptor section (begin/finish paths + a `{{ctx.*}}` begin-body template) is a
separate, larger feature and is explicitly out of scope here.

---

## 2. Public surface

New namespace `WebAuthnTestKit.Flow`, one type, isolated as the only code that touches `HttpClient`.

```csharp
namespace WebAuthnTestKit.Flow;

/// <summary>
/// Optional layer ③: sequences begin → device → finish for one ceremony over a caller-injected
/// HttpClient. The injected client carries session continuity (cookies / CSRF / bearer); the runner
/// never creates a client of its own. Pure plumbing — persistence, tokens and assertions stay the
/// caller's (design.en.md §6).
/// </summary>
public sealed class WebAuthnFlowRunner
{
    public WebAuthnFlowRunner(HttpClient http, TestKit kit);

    public Task<FlowResult> RegisterAsync(
        string service,
        VirtualAuthenticator device,
        string beginPath,
        string finishPath,
        JsonNode beginBody,
        Action<HttpRequestMessage>? configureRequest = null,
        CancellationToken ct = default);

    public Task<FlowResult> AuthenticateAsync(
        string service,
        VirtualAuthenticator device,
        string beginPath,
        string finishPath,
        JsonNode beginBody,
        string? userVerification = null,                  // "required" | "preferred" | "discouraged"; merged into the begin body when set
        Action<HttpRequestMessage>? configureRequest = null,
        CancellationToken ct = default);
}

/// <summary>Outcome of one ceremony driven end-to-end.</summary>
public sealed record FlowResult(
    CeremonyResult Result,        // success / PrimaryToken / Values / Raw finish response (from ②)
    byte[] CredentialId,          // the credential exercised (register: the new one; auth: the signer)
    JsonNode BeginResponse,       // raw begin JSON, for assertions/debug
    EnvelopeDebugInfo? Debug);    // codec.LastDebug from the EncodeFinish step
```

Notes.

- `CredentialId` is surfaced because register today returns it separately
  (`attestation.CredentialId`) and callers need it; ② alone doesn't put it in `CeremonyResult`.
- `userVerification` is an optional knob. When `null` (default) the begin body is sent untouched;
  when a value is passed the runner **merges** `["userVerification"] = value` into the begin body
  before sending (the caller no longer hand-builds the field — equivalent to DemoClient's `--uv`
  flag). The field name follows the WebAuthn-standard `userVerification`; services that name it
  differently skip this argument and write it into `beginBody` directly. For registration, pass it in
  `RegisterAsync`'s `beginBody` the same way if needed.
- `configureRequest` is the one extensibility hook (per-call headers / query). Optional, so the
  common call stays one line. Applied to **both** the begin and finish requests.
- No new HttpClient configuration knobs: base address, timeout, cookies, default headers and auth
  are properties of the **injected** client. That is what keeps continuity correct and the runner
  thin.

### Call shape (replacing DemoClient's hand-rolled flows)

```csharp
var runner = new WebAuthnFlowRunner(http, kit);   // http already logged in if needed

var reg = await runner.RegisterAsync("fido2-demo", device,
    "/attestation/options", "/attestation/result",
    new JsonObject { ["username"] = user });

var auth = await runner.AuthenticateAsync("fido2-demo", device,
    "/assertion/options", "/assertion/result",
    new JsonObject { ["username"] = user },
    userVerification: "required");             // optional; omit to send the begin body as-is

// caller still owns: device.Export() to persist signCount, token usage, Assert.True(auth.Result.Success)
```

---

## 3. Internal sequence

`RegisterAsync` (authentication is the mirror image via the assertion codec / `GetAssertion`,
and merges `userVerification` into `beginBody` before step 2 when the argument is set):

1. `codec = kit.Registration(service)` — fail-fast descriptor validation (unchanged ②).
2. `begin = POST beginPath, beginBody` → parse JSON.  *(step tag: `Begin`)*
3. `decoded = codec.DecodeOptions(begin)`.  *(`DecodeOptions`)*
4. `att = device.MakeCredential(decoded.Options)`.  *(`Sign`)*
5. `body = codec.EncodeFinish(att, decoded.Context)`; capture `codec.LastDebug`.  *(`EncodeFinish`)*
6. `finish = POST finishPath, body` → parse JSON.  *(`Finish`)*
7. `result = codec.DecodeResult(finish)`.  *(`DecodeResult`)*
8. return `FlowResult(result, att.CredentialId, begin, codec.LastDebug)`.

The single shared `POST` helper (mirroring DemoClient's) applies `configureRequest`, sends on the
injected client, and throws `WebAuthnFlowException` on a non-success status with the step tag, path,
status code and response body.

---

## 4. Errors and diagnostics — the real value-add

A typed exception that says **which step** failed and carries the codec diagnostics that are
otherwise scattered:

```csharp
public sealed class WebAuthnFlowException : Exception
{
    public FlowStep Step { get; }            // Begin | DecodeOptions | Sign | EncodeFinish | Finish | DecodeResult
    public string Service { get; }
    public EnvelopeDebugInfo? Debug { get; } // populated for EncodeFinish failures (unresolved {{templates}}, rpId, origin)
}

public enum FlowStep { Begin, DecodeOptions, Sign, EncodeFinish, Finish, DecodeResult }
```

- Non-success HTTP on begin/finish → `Step = Begin|Finish`, message includes status + body.
- `EncodeFinish` producing unresolved template variables (`LastDebug.UnresolvedTemplateVariables`)
  → throw with `Step = EncodeFinish` and `Debug` attached, instead of silently POSTing a body with
  literal `{{source.x}}` in it. This catches the most common descriptor mistake at the runner edge.
- `DecodeResult` with `Result.Success == false` is returned, **not** thrown — success/failure is a
  legitimate test outcome the caller asserts on. (Only protocol/transport faults throw.)

---

## 5. Plan of record (implementation steps, when greenlit)

1. `src/WebAuthnTestKit/Flow/WebAuthnFlowRunner.cs` — runner + `FlowResult` + `WebAuthnFlowException`
   + `FlowStep`. No other source files change (purely additive on top of ②).
2. **Unit tests** (`tests/WebAuthnTestKit.Tests`, `Category!=Integration`): a stub
   `HttpMessageHandler` returns canned begin/finish JSON — no network. Assert: correct sequencing,
   the same handler instance serves both POSTs (continuity), `configureRequest` is applied to both,
   `FlowResult` fields, and each `FlowStep` failure path (bad status, unresolved template,
   `Success=false` returned not thrown).
3. **Integration test** (`tests/WebAuthnTestKit.IntegrationTests`, Docker): reuse the existing
   Fido2NetLib container; run register + authenticate each in a single runner call and verify
   server-side, mirroring the existing 5 integration tests.
4. **Dogfood**: refactor `samples/DemoClient` `RegisterFlow`/`AuthFlow` onto the runner, deleting the
   hand-rolled `Post` plumbing — proves the runner absorbs exactly that glue.
5. **Docs**: in [design.en.md](design.en.md) / [design.md](design.md) move ③ from "the consumer
   implements" (§6) to "provided, opt-in"; update [status.md](status.md) roadmap + "Not implemented"
   list; add the README "Optional/future work" → "shipped" line and the scope caveat.

## 6. Open questions deferred (not v1)

- Declarative `transport` descriptor section (begin/finish paths + begin-body template) — would make
  the call `runner.RegisterAsync(service, device, ctx)`. Natural follow-on to §1.
- Cookie/CSRF helpers beyond "reuse the injected handler" (e.g. lifting a CSRF token from the begin
  response into the finish **header** — today only body `source.*` carry-over exists).
- A combined `RegisterAndAuthenticateAsync` convenience.
