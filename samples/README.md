# Samples

## `descriptors/fido2-demo.json`

A JSON envelope descriptor for the demo server below. It shows the typical shape:

- options nested under `$.publicKey`
- a `username` carried from the begin response into the finish body via `{{source.username}}`
- the standard credential fields (`{{credentialId}}`, `{{clientDataJSON}}`,
  `{{attestationObject}}` / `{{authenticatorData}}` + `{{signature}}`) wrapped under an
  app-specific `attestation` / `assertion` object
- `result.tokenPath` / `result.successWhen` to read the outcome

## `Fido2DemoServer/`

A minimal, **independent** WebAuthn verification server built on
[Fido2NetLib](https://github.com/passwordless-lib/fido2-net-lib). It exposes a small REST API:

| Endpoint | Purpose |
|---|---|
| `POST /attestation/options` | begin registration |
| `POST /attestation/result`  | finish registration (verifies attestation) |
| `POST /assertion/options`   | begin authentication |
| `POST /assertion/result`    | finish authentication (verifies signature + counter) |

It is used by `tests/WebAuthnTestKit.IntegrationTests` via Testcontainers: the image is built
from the `Dockerfile`, run in a container, and driven end-to-end by the kit. Because the server
genuinely checks origin, challenge, signature, and the signature counter, a passing integration
test proves the kit produces valid WebAuthn output.

Run it standalone:

```bash
docker build -t fido2-demo samples/Fido2DemoServer
docker run -p 8080:8080 fido2-demo
```

## `DemoClient/`

A runnable console client for the demo server, showing the **consumer side** of the kit: the kit
does `JSON <-> signature <-> JSON`, while the client owns the HTTP transport, the begin/finish
continuity, token usage, and device-state persistence (design.md §6).

```bash
# with the demo server running (Docker on :8080, or `dotnet run` on its launch port):
dotnet run --project samples/DemoClient -- --server http://localhost:8080 --user alice

# persist the device so the signature counter survives across runs:
dotnet run --project samples/DemoClient -- --server http://localhost:8080 --state device.json
```

Options: `--server <url>` (default `http://localhost:8080`), `--user <name>` (default `alice`),
`--descriptor <path>` (defaults to `samples/descriptors/fido2-demo.json`), `--state <path>`
(restore/save `DeviceState`; when present, registration is skipped and only authentication runs,
demonstrating the counter advancing on the real server).
