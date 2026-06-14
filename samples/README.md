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

Registration and authentication are **separate commands**, so you can enrol devices independently
of signing in.

```bash
# 1) register a new device (saves its DeviceState; does NOT authenticate)
dotnet run --project samples/DemoClient -- register --user alice --state alice.device.json

# 2) authenticate later with that device (counter persists; --uv requires user verification)
dotnet run --project samples/DemoClient -- auth --user alice --state alice.device.json --uv

# multiple devices on one account: register two and authenticate with each
dotnet run --project samples/DemoClient -- register --user alice --state alice-phone.json
dotnet run --project samples/DemoClient -- register --user alice --state alice-laptop.json
dotnet run --project samples/DemoClient -- auth --user alice --state alice-phone.json
dotnet run --project samples/DemoClient -- auth --user alice --state alice-laptop.json

# one-shot demo of the above (registers two devices, authenticates with each)
dotnet run --project samples/DemoClient -- demo --user alice
```

Commands: `register` (new device → `--state` file, required), `auth` (existing `--state` device),
`demo` (registers two devices to one account and authenticates with each).
Common options: `--server <url>` (default `http://localhost:8080`), `--user <name>` (default
`alice`), `--descriptor <path>`, `--uv` (request `userVerification=required`; the default device
sets the UV flag and is accepted).

> The demo server stores **multiple credentials per user**, so one account can enrol many devices.
> Integration tests cover this (two devices each authenticate) plus `userVerification=required`
> both ways: a UV-capable device is accepted, and a device that does not set the UV flag is rejected.
