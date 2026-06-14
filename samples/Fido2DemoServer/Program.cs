using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using Fido2NetLib;
using Fido2NetLib.Objects;

// Minimal independent WebAuthn server (Fido2NetLib) used to integration-test WebAuthnTestKit.
// Envelope is intentionally app-specific: options nested under "publicKey", finish bodies wrap the
// standard credential under "attestation"/"assertion" alongside a carried-over "username".

var builder = WebApplication.CreateBuilder(args);

var rpId = Environment.GetEnvironmentVariable("FIDO_RPID") ?? "localhost";
var origin = Environment.GetEnvironmentVariable("FIDO_ORIGIN") ?? "https://localhost";

var fido2 = new Fido2(new Fido2Configuration
{
    ServerDomain = rpId,
    ServerName = "WebAuthnTestKit Demo",
    Origins = new HashSet<string>(StringComparer.Ordinal) { origin },
});

var app = builder.Build();

app.MapGet("/health", () => Results.Ok("ok"));

// ── Registration ────────────────────────────────────────────
app.MapPost("/attestation/options", async (HttpContext ctx) =>
{
    var body = await ReadJson(ctx);
    var username = body["username"]!.GetValue<string>();

    var options = fido2.RequestNewCredential(new RequestNewCredentialParams
    {
        User = new Fido2User
        {
            Id = System.Text.Encoding.UTF8.GetBytes(username),
            Name = username,
            DisplayName = body["displayName"]?.GetValue<string>() ?? username,
        },
        ExcludeCredentials = new List<PublicKeyCredentialDescriptor>(),
        AttestationPreference = AttestationConveyancePreference.None,
    });

    Store.RegistrationOptions[username] = options;
    return Results.Json(new JsonObject
    {
        ["status"] = "ok",
        ["username"] = username,
        ["publicKey"] = JsonNode.Parse(options.ToJson()),
    });
});

app.MapPost("/attestation/result", async (HttpContext ctx) =>
{
    var body = await ReadJson(ctx);
    var username = body["username"]!.GetValue<string>();
    if (!Store.RegistrationOptions.TryGetValue(username, out var options))
        return Results.BadRequest(new JsonObject { ["status"] = "error", ["message"] = "no pending registration" });

    var raw = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(body["attestation"]!.ToJsonString())!;

    var credential = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
    {
        AttestationResponse = raw,
        OriginalOptions = options,
        IsCredentialIdUniqueToUserCallback = static (_, _) => Task.FromResult(true),
    }, ctx.RequestAborted);

    Store.Credentials[username] = new CredentialRecord(
        credential.Id, credential.PublicKey, credential.SignCount,
        System.Text.Encoding.UTF8.GetBytes(username));

    return Results.Json(new JsonObject { ["status"] = "ok" });
});

// ── Authentication ──────────────────────────────────────────
app.MapPost("/assertion/options", async (HttpContext ctx) =>
{
    var body = await ReadJson(ctx);
    var username = body["username"]!.GetValue<string>();
    if (!Store.Credentials.TryGetValue(username, out var cred))
        return Results.BadRequest(new JsonObject { ["status"] = "error", ["message"] = "unknown user" });

    var options = fido2.GetAssertionOptions(new GetAssertionOptionsParams
    {
        AllowedCredentials = new[] { new PublicKeyCredentialDescriptor(cred.CredentialId) },
        UserVerification = UserVerificationRequirement.Preferred,
    });

    Store.AssertionOptions[username] = options;
    return Results.Json(new JsonObject
    {
        ["status"] = "ok",
        ["username"] = username,
        ["publicKey"] = JsonNode.Parse(options.ToJson()),
    });
});

app.MapPost("/assertion/result", async (HttpContext ctx) =>
{
    var body = await ReadJson(ctx);
    var username = body["username"]!.GetValue<string>();
    if (!Store.AssertionOptions.TryGetValue(username, out var options) ||
        !Store.Credentials.TryGetValue(username, out var cred))
        return Results.BadRequest(new JsonObject { ["status"] = "error", ["message"] = "no pending assertion" });

    var raw = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(body["assertion"]!.ToJsonString())!;

    var result = await fido2.MakeAssertionAsync(new MakeAssertionParams
    {
        AssertionResponse = raw,
        OriginalOptions = options,
        StoredPublicKey = cred.PublicKey,
        StoredSignatureCounter = cred.SignCount,
        IsUserHandleOwnerOfCredentialIdCallback = (args, _) =>
            Task.FromResult(args.UserHandle.AsSpan().SequenceEqual(cred.UserHandle)),
    }, ctx.RequestAborted);

    Store.Credentials[username] = cred with { SignCount = result.SignCount };

    return Results.Json(new JsonObject
    {
        ["status"] = "ok",
        ["token"] = $"session-{username}-{Guid.NewGuid():N}",
        ["signCount"] = result.SignCount,
    });
});

app.Run();

static async Task<JsonObject> ReadJson(HttpContext ctx) =>
    (JsonObject)(await JsonNode.ParseAsync(ctx.Request.Body))!;

internal sealed record CredentialRecord(byte[] CredentialId, byte[] PublicKey, uint SignCount, byte[] UserHandle);

internal static class Store
{
    public static readonly ConcurrentDictionary<string, CredentialCreateOptions> RegistrationOptions = new();
    public static readonly ConcurrentDictionary<string, AssertionOptions> AssertionOptions = new();
    public static readonly ConcurrentDictionary<string, CredentialRecord> Credentials = new();
}
