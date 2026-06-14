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

    var creds = Store.CredentialsFor(username);
    lock (creds)
        creds.Add(new CredentialRecord
        {
            CredentialId = credential.Id,
            PublicKey = credential.PublicKey,
            SignCount = credential.SignCount,
            UserHandle = System.Text.Encoding.UTF8.GetBytes(username),
        });

    return Results.Json(new JsonObject { ["status"] = "ok", ["credentialCount"] = creds.Count });
});

// ── Authentication ──────────────────────────────────────────
app.MapPost("/assertion/options", async (HttpContext ctx) =>
{
    var body = await ReadJson(ctx);
    var username = body["username"]!.GetValue<string>();
    var creds = Store.CredentialsFor(username);
    List<CredentialRecord> snapshot;
    lock (creds) snapshot = creds.ToList();
    if (snapshot.Count == 0)
        return Results.BadRequest(new JsonObject { ["status"] = "error", ["message"] = "unknown user" });

    var userVerification = body["userVerification"]?.GetValue<string>() switch
    {
        "required" => UserVerificationRequirement.Required,
        "discouraged" => UserVerificationRequirement.Discouraged,
        _ => UserVerificationRequirement.Preferred,
    };

    var options = fido2.GetAssertionOptions(new GetAssertionOptionsParams
    {
        // Offer every credential registered to this user, so any of their devices can sign.
        AllowedCredentials = snapshot.Select(c => new PublicKeyCredentialDescriptor(c.CredentialId)).ToList(),
        UserVerification = userVerification,
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
    if (!Store.AssertionOptions.TryGetValue(username, out var options))
        return Results.BadRequest(new JsonObject { ["status"] = "error", ["message"] = "no pending assertion" });

    var raw = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(body["assertion"]!.ToJsonString())!;

    // Select the specific credential the device signed with (by credential id) among the user's devices.
    var creds = Store.CredentialsFor(username);
    CredentialRecord? cred;
    lock (creds) cred = creds.Find(c => c.CredentialId.AsSpan().SequenceEqual(raw.RawId));
    if (cred is null)
        return Results.BadRequest(new JsonObject { ["status"] = "error", ["message"] = "unknown credential" });

    var result = await fido2.MakeAssertionAsync(new MakeAssertionParams
    {
        AssertionResponse = raw,
        OriginalOptions = options,
        StoredPublicKey = cred.PublicKey,
        StoredSignatureCounter = cred.SignCount,
        IsUserHandleOwnerOfCredentialIdCallback = (args, _) =>
            Task.FromResult(args.UserHandle.AsSpan().SequenceEqual(cred.UserHandle)),
    }, ctx.RequestAborted);

    lock (creds) cred.SignCount = result.SignCount;

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

internal sealed class CredentialRecord
{
    public required byte[] CredentialId { get; init; }
    public required byte[] PublicKey { get; init; }
    public required byte[] UserHandle { get; init; }
    public uint SignCount { get; set; }
}

internal static class Store
{
    public static readonly ConcurrentDictionary<string, CredentialCreateOptions> RegistrationOptions = new();
    public static readonly ConcurrentDictionary<string, AssertionOptions> AssertionOptions = new();

    // One user may register many devices (passkeys), so each maps to a list of credentials.
    public static readonly ConcurrentDictionary<string, List<CredentialRecord>> Credentials = new();

    public static List<CredentialRecord> CredentialsFor(string username) =>
        Credentials.GetOrAdd(username, _ => new List<CredentialRecord>());
}
