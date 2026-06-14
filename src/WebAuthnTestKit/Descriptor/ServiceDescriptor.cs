using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace WebAuthnTestKit;

/// <summary>Which ceremony a descriptor section / codec applies to.</summary>
public enum CeremonyKind
{
    Registration,
    Assertion,
}

/// <summary>
/// Declarative, per-service mapping between an application's WebAuthn API envelope and the
/// standard WebAuthn structures. Deserialized from the JSON descriptor format.
/// </summary>
public sealed class ServiceDescriptor
{
    [JsonPropertyName("service")] public string Service { get; set; } = "";
    [JsonPropertyName("rp")] public RpDescriptor Rp { get; set; } = new();
    [JsonPropertyName("registration")] public CeremonyDescriptor? Registration { get; set; }
    [JsonPropertyName("assertion")] public CeremonyDescriptor? Assertion { get; set; }

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>Parses a JSON descriptor. Does not validate; codecs validate on construction.</summary>
    public static ServiceDescriptor Parse(string json) =>
        JsonSerializer.Deserialize<ServiceDescriptor>(json, Json)
        ?? throw new ArgumentException("Descriptor JSON deserialized to null.", nameof(json));

    public CeremonyDescriptor Ceremony(CeremonyKind kind) =>
        (kind == CeremonyKind.Registration ? Registration : Assertion)
        ?? throw new InvalidOperationException(
            $"Descriptor '{Service}' has no '{kind.ToString().ToLowerInvariant()}' section.");
}

public sealed class RpDescriptor
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("origin")] public string Origin { get; set; } = "";
}

public sealed class CeremonyDescriptor
{
    [JsonPropertyName("begin")] public BeginDescriptor Begin { get; set; } = new();
    [JsonPropertyName("finish")] public FinishDescriptor Finish { get; set; } = new();
}

public sealed class BeginDescriptor
{
    [JsonPropertyName("optionsPath")] public string OptionsPath { get; set; } = "";
    [JsonPropertyName("challengeEncoding")] public string ChallengeEncoding { get; set; } = "base64url";
    [JsonPropertyName("userIdEncoding")] public string UserIdEncoding { get; set; } = "base64url";
    [JsonPropertyName("credentialIdEncoding")] public string CredentialIdEncoding { get; set; } = "base64url";
}

public sealed class FinishDescriptor
{
    /// <summary>Template object for the finish request body; string leaves may contain <c>{{...}}</c>.</summary>
    [JsonPropertyName("body")] public JsonObject Body { get; set; } = new();
    [JsonPropertyName("result")] public ResultDescriptor Result { get; set; } = new();
}

public sealed class ResultDescriptor
{
    /// <summary>JSON path to the representative token, surfaced as <c>CeremonyResult.PrimaryToken</c>.</summary>
    [JsonPropertyName("tokenPath")] public string? TokenPath { get; set; }

    /// <summary>Optional condition (e.g. <c>$.status == 'ok'</c>) deciding <c>CeremonyResult.Success</c>.</summary>
    [JsonPropertyName("successWhen")] public string? SuccessWhen { get; set; }

    /// <summary>Optional name → JSON path map populating <c>CeremonyResult.Values</c>.</summary>
    [JsonPropertyName("values")] public Dictionary<string, string>? Values { get; set; }
}
