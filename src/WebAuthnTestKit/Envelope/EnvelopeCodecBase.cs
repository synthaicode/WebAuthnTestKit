using System.Text.Json;
using System.Text.Json.Nodes;

namespace WebAuthnTestKit;

/// <summary>Shared mechanics for the per-ceremony codecs (descriptor binding, finish/result handling).</summary>
public abstract class EnvelopeCodecBase
{
    protected ServiceDescriptor Descriptor { get; }
    protected CeremonyDescriptor Ceremony { get; }

    /// <inheritdoc cref="IEnvelopeCodec{TOptions,TFinish}.LastDebug"/>
    public EnvelopeDebugInfo? LastDebug { get; private set; }

    protected EnvelopeCodecBase(ServiceDescriptor descriptor, CeremonyKind kind)
    {
        DescriptorValidator.Validate(descriptor, kind);   // fail-fast at construction
        Descriptor = descriptor;
        Ceremony = descriptor.Ceremony(kind);
    }

    /// <summary>Builds the finish body from a values bag, resolving source.* against the begin context.</summary>
    protected JsonNode BuildFinish(IReadOnlyDictionary<string, string> values, EnvelopeContext context, byte[] credentialId)
    {
        var resolved = new List<string>();
        var unresolved = new List<string>();
        var body = EnvelopeEngine.Fill(
            Ceremony.Finish.Body, values, context.BeginResponse, context.UserContext, resolved, unresolved);

        LastDebug = new EnvelopeDebugInfo(
            RpId: Descriptor.Rp.Id,
            Origin: Descriptor.Rp.Origin,
            ChallengeBase64Url: ChallengeFromClientData(values),
            CredentialIdBase64Url: EnvelopeEngine.Encode(credentialId, "base64url"),
            OptionsPath: Ceremony.Begin.OptionsPath,
            ResolvedTemplateVariables: resolved,
            UnresolvedTemplateVariables: unresolved);

        return body;
    }

    /// <summary>Extracts the signed challenge (base64url) from the device's clientDataJSON for debug.</summary>
    private static string ChallengeFromClientData(IReadOnlyDictionary<string, string> values)
    {
        if (!values.TryGetValue("clientDataJSON", out var clientData))
            return "";
        try
        {
            using var doc = JsonDocument.Parse(EnvelopeEngine.Decode(clientData, "base64url"));
            return doc.RootElement.TryGetProperty("challenge", out var c) ? c.GetString() ?? "" : "";
        }
        catch
        {
            return "";
        }
    }

    /// <summary>Shared finish-response decoding (token, values, success).</summary>
    protected CeremonyResult DecodeResultCore(JsonNode finishResponse)
    {
        var result = Ceremony.Finish.Result;

        string? token = result.TokenPath is { } tp
            ? EnvelopeEngine.Resolve(finishResponse, tp)?.ToString()
            : null;

        var values = new Dictionary<string, string>();
        if (result.Values is { } map)
            foreach (var (name, path) in map)
                if (EnvelopeEngine.Resolve(finishResponse, path)?.ToString() is { } v)
                    values[name] = v;

        var success = result.SuccessWhen is { } cond
            ? EnvelopeEngine.Eval(finishResponse, cond)
            : token is not null || values.Count > 0;

        return new CeremonyResult(success, token, values, finishResponse);
    }

    protected JsonObject RequireOptions(JsonNode beginResponse)
    {
        var node = EnvelopeEngine.Resolve(beginResponse, Ceremony.Begin.OptionsPath);
        if (node is not JsonObject obj)
            throw new InvalidOperationException(
                $"Options not found at '{Ceremony.Begin.OptionsPath}' in begin response for '{Descriptor.Service}'.");
        return obj;
    }

    protected static string RequireString(JsonObject options, string field, string service)
    {
        if (options[field] is JsonValue v && v.TryGetValue(out string? s) && s is not null)
            return s;
        throw new InvalidOperationException($"Missing/invalid '{field}' in begin options for '{service}'.");
    }

    protected static string SerializeToString(JsonObject obj) =>
        obj.ToJsonString(new JsonSerializerOptions { WriteIndented = false });
}
