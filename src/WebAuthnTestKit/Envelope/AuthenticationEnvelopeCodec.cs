using System.Text;
using System.Text.Json.Nodes;

namespace WebAuthnTestKit;

/// <summary>Envelope codec for the authentication (assertion) ceremony of one service.</summary>
public sealed class AuthenticationEnvelopeCodec
    : EnvelopeCodecBase, IEnvelopeCodec<RequestOptions, AssertionResult>
{
    public AuthenticationEnvelopeCodec(ServiceDescriptor descriptor)
        : base(descriptor, CeremonyKind.Assertion) { }

    public DecodedOptions<RequestOptions> DecodeOptions(JsonNode beginResponse)
    {
        var begin = Ceremony.Begin;
        var options = RequireOptions(beginResponse);

        var challenge = EnvelopeEngine.Decode(RequireString(options, "challenge", Descriptor.Service), begin.ChallengeEncoding);

        var allow = (options["allowCredentials"] as JsonArray)?
            .OfType<JsonObject>()
            .Select(c => new AllowCredential(
                (c["type"] as JsonValue)?.GetValue<string>() ?? "public-key",
                EnvelopeEngine.Decode(RequireString(c, "id", Descriptor.Service), begin.CredentialIdEncoding)))
            .ToArray() ?? [];

        var request = new RequestOptions(challenge, Descriptor.Rp.Id, allow, Descriptor.Rp.Origin);
        return new DecodedOptions<RequestOptions>(request, new EnvelopeContext(beginResponse));
    }

    public JsonNode EncodeFinish(AssertionResult d, EnvelopeContext context)
    {
        var rawId = EnvelopeEngine.Encode(d.CredentialId, "base64url");
        var clientData = EnvelopeEngine.Encode(d.ClientDataJson, "base64url");
        var authData = EnvelopeEngine.Encode(d.AuthenticatorData, "base64url");
        var signature = EnvelopeEngine.Encode(d.Signature, "base64url");
        var userHandle = d.UserHandle is null ? null : EnvelopeEngine.Encode(d.UserHandle, "base64url");

        var response = new JsonObject
        {
            ["clientDataJSON"] = clientData,
            ["authenticatorData"] = authData,
            ["signature"] = signature,
            ["userHandle"] = userHandle,
        };
        var assertionJson = new JsonObject
        {
            ["id"] = rawId,
            ["rawId"] = rawId,
            ["type"] = "public-key",
            ["response"] = response,
        };
        var assertionJsonStr = SerializeToString(assertionJson);

        var values = new Dictionary<string, string>
        {
            ["credentialId"] = rawId,
            ["rawId"] = rawId,
            ["clientDataJSON"] = clientData,
            ["authenticatorData"] = authData,
            ["signature"] = signature,
            ["userHandle"] = userHandle ?? "",
            ["assertionJson"] = assertionJsonStr,
            ["assertionJsonBase64Url"] = EnvelopeEngine.Encode(Encoding.UTF8.GetBytes(assertionJsonStr), "base64url"),
        };

        return BuildFinish(values, context, d.CredentialId);
    }

    public CeremonyResult DecodeResult(JsonNode finishResponse) => DecodeResultCore(finishResponse);
}
