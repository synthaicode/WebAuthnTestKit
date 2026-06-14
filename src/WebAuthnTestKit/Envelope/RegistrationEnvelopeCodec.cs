using System.Text;
using System.Text.Json.Nodes;

namespace WebAuthnTestKit;

/// <summary>Envelope codec for the registration ceremony of one service.</summary>
public sealed class RegistrationEnvelopeCodec
    : EnvelopeCodecBase, IEnvelopeCodec<CreationOptions, AttestationResult>
{
    public RegistrationEnvelopeCodec(ServiceDescriptor descriptor)
        : base(descriptor, CeremonyKind.Registration) { }

    public DecodedOptions<CreationOptions> DecodeOptions(JsonNode beginResponse)
    {
        var begin = Ceremony.Begin;
        var options = RequireOptions(beginResponse);

        var challenge = EnvelopeEngine.Decode(RequireString(options, "challenge", Descriptor.Service), begin.ChallengeEncoding);

        var userNode = options["user"] as JsonObject
            ?? throw new InvalidOperationException($"Missing 'user' in begin options for '{Descriptor.Service}'.");
        var user = new UserEntity(
            EnvelopeEngine.Decode(RequireString(userNode, "id", Descriptor.Service), begin.UserIdEncoding),
            (userNode["name"] as JsonValue)?.GetValue<string>() ?? "",
            (userNode["displayName"] as JsonValue)?.GetValue<string>() ?? "");

        var prms = (options["pubKeyCredParams"] as JsonArray)?
            .OfType<JsonObject>()
            .Select(p => new PubKeyCredParam(
                (p["type"] as JsonValue)?.GetValue<string>() ?? "public-key",
                (p["alg"] as JsonValue)?.GetValue<int>() ?? PubKeyCredParam.Es256))
            .ToArray();
        if (prms is null || prms.Length == 0)
            prms = [new PubKeyCredParam("public-key", PubKeyCredParam.Es256)];

        var rp = new RpEntity(Descriptor.Rp.Id, (options["rp"]?["name"] as JsonValue)?.GetValue<string>());
        var creation = new CreationOptions(challenge, rp, user, prms, Descriptor.Rp.Origin);
        return new DecodedOptions<CreationOptions>(creation, new EnvelopeContext(beginResponse));
    }

    public JsonNode EncodeFinish(AttestationResult d, EnvelopeContext context)
    {
        var rawId = EnvelopeEngine.Encode(d.CredentialId, "base64url");
        var clientData = EnvelopeEngine.Encode(d.ClientDataJson, "base64url");
        var attObj = EnvelopeEngine.Encode(d.AttestationObject, "base64url");

        var attestationJson = new JsonObject
        {
            ["id"] = rawId,
            ["rawId"] = rawId,
            ["type"] = "public-key",
            ["response"] = new JsonObject
            {
                ["clientDataJSON"] = clientData,
                ["attestationObject"] = attObj,
            },
        };
        var attestationJsonStr = SerializeToString(attestationJson);

        var values = new Dictionary<string, string>
        {
            ["credentialId"] = rawId,
            ["rawId"] = rawId,
            ["clientDataJSON"] = clientData,
            ["attestationObject"] = attObj,
            ["attestationJson"] = attestationJsonStr,
            ["attestationJsonBase64Url"] = EnvelopeEngine.Encode(Encoding.UTF8.GetBytes(attestationJsonStr), "base64url"),
        };

        return BuildFinish(values, context, d.CredentialId);
    }

    public CeremonyResult DecodeResult(JsonNode finishResponse) => DecodeResultCore(finishResponse);
}
