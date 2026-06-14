using System.Buffers.Binary;
using System.Buffers.Text;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WebAuthnTestKit;

/// <summary>
/// Software (pseudo) FIDO2/WebAuthn authenticator for tests. Generates registration
/// (<see cref="MakeCredential"/>) and authentication (<see cref="GetAssertion"/>) ceremony outputs
/// without a browser or a physical key.
/// </summary>
/// <remarks>
/// Initial scope: ES256 only, attestation format <c>none</c>. <see cref="GetAssertion"/> mutates
/// state (advances the signature counter); call <see cref="Export"/> after authentication to
/// persist it, and <see cref="Import"/> to restore a device for reproducible tests.
/// </remarks>
public sealed class VirtualAuthenticator
{
    // Authenticator data flag bits (WebAuthn §6.1).
    private const byte FlagUserPresent = 0x01;
    private const byte FlagUserVerified = 0x04;
    private const byte FlagAttestedCredentialData = 0x40;

    private readonly VirtualAuthenticatorOptions _options;
    private readonly List<Credential> _credentials = new();

    public VirtualAuthenticator(VirtualAuthenticatorOptions options)
    {
        if (options.Algorithm != PubKeyCredParam.Es256)
            throw new NotSupportedException(
                $"Only ES256 (alg=-7) is supported; got alg={options.Algorithm}.");
        _options = options;
    }

    /// <summary>Performs a registration ceremony and stores the new credential on the device.</summary>
    public AttestationResult MakeCredential(CreationOptions options)
    {
        if (Array.FindIndex(options.Params, p => p.Alg == PubKeyCredParam.Es256) < 0)
            throw new NotSupportedException("RP does not offer ES256 (alg=-7); device supports only ES256.");

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pkcs8 = ecdsa.ExportPkcs8PrivateKey();
        var credentialId = RandomNumberGenerator.GetBytes(32);

        var clientDataJson = BuildClientData("webauthn.create", options.Challenge, options.Origin);
        var cosePublicKey = EncodeCoseEs256PublicKey(ecdsa);
        var attestedCredentialData = BuildAttestedCredentialData(credentialId, cosePublicKey);

        var flags = (byte)(UserFlags() | FlagAttestedCredentialData);
        var authData = BuildAuthenticatorData(options.Rp.Id, flags, signCount: 0, attestedCredentialData);
        var attestationObject = EncodeNoneAttestationObject(authData);

        _credentials.Add(new Credential
        {
            CredentialId = credentialId,
            RpId = options.Rp.Id,
            UserHandle = options.User.Id,
            PrivateKeyPkcs8 = pkcs8,
            SignCount = 0,
        });

        return new AttestationResult(credentialId, clientDataJson, attestationObject);
    }

    /// <summary>Performs an authentication ceremony, advancing the matched credential's counter.</summary>
    public AssertionResult GetAssertion(RequestOptions options)
    {
        var credential = SelectCredential(options);

        var newCount = credential.SignCount + 1;
        var clientDataJson = BuildClientData("webauthn.get", options.Challenge, options.Origin);
        var authData = BuildAuthenticatorData(options.RpId, UserFlags(), newCount, attestedCredentialData: null);

        var signedData = Concat(authData, SHA256.HashData(clientDataJson));
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(credential.PrivateKeyPkcs8, out _);
        var signature = ecdsa.SignData(signedData, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        credential.SignCount = newCount;
        return new AssertionResult(credential.CredentialId, clientDataJson, authData, signature, credential.UserHandle);
    }

    /// <summary>Snapshots device identity and stored credentials (including signature counters).</summary>
    public DeviceState Export() => new(
        _options.Aaguid,
        _options.Algorithm,
        _options.SupportsResidentKey,
        _options.UserPresent,
        _options.UserVerified,
        _credentials.ConvertAll(c => new StoredCredential(
            Clone(c.CredentialId)!, c.RpId, Clone(c.UserHandle), Clone(c.PrivateKeyPkcs8)!, c.SignCount)));

    /// <summary>Restores a device (identity + credentials) from a prior <see cref="Export"/>.</summary>
    public static VirtualAuthenticator Import(DeviceState state)
    {
        var device = new VirtualAuthenticator(new VirtualAuthenticatorOptions(
            state.Aaguid, state.Algorithm, state.SupportsResidentKey, state.UserPresent, state.UserVerified));
        foreach (var c in state.Credentials)
            device._credentials.Add(new Credential
            {
                CredentialId = Clone(c.CredentialId)!,
                RpId = c.RpId,
                UserHandle = Clone(c.UserHandle),
                PrivateKeyPkcs8 = Clone(c.PrivateKeyPkcs8)!,
                SignCount = c.SignCount,
            });
        return device;
    }

    private static byte[]? Clone(byte[]? value) => value is null ? null : (byte[])value.Clone();

    private Credential SelectCredential(RequestOptions options)
    {
        bool Allowed(Credential c) =>
            options.Allow.Length == 0 ||
            Array.Exists(options.Allow, a => a.Id.AsSpan().SequenceEqual(c.CredentialId));

        var match = _credentials.Find(c => c.RpId == options.RpId && Allowed(c));
        if (match is null)
            throw new InvalidOperationException(
                $"No matching credential in allowCredentials for rpId '{options.RpId}'.");
        return match;
    }

    private byte UserFlags()
    {
        byte flags = 0;
        if (_options.UserPresent) flags |= FlagUserPresent;
        if (_options.UserVerified) flags |= FlagUserVerified;
        return flags;
    }

    private static byte[] BuildClientData(string type, byte[] challenge, string origin)
    {
        var obj = new JsonObject
        {
            ["type"] = type,
            ["challenge"] = Base64Url.EncodeToString(challenge),
            ["origin"] = origin,
            ["crossOrigin"] = false,
        };
        return JsonSerializer.SerializeToUtf8Bytes(obj);
    }

    private byte[] BuildAuthenticatorData(string rpId, byte flags, uint signCount, byte[]? attestedCredentialData)
    {
        var rpIdHash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(rpId));
        var length = 32 + 1 + 4 + (attestedCredentialData?.Length ?? 0);
        var authData = new byte[length];

        rpIdHash.CopyTo(authData, 0);
        authData[32] = flags;
        BinaryPrimitives.WriteUInt32BigEndian(authData.AsSpan(33, 4), signCount);
        attestedCredentialData?.CopyTo(authData, 37);
        return authData;
    }

    private byte[] BuildAttestedCredentialData(byte[] credentialId, byte[] cosePublicKey)
    {
        var aaguid = _options.Aaguid.ToByteArray(bigEndian: true);   // RFC 4122 order, 16 bytes
        var data = new byte[16 + 2 + credentialId.Length + cosePublicKey.Length];

        aaguid.CopyTo(data, 0);
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(16, 2), (ushort)credentialId.Length);
        credentialId.CopyTo(data, 18);
        cosePublicKey.CopyTo(data, 18 + credentialId.Length);
        return data;
    }

    private static byte[] EncodeCoseEs256PublicKey(ECDsa ecdsa)
    {
        var p = ecdsa.ExportParameters(includePrivateParameters: false);
        var x = LeftPad(p.Q.X!, 32);
        var y = LeftPad(p.Q.Y!, 32);

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(5);
        writer.WriteInt32(1); writer.WriteInt32(2);     // kty: EC2
        writer.WriteInt32(3); writer.WriteInt32(-7);    // alg: ES256
        writer.WriteInt32(-1); writer.WriteInt32(1);    // crv: P-256
        writer.WriteInt32(-2); writer.WriteByteString(x);
        writer.WriteInt32(-3); writer.WriteByteString(y);
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] EncodeNoneAttestationObject(byte[] authData)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteTextString("fmt"); writer.WriteTextString("none");
        writer.WriteTextString("attStmt"); writer.WriteStartMap(0); writer.WriteEndMap();
        writer.WriteTextString("authData"); writer.WriteByteString(authData);
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] LeftPad(byte[] value, int size)
    {
        if (value.Length == size) return value;
        if (value.Length > size) throw new ArgumentException($"Value longer than {size} bytes.", nameof(value));
        var padded = new byte[size];
        value.CopyTo(padded, size - value.Length);
        return padded;
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result, 0);
        b.CopyTo(result, a.Length);
        return result;
    }

    private sealed class Credential
    {
        public required byte[] CredentialId { get; init; }
        public required string RpId { get; init; }
        public required byte[]? UserHandle { get; init; }
        public required byte[] PrivateKeyPkcs8 { get; init; }
        public uint SignCount { get; set; }
    }
}
