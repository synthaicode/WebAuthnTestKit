using System.Buffers.Binary;
using System.Buffers.Text;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WebAuthnTestKit;
using Xunit;

namespace WebAuthnTestKit.Tests;

public class VirtualAuthenticatorTests
{
    private const string RpId = "example.com";
    private const string Origin = "https://example.com";

    private static CreationOptions Creation(byte[] challenge) => new(
        challenge,
        new RpEntity(RpId, "Example"),
        new UserEntity(Encoding.UTF8.GetBytes("user-123"), "alice", "Alice"),
        new[] { new PubKeyCredParam("public-key", PubKeyCredParam.Es256) },
        Origin);

    [Fact]
    public void MakeCredential_produces_valid_clientData_and_attestedData()
    {
        var device = new VirtualAuthenticator(new());
        var challenge = RandomNumberGenerator.GetBytes(32);

        var att = device.MakeCredential(Creation(challenge));

        // clientDataJSON
        using var doc = JsonDocument.Parse(att.ClientDataJson);
        var root = doc.RootElement;
        Assert.Equal("webauthn.create", root.GetProperty("type").GetString());
        Assert.Equal(Origin, root.GetProperty("origin").GetString());
        Assert.Equal(challenge, Base64Url.DecodeFromChars(root.GetProperty("challenge").GetString()));

        // authData from attestationObject
        var (authData, _) = ExtractFromAttestation(att.AttestationObject);
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(RpId)), authData[..32]);
        var flags = authData[32];
        Assert.True((flags & 0x01) != 0, "UP set");
        Assert.True((flags & 0x04) != 0, "UV set");
        Assert.True((flags & 0x40) != 0, "AT set");
    }

    [Fact]
    public void GetAssertion_signature_verifies_against_registered_public_key()
    {
        var device = new VirtualAuthenticator(new());
        var att = device.MakeCredential(Creation(RandomNumberGenerator.GetBytes(32)));
        var publicKey = ImportPublicKeyFromAttestation(att.AttestationObject);

        var challenge = RandomNumberGenerator.GetBytes(32);
        var assertion = device.GetAssertion(new RequestOptions(challenge, RpId, Array.Empty<AllowCredential>(), Origin));

        var signedData = Concat(assertion.AuthenticatorData, SHA256.HashData(assertion.ClientDataJson));
        var ok = publicKey.VerifyData(signedData, assertion.Signature,
            HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        Assert.True(ok, "assertion signature must verify against the registered public key");

        using var cd = JsonDocument.Parse(assertion.ClientDataJson);
        Assert.Equal("webauthn.get", cd.RootElement.GetProperty("type").GetString());
        Assert.Equal(challenge, Base64Url.DecodeFromChars(cd.RootElement.GetProperty("challenge").GetString()));
    }

    [Fact]
    public void GetAssertion_advances_sign_counter()
    {
        var device = new VirtualAuthenticator(new());
        device.MakeCredential(Creation(RandomNumberGenerator.GetBytes(32)));

        var first = SignCount(device.GetAssertion(Request()));
        var second = SignCount(device.GetAssertion(Request()));

        Assert.Equal(1u, first);
        Assert.Equal(2u, second);
    }

    [Fact]
    public void GetAssertion_throws_when_no_credential_matches_allowList()
    {
        var device = new VirtualAuthenticator(new());
        device.MakeCredential(Creation(RandomNumberGenerator.GetBytes(32)));

        var unknown = new[] { new AllowCredential("public-key", RandomNumberGenerator.GetBytes(32)) };
        Assert.Throws<InvalidOperationException>(() =>
            device.GetAssertion(new RequestOptions(RandomNumberGenerator.GetBytes(32), RpId, unknown, Origin)));
    }

    [Fact]
    public void ExportImport_preserves_sign_counter()
    {
        var device = new VirtualAuthenticator(new());
        device.MakeCredential(Creation(RandomNumberGenerator.GetBytes(32)));
        device.GetAssertion(Request());                 // counter -> 1

        var restored = VirtualAuthenticator.Import(device.Export());
        var next = SignCount(restored.GetAssertion(Request()));

        Assert.Equal(2u, next);                          // continues, not reset
    }

    // ── helpers ─────────────────────────────────────────────

    private static RequestOptions Request() =>
        new(RandomNumberGenerator.GetBytes(32), RpId, Array.Empty<AllowCredential>(), Origin);

    private static uint SignCount(AssertionResult a) =>
        BinaryPrimitives.ReadUInt32BigEndian(a.AuthenticatorData.AsSpan(33, 4));

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        a.CopyTo(r, 0);
        b.CopyTo(r, a.Length);
        return r;
    }

    private static (byte[] AuthData, byte[] CosePublicKey) ExtractFromAttestation(byte[] attestationObject)
    {
        var reader = new CborReader(attestationObject);
        var count = reader.ReadStartMap();
        byte[] authData = Array.Empty<byte>();
        for (var i = 0; i < count; i++)
        {
            var key = reader.ReadTextString();
            if (key == "authData") authData = reader.ReadByteString();
            else reader.SkipValue();
        }
        reader.ReadEndMap();

        // authData: rpIdHash(32) flags(1) signCount(4) aaguid(16) credIdLen(2) credId(n) cose(rest)
        var credIdLen = BinaryPrimitives.ReadUInt16BigEndian(authData.AsSpan(53, 2));
        var coseOffset = 55 + credIdLen;
        var cose = authData[coseOffset..];
        return (authData, cose);
    }

    private static ECDsa ImportPublicKeyFromAttestation(byte[] attestationObject)
    {
        var (_, cose) = ExtractFromAttestation(attestationObject);
        var reader = new CborReader(cose);
        var count = reader.ReadStartMap();
        byte[] x = Array.Empty<byte>(), y = Array.Empty<byte>();
        for (var i = 0; i < count; i++)
        {
            var label = reader.ReadInt32();
            switch (label)
            {
                case -2: x = reader.ReadByteString(); break;
                case -3: y = reader.ReadByteString(); break;
                default: reader.SkipValue(); break;
            }
        }
        reader.ReadEndMap();

        return ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = x, Y = y },
        });
    }
}
