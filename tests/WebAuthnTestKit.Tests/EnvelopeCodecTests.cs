using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using WebAuthnTestKit;
using Xunit;

namespace WebAuthnTestKit.Tests;

public class EnvelopeCodecTests
{
    private const string RpId = "example.com";
    private const string Origin = "https://example.com";

    private static string B64Url(byte[] b) => Base64Url.EncodeToString(b);

    [Fact]
    public void Registration_roundtrip_individual_fields_with_source_carryover()
    {
        var descriptor = ServiceDescriptor.Parse("""
        {
          "service": "svc",
          "rp": { "id": "example.com", "origin": "https://example.com" },
          "registration": {
            "begin": { "optionsPath": "$.data.publicKey" },
            "finish": {
              "body": {
                "registrationId": "{{source.data.registrationId}}",
                "credential": {
                  "id": "{{credentialId}}",
                  "type": "public-key",
                  "response": {
                    "clientDataJSON": "{{clientDataJSON}}",
                    "attestationObject": "{{attestationObject}}"
                  }
                }
              },
              "result": { "tokenPath": "$.data.session.jwt", "successWhen": "$.status == 'ok'" }
            }
          }
        }
        """);

        var codec = new RegistrationEnvelopeCodec(descriptor);
        var device = new VirtualAuthenticator(new());
        var challenge = RandomNumberGenerator.GetBytes(32);

        var begin = new JsonObject
        {
            ["data"] = new JsonObject
            {
                ["registrationId"] = "reg-123",
                ["publicKey"] = new JsonObject
                {
                    ["challenge"] = B64Url(challenge),
                    ["rp"] = new JsonObject { ["id"] = RpId, ["name"] = "Example" },
                    ["user"] = new JsonObject
                    {
                        ["id"] = B64Url(Encoding.UTF8.GetBytes("u-1")),
                        ["name"] = "alice",
                        ["displayName"] = "Alice",
                    },
                    ["pubKeyCredParams"] = new JsonArray(new JsonObject { ["type"] = "public-key", ["alg"] = -7 }),
                },
            },
        };

        var decoded = codec.DecodeOptions(begin);
        Assert.Equal(challenge, decoded.Options.Challenge);
        Assert.Equal(Origin, decoded.Options.Origin);

        var att = device.MakeCredential(decoded.Options);
        var body = codec.EncodeFinish(att, decoded.Context);

        Assert.Equal("reg-123", body["registrationId"]!.GetValue<string>());
        Assert.Equal(B64Url(att.CredentialId), body["credential"]!["id"]!.GetValue<string>());
        Assert.Equal(B64Url(att.AttestationObject), body["credential"]!["response"]!["attestationObject"]!.GetValue<string>());
        Assert.Empty(codec.LastDebug!.UnresolvedTemplateVariables);

        var finish = new JsonObject
        {
            ["status"] = "ok",
            ["data"] = new JsonObject { ["session"] = new JsonObject { ["jwt"] = "TOKEN-42" } },
        };
        var result = codec.DecodeResult(finish);
        Assert.True(result.Success);
        Assert.Equal("TOKEN-42", result.PrimaryToken);
    }

    [Fact]
    public void Assertion_roundtrip_whole_object_base64url()
    {
        var descriptor = ServiceDescriptor.Parse("""
        {
          "service": "svc",
          "rp": { "id": "example.com", "origin": "https://example.com" },
          "assertion": {
            "begin": { "optionsPath": "$.publicKey" },
            "finish": {
              "body": { "requestId": "{{source.requestId}}", "fidoAssertion": "{{assertionJsonBase64Url}}" },
              "result": { "tokenPath": "$.token", "values": { "refresh": "$.refreshToken" } }
            }
          }
        }
        """);

        // register a credential first
        var device = new VirtualAuthenticator(new());
        var att = device.MakeCredential(new CreationOptions(
            RandomNumberGenerator.GetBytes(32),
            new RpEntity(RpId),
            new UserEntity(Encoding.UTF8.GetBytes("u-1"), "alice", "Alice"),
            [new PubKeyCredParam("public-key", -7)],
            Origin));

        var codec = new AuthenticationEnvelopeCodec(descriptor);
        var challenge = RandomNumberGenerator.GetBytes(32);
        var begin = new JsonObject
        {
            ["requestId"] = "req-9",
            ["publicKey"] = new JsonObject
            {
                ["challenge"] = B64Url(challenge),
                ["allowCredentials"] = new JsonArray(new JsonObject
                {
                    ["type"] = "public-key",
                    ["id"] = B64Url(att.CredentialId),
                }),
            },
        };

        var decoded = codec.DecodeOptions(begin);
        Assert.Single(decoded.Options.Allow);

        var assertion = device.GetAssertion(decoded.Options);
        var body = codec.EncodeFinish(assertion, decoded.Context);

        Assert.Equal("req-9", body["requestId"]!.GetValue<string>());

        // unpack the whole-object base64url and confirm it carried the device output verbatim
        var packed = Base64Url.DecodeFromChars(body["fidoAssertion"]!.GetValue<string>());
        var inner = JsonNode.Parse(packed)!;
        Assert.Equal(B64Url(att.CredentialId), inner["rawId"]!.GetValue<string>());
        Assert.Equal(B64Url(assertion.Signature), inner["response"]!["signature"]!.GetValue<string>());
        Assert.Equal(B64Url(assertion.AuthenticatorData), inner["response"]!["authenticatorData"]!.GetValue<string>());
    }

    [Fact]
    public void DecodeResult_populates_values_and_failure()
    {
        var descriptor = ServiceDescriptor.Parse("""
        {
          "service": "svc",
          "rp": { "id": "example.com", "origin": "https://example.com" },
          "assertion": {
            "begin": { "optionsPath": "$.publicKey" },
            "finish": {
              "body": { "x": "{{signature}}" },
              "result": { "tokenPath": "$.token", "successWhen": "$.status == 'ok'",
                          "values": { "role": "$.user.role" } }
            }
          }
        }
        """);
        var codec = new AuthenticationEnvelopeCodec(descriptor);

        var finish = new JsonObject
        {
            ["status"] = "denied",
            ["token"] = "T",
            ["user"] = new JsonObject { ["role"] = "admin" },
        };
        var result = codec.DecodeResult(finish);

        Assert.False(result.Success);                    // successWhen failed
        Assert.Equal("admin", result.Values["role"]);
    }

    [Fact]
    public void Construction_fails_fast_on_unknown_template_variable()
    {
        var json = """
        {
          "service": "svc",
          "rp": { "id": "example.com", "origin": "https://example.com" },
          "registration": {
            "begin": { "optionsPath": "$.publicKey" },
            "finish": { "body": { "x": "{{bogusVar}}" }, "result": {} }
          }
        }
        """;
        var ex = Assert.Throws<DescriptorValidationException>(
            () => new RegistrationEnvelopeCodec(ServiceDescriptor.Parse(json)));
        Assert.Contains("bogusVar", string.Join(" ", ex.Errors));
    }

    [Fact]
    public void Construction_fails_fast_on_invalid_origin()
    {
        var json = """
        {
          "service": "svc",
          "rp": { "id": "example.com", "origin": "not-a-url" },
          "assertion": { "begin": { "optionsPath": "$.publicKey" },
                         "finish": { "body": {}, "result": {} } }
        }
        """;
        var ex = Assert.Throws<DescriptorValidationException>(
            () => new AuthenticationEnvelopeCodec(ServiceDescriptor.Parse(json)));
        Assert.Contains("rp.origin", string.Join(" ", ex.Errors));
    }

    [Fact]
    public void TestKit_facade_routes_by_service_and_rejects_unknown()
    {
        var json = """
        {
          "service": "svc",
          "rp": { "id": "example.com", "origin": "https://example.com" },
          "registration": { "begin": { "optionsPath": "$.publicKey" },
                            "finish": { "body": { "x": "{{credentialId}}" }, "result": {} } }
        }
        """;
        var kit = TestKit.FromJson(json);

        Assert.NotNull(kit.Registration("svc"));
        Assert.Throws<KeyNotFoundException>(() => kit.Registration("missing"));
    }

    [Fact]
    public void EncodeFinish_resolves_ctx_from_user_context()
    {
        var descriptor = ServiceDescriptor.Parse("""
        {
          "service": "svc",
          "rp": { "id": "example.com", "origin": "https://example.com" },
          "assertion": {
            "begin": { "optionsPath": "$.publicKey" },
            "finish": { "body": { "tenant": "{{ctx.tenantId}}", "sig": "{{signature}}" }, "result": {} }
          }
        }
        """);
        var codec = new AuthenticationEnvelopeCodec(descriptor);
        var assertion = SignedAssertion(out _);

        var context = new EnvelopeContext(new JsonObject(), new JsonObject { ["tenantId"] = "acme" });
        var body = codec.EncodeFinish(assertion, context);

        Assert.Equal("acme", body["tenant"]!.GetValue<string>());
        Assert.Empty(codec.LastDebug!.UnresolvedTemplateVariables);
    }

    [Fact]
    public void Construction_fails_fast_on_invalid_userIdEncoding()
    {
        var json = """
        { "service": "svc", "rp": { "id": "example.com", "origin": "https://example.com" },
          "registration": { "begin": { "optionsPath": "$.publicKey", "userIdEncoding": "weird" },
                            "finish": { "body": {}, "result": {} } } }
        """;
        var ex = Assert.Throws<DescriptorValidationException>(
            () => new RegistrationEnvelopeCodec(ServiceDescriptor.Parse(json)));
        Assert.Contains("userIdEncoding", string.Join(" ", ex.Errors));
    }

    [Fact]
    public void Construction_fails_fast_on_invalid_credentialIdEncoding()
    {
        var json = """
        { "service": "svc", "rp": { "id": "example.com", "origin": "https://example.com" },
          "assertion": { "begin": { "optionsPath": "$.publicKey", "credentialIdEncoding": "weird" },
                         "finish": { "body": {}, "result": {} } } }
        """;
        var ex = Assert.Throws<DescriptorValidationException>(
            () => new AuthenticationEnvelopeCodec(ServiceDescriptor.Parse(json)));
        Assert.Contains("credentialIdEncoding", string.Join(" ", ex.Errors));
    }

    [Fact]
    public void LastDebug_challenge_is_the_signed_challenge_not_clientData()
    {
        var descriptor = ServiceDescriptor.Parse("""
        { "service": "svc", "rp": { "id": "example.com", "origin": "https://example.com" },
          "assertion": { "begin": { "optionsPath": "$.publicKey" },
                         "finish": { "body": { "sig": "{{signature}}" }, "result": {} } } }
        """);
        var codec = new AuthenticationEnvelopeCodec(descriptor);
        var assertion = SignedAssertion(out var challenge);

        codec.EncodeFinish(assertion, new EnvelopeContext(new JsonObject()));

        Assert.Equal(B64Url(challenge), codec.LastDebug!.ChallengeBase64Url);
    }

    // Registers a credential and returns a fresh assertion; outputs the challenge it signed.
    private static AssertionResult SignedAssertion(out byte[] challenge)
    {
        var device = new VirtualAuthenticator(new());
        var att = device.MakeCredential(new CreationOptions(
            RandomNumberGenerator.GetBytes(32), new RpEntity(RpId),
            new UserEntity(Encoding.UTF8.GetBytes("u"), "u", "U"),
            [new PubKeyCredParam("public-key", -7)], Origin));
        challenge = RandomNumberGenerator.GetBytes(32);
        return device.GetAssertion(new RequestOptions(
            challenge, RpId, [new AllowCredential("public-key", att.CredentialId)], Origin));
    }
}
