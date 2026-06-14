using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using WebAuthnTestKit;

namespace WebAuthnTestKit.IntegrationTests;

[Trait("Category", "Integration")]
public sealed class WebAuthnFlowTests : IClassFixture<Fido2DemoServerFixture>
{
    private readonly Fido2DemoServerFixture _server;
    private readonly TestKit _kit;

    public WebAuthnFlowTests(Fido2DemoServerFixture server)
    {
        _server = server;
        _kit = TestKit.FromJson(server.DescriptorJson);
    }

    [Fact]
    public async Task Register_then_authenticate_against_real_fido2_server()
    {
        const string username = "alice";
        var device = new VirtualAuthenticator(new());

        // ── Registration ──
        var reg = _kit.Registration("fido2-demo");
        var regBegin = await Post("/attestation/options",
            new JsonObject { ["username"] = username, ["displayName"] = "Alice" });

        var regOptions = reg.DecodeOptions(regBegin);
        var attestation = device.MakeCredential(regOptions.Options);
        var regFinishBody = reg.EncodeFinish(attestation, regOptions.Context);
        var regFinish = await Post("/attestation/result", regFinishBody);

        Assert.True(reg.DecodeResult(regFinish).Success, "registration should be accepted by the server");

        // ── Authentication ──
        var auth = _kit.Authentication("fido2-demo");
        var authBegin = await Post("/assertion/options", new JsonObject { ["username"] = username });

        var authOptions = auth.DecodeOptions(authBegin);
        var assertion = device.GetAssertion(authOptions.Options);
        var authFinishBody = auth.EncodeFinish(assertion, authOptions.Context);
        var authFinish = await Post("/assertion/result", authFinishBody);

        var result = auth.DecodeResult(authFinish);
        Assert.True(result.Success, "assertion signature must verify on the server");
        Assert.False(string.IsNullOrEmpty(result.PrimaryToken));
    }

    [Fact]
    public async Task Second_authentication_advances_server_side_counter()
    {
        const string username = "bob";
        var device = new VirtualAuthenticator(new());
        var reg = _kit.Registration("fido2-demo");
        var auth = _kit.Authentication("fido2-demo");

        var regBegin = await Post("/attestation/options", new JsonObject { ["username"] = username });
        var regOptions = reg.DecodeOptions(regBegin);
        var att = device.MakeCredential(regOptions.Options);
        await Post("/attestation/result", reg.EncodeFinish(att, regOptions.Context));

        async Task<long> Authenticate()
        {
            var begin = await Post("/assertion/options", new JsonObject { ["username"] = username });
            var opts = auth.DecodeOptions(begin);
            var assertion = device.GetAssertion(opts.Options);
            var finish = await Post("/assertion/result", auth.EncodeFinish(assertion, opts.Context));
            return finish["signCount"]!.GetValue<long>();
        }

        Assert.Equal(1, await Authenticate());
        Assert.Equal(2, await Authenticate());   // server accepts the strictly-increasing counter
    }

    [Fact]
    public async Task User_verification_required_succeeds_for_uv_capable_device()
    {
        const string username = "carol";
        var device = new VirtualAuthenticator(new());   // UserVerified = true by default
        await RegisterDevice(username, device);

        var auth = _kit.Authentication("fido2-demo");
        var begin = await Post("/assertion/options",
            new JsonObject { ["username"] = username, ["userVerification"] = "required" });
        var opts = auth.DecodeOptions(begin);
        var assertion = device.GetAssertion(opts.Options);
        var result = auth.DecodeResult(await Post("/assertion/result", auth.EncodeFinish(assertion, opts.Context)));

        Assert.True(result.Success, "UV-capable device should satisfy userVerification=required");
    }

    [Fact]
    public async Task User_verification_required_rejects_device_without_uv_flag()
    {
        const string username = "dave";
        var device = new VirtualAuthenticator(new());
        await RegisterDevice(username, device);

        // Same credential, but a device that does NOT set the UV flag.
        var uvless = VirtualAuthenticator.Import(device.Export() with { UserVerified = false });

        var auth = _kit.Authentication("fido2-demo");
        var begin = await Post("/assertion/options",
            new JsonObject { ["username"] = username, ["userVerification"] = "required" });
        var opts = auth.DecodeOptions(begin);
        var assertion = uvless.GetAssertion(opts.Options);   // valid signature, UV flag off
        var body = auth.EncodeFinish(assertion, opts.Context);

        // The server requires UV, so it must reject the assertion (non-2xx -> Post throws).
        await Assert.ThrowsAsync<Xunit.Sdk.XunitException>(() => Post("/assertion/result", body));
    }

    private async Task RegisterDevice(string username, VirtualAuthenticator device)
    {
        var reg = _kit.Registration("fido2-demo");
        var begin = await Post("/attestation/options", new JsonObject { ["username"] = username });
        var opts = reg.DecodeOptions(begin);
        var att = device.MakeCredential(opts.Options);
        var result = reg.DecodeResult(await Post("/attestation/result", reg.EncodeFinish(att, opts.Context)));
        Assert.True(result.Success);
    }

    private async Task<JsonNode> Post(string path, JsonNode body)
    {
        using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        var response = await _server.Client.PostAsync(path, content);
        var text = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode)
            throw new Xunit.Sdk.XunitException($"POST {path} -> {(int)response.StatusCode}: {text}");
        return JsonNode.Parse(text)!;
    }
}
