using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using WebAuthnTestKit;

// Runnable client for samples/Fido2DemoServer. Demonstrates the CONSUMER side of WebAuthnTestKit:
// the kit converts JSON <-> signature <-> JSON, while this program owns the HTTP transport,
// the begin/finish continuity, token usage, and device-state persistence (design.md §6).
//
// Usage:
//   dotnet run --project samples/DemoClient -- [--server http://localhost:8080]
//                                               [--user alice] [--descriptor path] [--state path]
//                                               [--uv]   # request userVerification=required on auth

var opts = Args.Parse(args);
var descriptorPath = opts.Descriptor ?? Path.Combine(RepoRoot(), "samples", "descriptors", "fido2-demo.json");

var kit = TestKit.FromJson(File.ReadAllText(descriptorPath));
using var http = new HttpClient { BaseAddress = new Uri(opts.Server) };

// Restore a previously registered device if a state file was given and exists; else a fresh one.
var device = opts.State is { } sp && File.Exists(sp)
    ? VirtualAuthenticator.Import(JsonSerializer.Deserialize<DeviceState>(File.ReadAllText(sp))!)
    : new VirtualAuthenticator(new());
var hasCredential = opts.State is { } s && File.Exists(s);

Console.WriteLine($"server     : {opts.Server}");
Console.WriteLine($"descriptor : {descriptorPath}");
Console.WriteLine($"user       : {opts.User}");
Console.WriteLine($"device     : {(hasCredential ? "restored from state" : "new")}");
Console.WriteLine();

try
{
    if (!hasCredential)
        await Register(kit, http, device, opts.User);

    await Authenticate(kit, http, device, opts.User, opts.Uv);

    if (opts.State is { } statePath)
    {
        File.WriteAllText(statePath, JsonSerializer.Serialize(device.Export(),
            new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"\n[state] saved device (with advanced signCount) to {statePath}");
    }
}
catch (HttpFlowException ex)
{
    Console.Error.WriteLine($"\nFAILED: {ex.Message}");
    Environment.Exit(1);
}

return;

// ── Ceremonies ──────────────────────────────────────────────

static async Task Register(TestKit kit, HttpClient http, VirtualAuthenticator device, string user)
{
    Console.WriteLine("== Registration ==");
    var reg = kit.Registration("fido2-demo");

    var begin = await Post(http, "/attestation/options", new JsonObject { ["username"] = user });
    Console.WriteLine("  begin  -> options received");

    var decoded = reg.DecodeOptions(begin);                       // app envelope -> standard options
    var attestation = device.MakeCredential(decoded.Options);     // sign with the test device
    var body = reg.EncodeFinish(attestation, decoded.Context);    // standard output -> app finish body

    var result = reg.DecodeResult(await Post(http, "/attestation/result", body));
    Console.WriteLine($"  finish -> success={result.Success}");
}

static async Task Authenticate(TestKit kit, HttpClient http, VirtualAuthenticator device, string user, bool requireUv)
{
    Console.WriteLine($"== Authentication ==  (userVerification: {(requireUv ? "required" : "preferred")})");
    var auth = kit.Authentication("fido2-demo");

    var beginBody = new JsonObject { ["username"] = user };
    if (requireUv) beginBody["userVerification"] = "required";   // server enforces the UV flag

    var begin = await Post(http, "/assertion/options", beginBody);
    Console.WriteLine("  begin  -> options received");

    var decoded = auth.DecodeOptions(begin);
    var assertion = device.GetAssertion(decoded.Options);         // device sets UV flag (UserVerified=true), advances signCount
    var body = auth.EncodeFinish(assertion, decoded.Context);

    var result = auth.DecodeResult(await Post(http, "/assertion/result", body));
    Console.WriteLine($"  finish -> success={result.Success}");
    Console.WriteLine($"  token  -> {result.PrimaryToken}");
}

// ── Consumer-owned HTTP transport ───────────────────────────

static async Task<JsonNode> Post(HttpClient http, string path, JsonNode body)
{
    using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
    var response = await http.PostAsync(path, content);
    var text = await response.Content.ReadAsStringAsync();
    if (!response.IsSuccessStatusCode)
        throw new HttpFlowException($"POST {path} -> {(int)response.StatusCode}: {text}");
    return JsonNode.Parse(text)!;
}

static string RepoRoot()
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "WebAuthnTestKit.slnx")))
        dir = dir.Parent;
    return dir?.FullName ?? Directory.GetCurrentDirectory();
}

sealed class HttpFlowException(string message) : Exception(message);

readonly record struct Options(string Server, string User, string? Descriptor, string? State, bool Uv)
{
    public static Options Parse(string[] args)
    {
        string server = "http://localhost:8080", user = "alice";
        string? descriptor = null, state = null;
        bool uv = false;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--uv": uv = true; break;
                case "--server" when i + 1 < args.Length: server = args[++i]; break;
                case "--user" when i + 1 < args.Length: user = args[++i]; break;
                case "--descriptor" when i + 1 < args.Length: descriptor = args[++i]; break;
                case "--state" when i + 1 < args.Length: state = args[++i]; break;
            }
        }
        return new Options(server, user, descriptor, state, uv);
    }
}

static class Args
{
    public static Options Parse(string[] args) => Options.Parse(args);
}
