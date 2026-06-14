using System.Buffers.Text;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using WebAuthnTestKit;

// Runnable client for samples/Fido2DemoServer. Demonstrates the CONSUMER side of WebAuthnTestKit:
// the kit converts JSON <-> signature <-> JSON, while this program owns the HTTP transport,
// the begin/finish continuity, token usage, and device-state persistence (design.md §6).
//
// Commands (registration and authentication are separate operations):
//   register  --state <file>            register a NEW device, save it; does not authenticate
//   auth      --state <file> [--uv]     authenticate with a previously registered device
//   demo                                register TWO devices to one account, then auth with each
//
// Common options: --server <url> (default http://localhost:8080), --user <name> (default alice),
//                 --descriptor <path>, --uv (request userVerification=required on auth)

string command = "demo";
var optionArgs = args;
if (args.Length > 0 && !args[0].StartsWith("--")) { command = args[0]; optionArgs = args[1..]; }
var opts = Options.Parse(optionArgs);

var descriptorPath = opts.Descriptor ?? Path.Combine(RepoRoot(), "samples", "descriptors", "fido2-demo.json");
var kit = TestKit.FromJson(File.ReadAllText(descriptorPath));
using var http = new HttpClient { BaseAddress = new Uri(opts.Server) };

Console.WriteLine($"server  : {opts.Server}");
Console.WriteLine($"user    : {opts.User}");
Console.WriteLine($"command : {command}");
Console.WriteLine();

try
{
    switch (command)
    {
        case "register": await RegisterCommand(); break;
        case "auth": await AuthCommand(); break;
        case "demo": await DemoCommand(); break;
        default:
            Console.Error.WriteLine($"unknown command '{command}'. Use: register | auth | demo");
            Environment.Exit(2);
            break;
    }
}
catch (HttpFlowException ex)
{
    Console.Error.WriteLine($"\nFAILED: {ex.Message}");
    Environment.Exit(1);
}

return;

// ── Commands ────────────────────────────────────────────────

async Task RegisterCommand()
{
    if (opts.State is not { } statePath)
    {
        Console.Error.WriteLine("register requires --state <file> to save the new device.");
        Environment.Exit(2);
        return;
    }

    Console.WriteLine("== Register a new device ==");
    var device = new VirtualAuthenticator(new());           // a brand-new authenticator each time
    var credentialId = await RegisterFlow(device, opts.User);
    SaveDevice(device, statePath);
    Console.WriteLine($"  credential {Short(credentialId)} registered -> saved device to {statePath}");
}

async Task AuthCommand()
{
    if (opts.State is not { } statePath || !File.Exists(statePath))
    {
        Console.Error.WriteLine("auth requires an existing --state <file> (run 'register' first).");
        Environment.Exit(2);
        return;
    }

    Console.WriteLine($"== Authenticate ==  (userVerification: {(opts.Uv ? "required" : "preferred")})");
    var device = LoadDevice(statePath);
    var result = await AuthFlow(device, opts.User, opts.Uv);
    SaveDevice(device, statePath);                          // persist the advanced signCount
    Console.WriteLine($"  success={result.Success}  token={result.PrimaryToken}");
}

async Task DemoCommand()
{
    // Register MULTIPLE devices to the same account, then authenticate with each independently
    // (mirrors a user enrolling several passkeys).
    var stateA = Path.Combine(Path.GetTempPath(), $"{opts.User}-A.device.json");
    var stateB = Path.Combine(Path.GetTempPath(), $"{opts.User}-B.device.json");

    Console.WriteLine("== Register device A ==");
    var deviceA = new VirtualAuthenticator(new());
    var credA = await RegisterFlow(deviceA, opts.User);
    SaveDevice(deviceA, stateA);
    Console.WriteLine($"  device A credential {Short(credA)} -> {stateA}");

    Console.WriteLine("== Register device B ==");
    var deviceB = new VirtualAuthenticator(new());
    var credB = await RegisterFlow(deviceB, opts.User);
    SaveDevice(deviceB, stateB);
    Console.WriteLine($"  device B credential {Short(credB)} -> {stateB}");

    Console.WriteLine("\n== Authenticate with device A ==");
    var ra = await AuthFlow(LoadDevice(stateA), opts.User, opts.Uv);
    Console.WriteLine($"  success={ra.Success}  token={ra.PrimaryToken}");

    Console.WriteLine("== Authenticate with device B ==");
    var rb = await AuthFlow(LoadDevice(stateB), opts.User, opts.Uv);
    Console.WriteLine($"  success={rb.Success}  token={rb.PrimaryToken}");

    Console.WriteLine($"\n[demo] two devices registered to '{opts.User}', each authenticated independently.");
}

// ── Reusable ceremony flows (kit + HTTP) ────────────────────

async Task<byte[]> RegisterFlow(VirtualAuthenticator device, string user)
{
    var reg = kit.Registration("fido2-demo");
    var begin = await Post(http, "/attestation/options", new JsonObject { ["username"] = user });
    var decoded = reg.DecodeOptions(begin);
    var attestation = device.MakeCredential(decoded.Options);
    var result = reg.DecodeResult(await Post(http, "/attestation/result", reg.EncodeFinish(attestation, decoded.Context)));
    if (!result.Success) throw new HttpFlowException("registration was rejected by the server");
    return attestation.CredentialId;
}

async Task<CeremonyResult> AuthFlow(VirtualAuthenticator device, string user, bool requireUv)
{
    var auth = kit.Authentication("fido2-demo");
    var beginBody = new JsonObject { ["username"] = user };
    if (requireUv) beginBody["userVerification"] = "required";

    var begin = await Post(http, "/assertion/options", beginBody);
    var decoded = auth.DecodeOptions(begin);                // allowCredentials may list several devices;
    var assertion = device.GetAssertion(decoded.Options);   // this device signs with its own credential
    return auth.DecodeResult(await Post(http, "/assertion/result", auth.EncodeFinish(assertion, decoded.Context)));
}

// ── Consumer-owned plumbing ─────────────────────────────────

static async Task<JsonNode> Post(HttpClient http, string path, JsonNode body)
{
    using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
    var response = await http.PostAsync(path, content);
    var text = await response.Content.ReadAsStringAsync();
    if (!response.IsSuccessStatusCode)
        throw new HttpFlowException($"POST {path} -> {(int)response.StatusCode}: {text}");
    return JsonNode.Parse(text)!;
}

static VirtualAuthenticator LoadDevice(string path) =>
    VirtualAuthenticator.Import(JsonSerializer.Deserialize<DeviceState>(File.ReadAllText(path))!);

static void SaveDevice(VirtualAuthenticator device, string path) =>
    File.WriteAllText(path, JsonSerializer.Serialize(device.Export(), new JsonSerializerOptions { WriteIndented = true }));

static string Short(byte[] credentialId) => Base64Url.EncodeToString(credentialId)[..8] + "…";

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
