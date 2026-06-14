using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using DotNet.Testcontainers.Images;

namespace WebAuthnTestKit.IntegrationTests;

/// <summary>
/// Builds the Fido2NetLib demo server image from its Dockerfile and runs it in a container for the
/// duration of the test class. The container is an independent WebAuthn verifier — it really checks
/// origin, challenge, signature, and counter — so a green test proves the kit's output is valid.
/// </summary>
public sealed class Fido2DemoServerFixture : IAsyncLifetime
{
    private IFutureDockerImage _image = default!;
    private IContainer _container = default!;

    public HttpClient Client { get; private set; } = default!;
    public string DescriptorJson { get; private set; } = "";

    public async Task InitializeAsync()
    {
        var repoRoot = CommonDirectoryPath.GetGitDirectory();
        DescriptorJson = await File.ReadAllTextAsync(
            Path.Combine(repoRoot.DirectoryPath, "samples", "descriptors", "fido2-demo.json"));

        _image = new ImageFromDockerfileBuilder()
            .WithDockerfileDirectory(repoRoot, Path.Combine("samples", "Fido2DemoServer"))
            .WithDockerfile("Dockerfile")
            .WithName("webauthntestkit-fido2demo:itest")
            .Build();
        await _image.CreateAsync();

#pragma warning disable CS0618 // parameterless ContainerBuilder is obsolete in 4.12 but still the simplest with a runtime-built image
        _container = new ContainerBuilder()
            .WithImage(_image)
            .WithPortBinding(8080, true)
            .WithEnvironment("FIDO_RPID", "localhost")
            .WithEnvironment("FIDO_ORIGIN", "https://localhost")
            .WithWaitStrategy(Wait.ForUnixContainer()
                .UntilHttpRequestIsSucceeded(r => r.ForPort(8080).ForPath("/health")))
            .Build();
#pragma warning restore CS0618
        await _container.StartAsync();

        Client = new HttpClient
        {
            BaseAddress = new UriBuilder("http", _container.Hostname, _container.GetMappedPublicPort(8080)).Uri,
        };
    }

    public async Task DisposeAsync()
    {
        Client?.Dispose();
        if (_container is not null) await _container.DisposeAsync();
        if (_image is not null) await _image.DisposeAsync();
    }
}
