namespace WebAuthnTestKit;

/// <summary>
/// Entry point for working with multiple service descriptors. Hands out per-service, descriptor-bound
/// codecs. (Named <c>TestKit</c> rather than <c>WebAuthnTestKit</c> to avoid clashing with the namespace.)
/// </summary>
public sealed class TestKit
{
    private readonly Dictionary<string, ServiceDescriptor> _descriptors;

    public TestKit(IEnumerable<ServiceDescriptor> descriptors) =>
        _descriptors = descriptors.ToDictionary(d => d.Service, StringComparer.Ordinal);

    /// <summary>Loads descriptors from JSON strings.</summary>
    public static TestKit FromJson(params string[] descriptorJson) =>
        new(descriptorJson.Select(ServiceDescriptor.Parse));

    /// <summary>Returns a registration codec bound to the named service's descriptor (validated on construction).</summary>
    public RegistrationEnvelopeCodec Registration(string service) =>
        new(Get(service));

    /// <summary>Returns an authentication codec bound to the named service's descriptor (validated on construction).</summary>
    public AuthenticationEnvelopeCodec Authentication(string service) =>
        new(Get(service));

    private ServiceDescriptor Get(string service) =>
        _descriptors.TryGetValue(service, out var d)
            ? d
            : throw new KeyNotFoundException($"No descriptor registered for service '{service}'.");
}
