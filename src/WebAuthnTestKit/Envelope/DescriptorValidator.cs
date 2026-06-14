namespace WebAuthnTestKit;

/// <summary>Thrown when a <see cref="ServiceDescriptor"/> fails construction-time validation.</summary>
public sealed class DescriptorValidationException(string service, IReadOnlyList<string> errors)
    : Exception($"Descriptor '{service}' is invalid:{Environment.NewLine}- {string.Join($"{Environment.NewLine}- ", errors)}")
{
    public IReadOnlyList<string> Errors { get; } = errors;
}

/// <summary>
/// Fail-fast checks run when a codec is constructed, so descriptor mistakes surface at setup
/// rather than mid-ceremony.
/// </summary>
public static class DescriptorValidator
{
    private static readonly string[] RegistrationVars =
        ["credentialId", "rawId", "clientDataJSON", "attestationObject", "attestationJson", "attestationJsonBase64Url"];

    private static readonly string[] AssertionVars =
        ["credentialId", "rawId", "clientDataJSON", "authenticatorData", "signature", "userHandle", "assertionJson", "assertionJsonBase64Url"];

    public static void Validate(ServiceDescriptor descriptor, CeremonyKind kind)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(descriptor.Service))
            errors.Add("'service' is required.");
        if (string.IsNullOrWhiteSpace(descriptor.Rp.Id))
            errors.Add("'rp.id' is required.");
        if (!Uri.TryCreate(descriptor.Rp.Origin, UriKind.Absolute, out _))
            errors.Add($"'rp.origin' must be an absolute URL; got '{descriptor.Rp.Origin}'.");

        var ceremony = kind == CeremonyKind.Registration ? descriptor.Registration : descriptor.Assertion;
        if (ceremony is null)
        {
            errors.Add($"'{kind.ToString().ToLowerInvariant()}' section is required for this codec.");
            throw new DescriptorValidationException(descriptor.Service, errors);
        }

        if (string.IsNullOrWhiteSpace(ceremony.Begin.OptionsPath))
            errors.Add("'begin.optionsPath' is required.");
        ValidateEncoding(errors, "begin.challengeEncoding", ceremony.Begin.ChallengeEncoding);
        if (kind == CeremonyKind.Registration)
            ValidateEncoding(errors, "begin.userIdEncoding", ceremony.Begin.UserIdEncoding);
        else
            ValidateEncoding(errors, "begin.credentialIdEncoding", ceremony.Begin.CredentialIdEncoding);

        var allowed = kind == CeremonyKind.Registration ? RegistrationVars : AssertionVars;
        foreach (var name in EnvelopeEngine.TemplateVariables(ceremony.Finish.Body))
        {
            if (name.StartsWith("source.", StringComparison.Ordinal)) continue;   // begin response
            if (name.StartsWith("ctx.", StringComparison.Ordinal)) continue;       // caller-supplied UserContext
            if (!allowed.Contains(name))
                errors.Add($"'finish.body' references unknown template variable '{{{{{name}}}}}'. " +
                           $"Allowed: {string.Join(", ", allowed)}, or source.*/ctx.*");
        }

        if (errors.Count > 0)
            throw new DescriptorValidationException(descriptor.Service, errors);
    }

    private static void ValidateEncoding(List<string> errors, string field, string encoding)
    {
        if (!EnvelopeEngine.IsSupportedEncoding(encoding))
            errors.Add($"'{field}' must be base64url/base64/hex; got '{encoding}'.");
    }
}
