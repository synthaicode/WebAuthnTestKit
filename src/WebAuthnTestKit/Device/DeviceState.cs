namespace WebAuthnTestKit;

/// <summary>
/// Construction-time identity of a software (pseudo) authenticator. Fixed for the lifetime of
/// the device. Initial scope: ES256 only, attestation format "none".
/// </summary>
public record VirtualAuthenticatorOptions(
    Guid Aaguid = default,
    int Algorithm = PubKeyCredParam.Es256,
    bool SupportsResidentKey = true,
    bool UserPresent = true,
    bool UserVerified = true);

/// <summary>
/// A single credential held by the device. <see cref="PrivateKeyPkcs8"/> is the PKCS#8-encoded
/// EC private key; <see cref="SignCount"/> advances on each assertion.
/// </summary>
public record StoredCredential(
    byte[] CredentialId,
    string RpId,
    byte[]? UserHandle,
    byte[] PrivateKeyPkcs8,
    uint SignCount);

/// <summary>
/// Serializable snapshot of a device's identity and stored credentials. Use
/// <c>VirtualAuthenticator.Export</c>/<c>Import</c> to persist state across test cases so the
/// signature counter is preserved.
/// </summary>
public record DeviceState(
    Guid Aaguid,
    int Algorithm,
    bool SupportsResidentKey,
    bool UserPresent,
    bool UserVerified,
    IReadOnlyList<StoredCredential> Credentials);
