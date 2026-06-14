namespace WebAuthnTestKit;

/// <summary>
/// Output of a registration ceremony produced by the software authenticator.
/// With attestation format "none", <see cref="AttestationObject"/> is the CBOR of
/// <c>{ fmt:"none", attStmt:{}, authData }</c>.
/// </summary>
public record AttestationResult(
    byte[] CredentialId,
    byte[] ClientDataJson,
    byte[] AttestationObject);

/// <summary>
/// Output of an authentication ceremony produced by the software authenticator.
/// <see cref="UserHandle"/> is present for discoverable (resident) credentials.
/// </summary>
public record AssertionResult(
    byte[] CredentialId,
    byte[] ClientDataJson,
    byte[] AuthenticatorData,
    byte[] Signature,
    byte[]? UserHandle);
