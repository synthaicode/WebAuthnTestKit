namespace WebAuthnTestKit;

/// <summary>
/// Relying Party entity. <see cref="Id"/> is the WebAuthn RP ID (a registrable domain),
/// which the authenticator hashes into <c>authenticatorData.rpIdHash</c>.
/// </summary>
public record RpEntity(string Id, string? Name = null);

/// <summary>
/// User entity for registration. <see cref="Id"/> is the opaque user handle (raw bytes),
/// echoed back as <c>userHandle</c> during assertion.
/// </summary>
public record UserEntity(byte[] Id, string Name, string DisplayName);

/// <summary>
/// A credential parameter the RP will accept. <see cref="Alg"/> is a COSE algorithm
/// identifier; only <c>-7</c> (ES256) is supported initially.
/// </summary>
public record PubKeyCredParam(string Type, int Alg)
{
    /// <summary>COSE algorithm identifier for ES256 (ECDSA over P-256 with SHA-256).</summary>
    public const int Es256 = -7;
}

/// <summary>
/// A credential the RP allows for an assertion. <see cref="Id"/> is the raw credential ID;
/// the device must hold a matching credential or the assertion fails fast.
/// </summary>
public record AllowCredential(string Type, byte[] Id);

/// <summary>
/// Standard, API-agnostic registration options decoded from a server's "begin" response.
/// <see cref="Challenge"/> is the raw (decoded) challenge; the device re-encodes it as
/// base64url inside clientDataJSON per spec. <see cref="Origin"/> is the full caller origin
/// (e.g. <c>https://example.com</c>) written into clientDataJSON; it comes from the descriptor's
/// <c>rp.origin</c> and is distinct from the RP ID hashed into authenticatorData.
/// </summary>
public record CreationOptions(
    byte[] Challenge,
    RpEntity Rp,
    UserEntity User,
    PubKeyCredParam[] Params,
    string Origin);

/// <summary>
/// Standard, API-agnostic assertion options decoded from a server's "begin" response.
/// <see cref="Origin"/> is the full caller origin written into clientDataJSON;
/// <see cref="RpId"/> is the domain hashed into authenticatorData.
/// </summary>
public record RequestOptions(
    byte[] Challenge,
    string RpId,
    AllowCredential[] Allow,
    string Origin);
