using System.Text.Json.Nodes;

namespace WebAuthnTestKit;

/// <summary>
/// Context carried from a server's "begin" response into the matching "finish" request, so the
/// codec can resolve <c>{{source.path}}</c> template variables (requestId, transactionId, state,
/// csrfToken, registrationToken, ...) against <see cref="BeginResponse"/>. <see cref="UserContext"/>
/// is an optional bag of caller-supplied values, resolved in templates via <c>{{ctx.path}}</c>.
/// </summary>
public record EnvelopeContext(JsonNode BeginResponse, JsonNode? UserContext = null);

/// <summary>
/// Result of decoding a "begin" response: the standard <see cref="Options"/> to feed the device,
/// plus the <see cref="Context"/> needed to build the "finish" request without mixing up ceremonies.
/// </summary>
public record DecodedOptions<TOptions>(TOptions Options, EnvelopeContext Context);

/// <summary>
/// Result of decoding a server's "finish" response. <see cref="PrimaryToken"/> is the
/// representative token for convenience; <see cref="Values"/> carries the full set of extracted
/// values (accessToken/refreshToken/idToken/sessionId/role/expiresIn/...). <see cref="Raw"/> is
/// the untouched response for escape-hatch access.
/// </summary>
public record CeremonyResult(
    bool Success,
    string? PrimaryToken,
    IReadOnlyDictionary<string, string> Values,
    JsonNode Raw);

/// <summary>
/// Diagnostics captured during the most recent <c>EncodeFinish</c> call, for tracking the common
/// failure causes (encoding mismatch, RP ID/origin mismatch, credential ID mismatch, unresolved
/// template variables, JSON path misses).
/// </summary>
public record EnvelopeDebugInfo(
    string RpId,
    string Origin,
    string ChallengeBase64Url,
    string CredentialIdBase64Url,
    string OptionsPath,
    IReadOnlyList<string> ResolvedTemplateVariables,
    IReadOnlyList<string> UnresolvedTemplateVariables);
