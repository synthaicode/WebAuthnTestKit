using System.Text.Json.Nodes;

namespace WebAuthnTestKit;

/// <summary>
/// Converts between an application's WebAuthn API envelope and standard WebAuthn DTOs for one
/// ceremony of one service. Stateless with respect to HTTP; the caller owns transport and the
/// begin/finish session continuity.
/// </summary>
/// <typeparam name="TOptions">The decoded begin-options type (<see cref="CreationOptions"/> / <see cref="RequestOptions"/>).</typeparam>
/// <typeparam name="TFinish">The device output type (<see cref="AttestationResult"/> / <see cref="AssertionResult"/>).</typeparam>
public interface IEnvelopeCodec<TOptions, TFinish>
{
    /// <summary>Decodes a server "begin" response into standard options plus the context for "finish".</summary>
    DecodedOptions<TOptions> DecodeOptions(JsonNode beginResponse);

    /// <summary>Builds the "finish" request body from device output and the begin context.</summary>
    JsonNode EncodeFinish(TFinish deviceOutput, EnvelopeContext context);

    /// <summary>Extracts token/values and success from a server "finish" response.</summary>
    CeremonyResult DecodeResult(JsonNode finishResponse);

    /// <summary>Diagnostics from the most recent <see cref="EncodeFinish"/> call (null before first use).</summary>
    EnvelopeDebugInfo? LastDebug { get; }
}
