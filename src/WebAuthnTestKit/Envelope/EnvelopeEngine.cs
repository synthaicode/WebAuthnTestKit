using System.Buffers.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace WebAuthnTestKit;

/// <summary>
/// Stateless primitives shared by the envelope codecs: JSON path resolution, encoding conversion,
/// <c>{{...}}</c> template substitution, and <c>successWhen</c> evaluation. No HTTP, no device state.
/// </summary>
public static partial class EnvelopeEngine
{
    [GeneratedRegex(@"([A-Za-z0-9_\-\.]+)|\[(\d+)\]")] private static partial Regex PathSegments();
    [GeneratedRegex(@"\{\{\s*([^}]+?)\s*\}\}")] private static partial Regex TemplateToken();

    /// <summary>Resolves a minimal JSON path (<c>$.a.b[0].c</c>) against a node. Null if any segment misses.</summary>
    public static JsonNode? Resolve(JsonNode? root, string path)
    {
        var node = root;
        foreach (Match m in PathSegments().Matches(path))
        {
            if (node is null) return null;
            if (m.Groups[2].Success)
            {
                var idx = int.Parse(m.Groups[2].Value);
                node = node is JsonArray arr && idx < arr.Count ? arr[idx] : null;
            }
            else
            {
                // A "$.a.b" head yields a "$" or "$.a"-style token via the dotted char class; split it.
                foreach (var name in m.Groups[1].Value.Split('.', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (name == "$") continue;
                    if (node is null) return null;
                    node = node is JsonObject obj && obj.TryGetPropertyValue(name, out var v) ? v : null;
                }
            }
        }
        return node;
    }

    public static byte[] Decode(string value, string encoding) => encoding switch
    {
        "base64url" => Base64Url.DecodeFromChars(value),
        "base64" => Convert.FromBase64String(value),
        "hex" => Convert.FromHexString(value),
        _ => throw new NotSupportedException($"Unsupported encoding '{encoding}'."),
    };

    public static string Encode(byte[] value, string encoding) => encoding switch
    {
        "base64url" => Base64Url.EncodeToString(value),
        "base64" => Convert.ToBase64String(value),
        "hex" => Convert.ToHexString(value).ToLowerInvariant(),
        _ => throw new NotSupportedException($"Unsupported encoding '{encoding}'."),
    };

    public static bool IsSupportedEncoding(string encoding) =>
        encoding is "base64url" or "base64" or "hex";

    /// <summary>The literal template variable names referenced by a template object (without braces).</summary>
    public static IEnumerable<string> TemplateVariables(JsonNode? template)
    {
        foreach (var leaf in StringLeaves(template))
            foreach (Match m in TemplateToken().Matches(leaf))
                yield return m.Groups[1].Value;
    }

    /// <summary>
    /// Deep-copies <paramref name="template"/>, substituting <c>{{var}}</c> tokens from
    /// <paramref name="values"/>, <c>{{source.path}}</c> from <paramref name="source"/> (the begin
    /// response), and <c>{{ctx.path}}</c> from <paramref name="userContext"/> (caller-supplied).
    /// Records which variables resolved and which did not.
    /// </summary>
    public static JsonNode Fill(
        JsonNode template,
        IReadOnlyDictionary<string, string> values,
        JsonNode? source,
        JsonNode? userContext,
        List<string> resolved,
        List<string> unresolved)
    {
        var clone = template.DeepClone();
        FillInPlace(clone, values, source, userContext, resolved, unresolved);
        return clone;
    }

    private static void FillInPlace(
        JsonNode? node,
        IReadOnlyDictionary<string, string> values,
        JsonNode? source,
        JsonNode? userContext,
        List<string> resolved,
        List<string> unresolved)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var key in obj.Select(kv => kv.Key).ToList())
                {
                    if (obj[key] is JsonValue v && v.TryGetValue(out string? s))
                        obj[key] = Substitute(s, values, source, userContext, resolved, unresolved);
                    else
                        FillInPlace(obj[key], values, source, userContext, resolved, unresolved);
                }
                break;
            case JsonArray arr:
                for (var i = 0; i < arr.Count; i++)
                {
                    if (arr[i] is JsonValue v && v.TryGetValue(out string? s))
                        arr[i] = Substitute(s, values, source, userContext, resolved, unresolved);
                    else
                        FillInPlace(arr[i], values, source, userContext, resolved, unresolved);
                }
                break;
        }
    }

    private static string Substitute(
        string input,
        IReadOnlyDictionary<string, string> values,
        JsonNode? source,
        JsonNode? userContext,
        List<string> resolved,
        List<string> unresolved)
    {
        return TemplateToken().Replace(input, m =>
        {
            var name = m.Groups[1].Value;
            string? value =
                name.StartsWith("source.", StringComparison.Ordinal)
                    ? Resolve(source, "$." + name["source.".Length..])?.ToString()
                : name.StartsWith("ctx.", StringComparison.Ordinal)
                    ? Resolve(userContext, "$." + name["ctx.".Length..])?.ToString()
                : values.TryGetValue(name, out var v) ? v : null;

            if (value is null) { unresolved.Add(name); return m.Value; }
            resolved.Add(name);
            return value;
        });
    }

    /// <summary>Evaluates a <c>successWhen</c> condition: <c>path == 'lit'</c>, <c>path == num</c>, or path truthiness.</summary>
    public static bool Eval(JsonNode? root, string condition)
    {
        var eq = condition.IndexOf("==", StringComparison.Ordinal);
        if (eq < 0)
        {
            var node = Resolve(root, condition.Trim());
            return node is not null && node.ToString() is not ("false" or "");
        }

        var path = condition[..eq].Trim();
        var rhs = condition[(eq + 2)..].Trim().Trim('\'', '"');
        return Resolve(root, path)?.ToString() == rhs;
    }

    private static IEnumerable<string> StringLeaves(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var kv in obj)
                    foreach (var s in StringLeaves(kv.Value)) yield return s;
                break;
            case JsonArray arr:
                foreach (var item in arr)
                    foreach (var s in StringLeaves(item)) yield return s;
                break;
            case JsonValue v when v.TryGetValue(out string? s):
                yield return s;
                break;
        }
    }
}
