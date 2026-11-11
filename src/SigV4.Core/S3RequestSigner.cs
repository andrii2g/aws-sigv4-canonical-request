using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace SigV4.Core;

/// <summary>An offline, synthetic-credentials-only implementation of S3 GET header signing.</summary>
public static class S3RequestSigner
{
    // Published AWS example credentials, never loaded from the environment or a profile.
    private const string AccessKeyId = "AKIAIOSFODNN7EXAMPLE";
    private const string ExampleSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly HashSet<string> UnsupportedHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "authorization", "x-amz-security-token", "connection", "user-agent", "keep-alive",
        "transfer-encoding", "te", "trailer", "upgrade", "proxy-authorization", "proxy-authenticate",
        "x-amzn-trace-id", "content-length", "content-md5",
    };

    public static SigningTrace Sign(SigningRequest request) => SignTransformed(request, static parts => parts);

    // Only the experiment assembly can substitute a deliberately broken canonical representation.
    internal static SigningTrace SignTransformed(
        SigningRequest request,
        Func<CanonicalRequestParts, CanonicalRequestParts> transform)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(transform);
        Validate(request);

        long started = Stopwatch.GetTimestamp();
        string payloadHash = Hex(SHA256.HashData([]));
        string timestamp = request.Timestamp.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        string date = request.Timestamp.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        ImmutableArray<RequestHeader> headers = PrepareHeaders(request.Headers, timestamp, payloadHash);
        string path = S3UriEncoder.Encode(request.Path.Length == 0 ? "/" : request.Path, preserveSlashes: true);
        string query = CanonicalizeQuery(request.Query);
        string canonicalHeaders = string.Concat(headers.Select(header => $"{header.Name}:{header.Value}\n"));
        string signedHeaders = string.Join(';', headers.Select(header => header.Name));
        var parts = transform(new CanonicalRequestParts(
            request.Method, path, query, canonicalHeaders, signedHeaders, payloadHash));
        string canonicalRequest = string.Join('\n', parts.Method, parts.Uri, parts.Query,
            parts.Headers, parts.SignedHeaders, parts.PayloadHash);
        string canonicalHash = Hex(SHA256.HashData(StrictUtf8.GetBytes(canonicalRequest)));
        string scope = $"{date}/{request.Region}/{request.Service}/aws4_request";
        string stringToSign = $"AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{canonicalHash}";
        string signature = CalculateSignature(date, request.Region, request.Service, stringToSign);
        string authorization = $"AWS4-HMAC-SHA256 Credential={AccessKeyId}/{scope},SignedHeaders={parts.SignedHeaders},Signature={signature}";
        double microseconds = Stopwatch.GetElapsedTime(started).TotalMicroseconds;

        return new SigningTrace(
            request,
            FormatHttpRequest(request, headers, path, authorization),
            parts,
            canonicalRequest,
            canonicalHash,
            scope,
            stringToSign,
            [
                new("kDate", "AWS4 + synthetic secret", date),
                new("kRegion", "kDate", request.Region),
                new("kService", "kRegion", request.Service),
                new("kSigning", "kService", "aws4_request"),
            ],
            signature,
            authorization,
            new SigningMetrics(6, request.Query.Length, headers.Length, 2, 5, microseconds));
    }

    private static string CanonicalizeQuery(ImmutableArray<QueryParameter> query) =>
        string.Join('&', query.Select(pair => new QueryParameter(S3UriEncoder.Encode(pair.Name), S3UriEncoder.Encode(pair.Value)))
            .OrderBy(pair => pair.Name, StringComparer.Ordinal)
            .ThenBy(pair => pair.Value, StringComparer.Ordinal)
            .Select(pair => $"{pair.Name}={pair.Value}"));

    private static ImmutableArray<RequestHeader> PrepareHeaders(
        ImmutableArray<RequestHeader> input, string timestamp, string payloadHash)
    {
        var grouped = input.GroupBy(header => header.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key.ToLowerInvariant(),
                group => string.Join(',', group.Select(header => NormalizeHeaderValue(header.Value))),
                StringComparer.Ordinal);
        AddOrValidate("x-amz-date", timestamp);
        AddOrValidate("x-amz-content-sha256", payloadHash);
        return [.. grouped.OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Select(pair => new RequestHeader(pair.Key, pair.Value))];

        void AddOrValidate(string name, string expected)
        {
            if (grouped.TryGetValue(name, out string? supplied) && supplied != expected)
            {
                throw new ArgumentException($"Header '{name}' must match the fixed signing inputs.", nameof(input));
            }

            grouped[name] = expected;
        }
    }

    private static string NormalizeHeaderValue(string value) =>
        string.Join(' ', value.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries));

    private static string FormatHttpRequest(SigningRequest request,
        ImmutableArray<RequestHeader> headers, string path, string authorization)
    {
        // Preserve query input order here; only the canonical query is sorted.
        string rawQuery = string.Join('&', request.Query.Select(pair =>
            $"{S3UriEncoder.Encode(pair.Name)}={S3UriEncoder.Encode(pair.Value)}"));
        string target = rawQuery.Length == 0 ? path : $"{path}?{rawQuery}";
        // Show the caller's header presentation, then append the two generated headers if absent.
        IEnumerable<RequestHeader> displayedHeaders = request.Headers.Concat(headers.Where(generated =>
            !request.Headers.Any(original => original.Name.Equals(generated.Name, StringComparison.OrdinalIgnoreCase))));
        string headerLines = string.Join("\r\n", displayedHeaders.Select(header => $"{header.Name}: {header.Value}"));
        return $"GET {target} HTTP/1.1\r\n{headerLines}\r\nAuthorization: {authorization}\r\n\r\n";
    }

    private static string CalculateSignature(string date, string region, string service, string stringToSign)
    {
        // Keep HMAC outputs binary between steps. Never put key material in diagnostic objects.
        byte[] initialKey = Encoding.UTF8.GetBytes("AWS4" + ExampleSecret);
        byte[]? dateKey = null;
        byte[]? regionKey = null;
        byte[]? serviceKey = null;
        byte[]? signingKey = null;
        try
        {
            dateKey = HMACSHA256.HashData(initialKey, Encoding.UTF8.GetBytes(date));
            regionKey = HMACSHA256.HashData(dateKey, Encoding.UTF8.GetBytes(region));
            serviceKey = HMACSHA256.HashData(regionKey, Encoding.UTF8.GetBytes(service));
            signingKey = HMACSHA256.HashData(serviceKey, "aws4_request"u8);
            return Hex(HMACSHA256.HashData(signingKey, Encoding.UTF8.GetBytes(stringToSign)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(initialKey);
            if (dateKey is not null) { CryptographicOperations.ZeroMemory(dateKey); }
            if (regionKey is not null) { CryptographicOperations.ZeroMemory(regionKey); }
            if (serviceKey is not null) { CryptographicOperations.ZeroMemory(serviceKey); }
            if (signingKey is not null) { CryptographicOperations.ZeroMemory(signingKey); }
        }
    }

    private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);

    private static void Validate(SigningRequest request)
    {
        if (request.Method != "GET" || request.Service != "s3" || request.CredentialPreset != "aws-documentation")
        {
            throw new ArgumentException("Only GET, service s3, and the aws-documentation synthetic preset are supported.", nameof(request));
        }

        if (request.Timestamp == default || request.Timestamp.Offset != TimeSpan.Zero || request.Timestamp.Ticks % TimeSpan.TicksPerSecond != 0)
        {
            throw new ArgumentException("Supply a fixed UTC timestamp with whole-second precision.", nameof(request));
        }

        if (string.IsNullOrWhiteSpace(request.Region) || request.Region.Any(character => !char.IsAsciiLetterLower(character) && !char.IsAsciiDigit(character) && character != '-'))
        {
            throw new ArgumentException("Region must contain lowercase ASCII letters, digits, and hyphens.", nameof(request));
        }

        if (request.Path is null || (request.Path.Length != 0 && !request.Path.StartsWith('/')))
        {
            throw new ArgumentException("Path must be empty or start with '/'; supply unescaped text.", nameof(request));
        }

        if (request.Query.IsDefault || request.Headers.IsDefault || request.Query.Any(pair => pair is null || pair.Name is null || pair.Value is null))
        {
            throw new ArgumentException("Query and header collections and their values must not be null.", nameof(request));
        }

        foreach (RequestHeader header in request.Headers)
        {
            if (header is null || string.IsNullOrEmpty(header.Name) || !header.Name.All(IsHeaderNameCharacter)
                || header.Value is null || header.Value.Any(character => char.IsControl(character) && character != '\t'))
            {
                throw new ArgumentException("Headers require valid HTTP token names and values without control characters.", nameof(request));
            }

            if (UnsupportedHeaders.Contains(header.Name))
            {
                throw new ArgumentException($"Header '{header.Name}' is outside the educational GET scope.", nameof(request));
            }
        }

        RequestHeader[] hosts = [.. request.Headers.Where(header => header.Name.Equals("host", StringComparison.OrdinalIgnoreCase))];
        if (hosts.Length != 1 || !IsSupportedAuthority(NormalizeHeaderValue(hosts[0].Value)))
        {
            throw new ArgumentException("Supply exactly one host header containing an ASCII hostname and optional port.", nameof(request));
        }
    }

    private static bool IsSupportedAuthority(string value)
    {
        string[] authority = value.Split(':');
        if (authority.Length > 2 || (authority.Length == 2 &&
            (!ushort.TryParse(authority[1], NumberStyles.None, CultureInfo.InvariantCulture, out ushort port) || port == 0)))
        {
            return false;
        }

        string hostname = authority[0].EndsWith('.') ? authority[0][..^1] : authority[0];
        return hostname.Length is > 0 and <= 253 && hostname.Split('.').All(label =>
            label.Length is > 0 and <= 63 && char.IsAsciiLetterOrDigit(label[0]) &&
            char.IsAsciiLetterOrDigit(label[^1]) &&
            label.All(character => char.IsAsciiLetterOrDigit(character) || character == '-'));
    }

    private static bool IsHeaderNameCharacter(char character) =>
        char.IsAsciiLetterOrDigit(character) || "!#$%&'*+-.^_`|~".Contains(character, StringComparison.Ordinal);
}
