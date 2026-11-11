using System.Collections.Immutable;

namespace SigV4.Core;

/// <summary>The six components serialized into a canonical request.</summary>
public sealed record CanonicalRequestParts(
    string Method,
    string Uri,
    string Query,
    string Headers,
    string SignedHeaders,
    string PayloadHash);

/// <summary>Public inputs and labels only; key bytes never enter a trace.</summary>
public sealed record KeyDerivationStep(string Name, string KeyLabel, string Input)
{
    public string Output { get; } = "[redacted]";
}

public sealed record SigningMetrics(
    int CanonicalComponents,
    int QueryParameters,
    int SignedHeaderCount,
    int Sha256Operations,
    int HmacSha256Operations,
    double ElapsedMicroseconds);

/// <summary>Safe to render: contains only synthetic request data and nonsecret results.</summary>
public sealed record SigningTrace(
    SigningRequest Request,
    string HttpRequest,
    CanonicalRequestParts Canonical,
    string CanonicalRequest,
    string CanonicalRequestHash,
    string CredentialScope,
    string StringToSign,
    ImmutableArray<KeyDerivationStep> KeyDerivation,
    string Signature,
    string AuthorizationHeader,
    SigningMetrics Metrics);
