using System.Collections.Immutable;

namespace SigV4.Core;

/// <summary>A logical S3 GET request. Paths and query pairs are unescaped Unicode text.</summary>
public sealed record SigningRequest
{
    public string Method { get; init; } = "GET";
    public string Path { get; init; } = "/";
    public ImmutableArray<QueryParameter> Query { get; init; } = [];
    public ImmutableArray<RequestHeader> Headers { get; init; } = [];
    public DateTimeOffset Timestamp { get; init; }
    public string Region { get; init; } = "us-east-1";
    public string Service { get; init; } = "s3";
    public string CredentialPreset { get; init; } = "aws-documentation";
}

public sealed record QueryParameter(string Name, string Value);

public sealed record RequestHeader(string Name, string Value);
