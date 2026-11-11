using System.Text;
using System.Text.Json;
using SigV4.Core;

namespace SigV4.Tests;

public sealed class AwsVectorTests
{
    [Theory]
    [InlineData("aws-get-object")]
    [InlineData("aws-get-lifecycle")]
    [InlineData("aws-list-objects")]
    public void Sign_matches_every_published_intermediate_and_signature(string id)
    {
        var fixture = AwsVectorFixture.Load(id);
        var trace = S3RequestSigner.Sign(fixture.Request);

        Assert.Equal(Encoding.UTF8.GetBytes(fixture.Expected.CanonicalRequest),
            Encoding.UTF8.GetBytes(trace.CanonicalRequest));
        Assert.Equal(fixture.Expected.CanonicalRequestHash, trace.CanonicalRequestHash);
        Assert.Equal(fixture.Expected.CredentialScope, trace.CredentialScope);
        Assert.Equal(fixture.Expected.StringToSign, trace.StringToSign);
        Assert.Equal(fixture.Expected.Signature, trace.Signature);
        Assert.Equal(
            $"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/{fixture.Expected.CredentialScope},SignedHeaders={trace.Canonical.SignedHeaders},Signature={fixture.Expected.Signature}",
            trace.AuthorizationHeader);
        Assert.DoesNotContain('\r', trace.CanonicalRequest);
        Assert.False(trace.CanonicalRequest.EndsWith('\n'));
        Assert.False(trace.StringToSign.EndsWith('\n'));
    }

    [Fact]
    public void Sign_counts_high_level_crypto_operations_and_redacts_key_outputs()
    {
        var trace = S3RequestSigner.Sign(AwsVectorFixture.Load("aws-get-object").Request);

        Assert.Equal(6, trace.Metrics.CanonicalComponents);
        Assert.Equal(0, trace.Metrics.QueryParameters);
        Assert.Equal(4, trace.Metrics.SignedHeaderCount);
        Assert.Equal(2, trace.Metrics.Sha256Operations);
        Assert.Equal(5, trace.Metrics.HmacSha256Operations);
        Assert.True(trace.Metrics.ElapsedMicroseconds >= 0);
        Assert.Collection(trace.KeyDerivation,
            step => Assert.Equal("20130524", step.Input),
            step => Assert.Equal("us-east-1", step.Input),
            step => Assert.Equal("s3", step.Input),
            step => Assert.Equal("aws4_request", step.Input));
        Assert.All(trace.KeyDerivation, step => Assert.Equal("[redacted]", step.Output));
        Assert.DoesNotContain("EXAMPLEKEY", JsonSerializer.Serialize(trace), StringComparison.Ordinal);
    }
}

internal sealed record AwsVectorFixture(
    string Id,
    string Title,
    string SourceUrl,
    SigningRequest Request,
    AwsExpectedResult Expected)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    internal static AwsVectorFixture Load(string id)
    {
        var assembly = typeof(AwsVectorTests).Assembly;
        var resource = Assert.Single(assembly.GetManifestResourceNames(),
            name => name.EndsWith($"{id}.json", StringComparison.Ordinal));
        using var stream = assembly.GetManifestResourceStream(resource)
            ?? throw new InvalidOperationException($"Missing test fixture: {id}");
        return JsonSerializer.Deserialize<AwsVectorFixture>(stream, JsonOptions)
            ?? throw new InvalidOperationException($"Invalid test fixture: {id}");
    }
}

internal sealed record AwsExpectedResult(
    string CanonicalRequest,
    string CanonicalRequestHash,
    string CredentialScope,
    string StringToSign,
    string Signature);
