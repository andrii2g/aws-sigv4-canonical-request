using SigV4.Experiments;

namespace SigV4.Tests;

public sealed class ExperimentTests
{
    [Theory]
    [InlineData("query-order")]
    [InlineData("header-normalization")]
    public void EquivalentPresentationChangesPreserveCanonicalBytesAndSignature(string id)
    {
        var result = ExperimentCatalog.Run(id);

        Assert.True(result.ExpectMatch);
        Assert.True(result.SignaturesMatch);
        Assert.True(result.Passed);
        Assert.Null(result.FirstDivergentStage);
        Assert.NotEqual(result.Baseline.HttpRequest, result.Variant.HttpRequest);
        Assert.Equal(result.Baseline.Canonical, result.Variant.Canonical);
        Assert.Equal(result.Baseline.CanonicalRequestHash, result.Variant.CanonicalRequestHash);
        Assert.Equal(result.Baseline.StringToSign, result.Variant.StringToSign);
        Assert.Equal(result.Baseline.Signature, result.Variant.Signature);
    }

    [Theory]
    [InlineData("skip-query-sort", "Canonical query")]
    [InlineData("space-as-plus", "Canonical URI")]
    [InlineData("skip-header-normalization", "Canonical headers")]
    public void FaultyRulesChangeSigningBytesWithoutChangingTheInputRequest(string id, string firstStage)
    {
        var result = ExperimentCatalog.Run(id);

        Assert.False(result.ExpectMatch);
        Assert.False(result.SignaturesMatch);
        Assert.True(result.Passed);
        Assert.Equal(firstStage, result.FirstDivergentStage);
        Assert.Equal(result.Baseline.Request, result.Variant.Request);
        Assert.NotEqual(result.Baseline.CanonicalRequest, result.Variant.CanonicalRequest);
        Assert.NotEqual(result.Baseline.CanonicalRequestHash, result.Variant.CanonicalRequestHash);
        Assert.NotEqual(result.Baseline.StringToSign, result.Variant.StringToSign);
        Assert.NotEqual(result.Baseline.Signature, result.Variant.Signature);
    }

    [Fact]
    public void ChangingTheObjectKeyChangesTheCanonicalUriAndSignature()
    {
        var result = ExperimentCatalog.Run("request-tampering");

        Assert.False(result.ExpectMatch);
        Assert.False(result.SignaturesMatch);
        Assert.True(result.Passed);
        Assert.Equal("Canonical URI", result.FirstDivergentStage);
        Assert.NotEqual(result.Baseline.Request.Path, result.Variant.Request.Path);
        Assert.Equal(result.Baseline.Canonical.Query, result.Variant.Canonical.Query);
        Assert.Equal(result.Baseline.Canonical.Headers, result.Variant.Canonical.Headers);
        Assert.NotEqual(result.Baseline.Signature, result.Variant.Signature);
    }

    [Theory]
    [InlineData("")]
    [InlineData("unknown")]
    public void UnknownExperimentIsRejected(string id)
    {
        Assert.Throws<ArgumentException>(() => ExperimentCatalog.Run(id));
    }
}
