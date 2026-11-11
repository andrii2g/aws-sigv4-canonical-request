using System.Collections.Immutable;
using SigV4.Core;

namespace SigV4.Tests;

// These are locally specified edge cases; the AWS reference vectors are tested separately.
public sealed class CanonicalizationTests
{
    [Theory]
    [InlineData("", "/")]
    [InlineData("/photos//./../sample.jpg", "/photos//./../sample.jpg")]
    [InlineData("/café/雪 +%2F", "/caf%C3%A9/%E9%9B%AA%20%2B%252F")]
    [InlineData("/emoji/🔐", "/emoji/%F0%9F%94%90")]
    public void Sign_preserves_logical_s3_paths_and_encodes_utf8_bytes(string path, string expected)
    {
        var trace = S3RequestSigner.Sign(Request() with { Path = path });

        Assert.Equal(expected, trace.Canonical.Uri);
    }

    [Fact]
    public void Sign_encodes_then_sorts_query_pairs_preserving_duplicate_and_empty_values()
    {
        var request = Request() with
        {
            Query =
            [
                new("z", "last"),
                new("a", "two words"),
                new("a", "+"),
                new("a", "%"),
                new("empty", ""),
                new("Z", "upper"),
                new("é", "/"),
                new("a", "%")
            ]
        };

        var trace = S3RequestSigner.Sign(request);

        Assert.Equal("%C3%A9=%2F&Z=upper&a=%25&a=%25&a=%2B&a=two%20words&empty=&z=last",
            trace.Canonical.Query);
        Assert.Equal(8, trace.Metrics.QueryParameters);
    }

    [Fact]
    public void Sign_normalizes_header_names_whitespace_and_duplicate_values()
    {
        var request = Request() with
        {
            Headers =
            [
                new("hOsT", "examplebucket.s3.amazonaws.com"),
                new("X-Example", "  alpha\t \tbeta  "),
                new("X-Multi", " one  two"),
                new("x-multi", "three \t four ")
            ]
        };

        var trace = S3RequestSigner.Sign(request);

        Assert.Equal(
            "host:examplebucket.s3.amazonaws.com\n" +
            "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" +
            "x-amz-date:20130524T000000Z\n" +
            "x-example:alpha beta\n" +
            "x-multi:one two,three four\n",
            trace.Canonical.Headers);
        Assert.Equal("host;x-amz-content-sha256;x-amz-date;x-example;x-multi", trace.Canonical.SignedHeaders);
    }

    [Fact]
    public void Sign_is_invariant_to_query_order_header_case_and_permitted_whitespace()
    {
        var request = Request() with
        {
            Query = [new("b", "2"), new("a", "1")],
            Headers = [new("Host", "examplebucket.s3.amazonaws.com"), new("X-Example", "alpha beta")]
        };
        var equivalent = request with
        {
            Query = request.Query.Reverse().ToImmutableArray(),
            Headers = [new("x-example", " \talpha   beta\t"), new("HOST", " \texamplebucket.s3.amazonaws.com\t ")]
        };

        var baseline = S3RequestSigner.Sign(request);
        var changed = S3RequestSigner.Sign(equivalent);

        Assert.Equal(baseline.CanonicalRequest, changed.CanonicalRequest);
        Assert.Equal(baseline.StringToSign, changed.StringToSign);
        Assert.Equal(baseline.Signature, changed.Signature);
    }

    [Fact]
    public void Sign_uses_explicit_timestamp_and_scope_without_ambient_clock()
    {
        var request = Request();

        var first = S3RequestSigner.Sign(request);
        var repeated = S3RequestSigner.Sign(request);
        var otherRegion = S3RequestSigner.Sign(request with { Region = "eu-west-1" });
        var otherDate = S3RequestSigner.Sign(request with { Timestamp = request.Timestamp.AddDays(1) });

        Assert.Equal(first.Signature, repeated.Signature);
        Assert.Equal("20130524/us-east-1/s3/aws4_request", first.CredentialScope);
        Assert.Equal("20130524/eu-west-1/s3/aws4_request", otherRegion.CredentialScope);
        Assert.Equal("20130525/us-east-1/s3/aws4_request", otherDate.CredentialScope);
        Assert.NotEqual(first.Signature, otherRegion.Signature);
        Assert.NotEqual(first.Signature, otherDate.Signature);
    }

    [Theory]
    [InlineData("POST", "s3", "aws-documentation")]
    [InlineData("get", "s3", "aws-documentation")]
    [InlineData("GET", "iam", "aws-documentation")]
    [InlineData("GET", "s3", "real-credentials")]
    public void Sign_rejects_inputs_outside_the_educational_get_scope(string method, string service, string preset)
    {
        var request = Request() with { Method = method, Service = service, CredentialPreset = preset };

        Assert.ThrowsAny<ArgumentException>(() => S3RequestSigner.Sign(request));
    }

    [Fact]
    public void Sign_rejects_missing_or_non_utc_timestamps()
    {
        Assert.ThrowsAny<ArgumentException>(() => S3RequestSigner.Sign(Request() with { Timestamp = default }));
        Assert.ThrowsAny<ArgumentException>(() => S3RequestSigner.Sign(Request() with
        {
            Timestamp = new DateTimeOffset(2013, 5, 24, 2, 0, 0, TimeSpan.FromHours(2))
        }));
    }

    [Theory]
    [InlineData("X-Test\r\nInjected", "value")]
    [InlineData("X Test", "value")]
    [InlineData("X-Test", "value\r\nInjected: yes")]
    // secret-guard:allow(http-credential-header) reason="Synthetic rejection test; no credential value"
    [InlineData("Authorization", "value")]
    // secret-guard:allow(http-credential-header) reason="Synthetic rejection test; no session token"
    [InlineData("X-Amz-Security-Token", "value")]
    [InlineData("Connection", "keep-alive")]
    [InlineData("X-Amz-Date", "20130525T000000Z")]
    [InlineData("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")]
    public void Sign_rejects_invalid_unsupported_or_inconsistent_headers(string name, string value)
    {
        var request = Request() with
        {
            Headers = [new("Host", "examplebucket.s3.amazonaws.com"), new(name, value)]
        };

        Assert.ThrowsAny<ArgumentException>(() => S3RequestSigner.Sign(request));
    }

    [Fact]
    public void Sign_requires_a_host_and_rejects_duplicate_host_headers()
    {
        Assert.ThrowsAny<ArgumentException>(() => S3RequestSigner.Sign(Request() with { Headers = [] }));
        Assert.ThrowsAny<ArgumentException>(() => S3RequestSigner.Sign(Request() with
        {
            Headers = [new("Host", "first.example"), new("HOST", "second.example")]
        }));
    }

    [Theory]
    [InlineData(":")]
    [InlineData("host::80")]
    [InlineData("example.com:abc")]
    [InlineData("example.com:70000")]
    [InlineData("-bad.example")]
    public void Sign_rejects_malformed_host_authorities(string host)
    {
        var request = Request() with { Headers = [new("Host", host)] };

        Assert.ThrowsAny<ArgumentException>(() => S3RequestSigner.Sign(request));
    }

    [Fact]
    public void Sign_accepts_a_normalized_hostname_with_an_explicit_valid_port()
    {
        var request = Request() with { Headers = [new("Host", " \texample.com:8443\t ")] };

        var trace = S3RequestSigner.Sign(request);

        Assert.StartsWith("host:example.com:8443\n", trace.Canonical.Headers, StringComparison.Ordinal);
    }

    [Fact]
    public void Sign_rejects_unpaired_unicode_surrogates_instead_of_silently_replacing_them()
    {
        var request = Request() with { Path = "/invalid/\uD800" };

        Assert.ThrowsAny<ArgumentException>(() => S3RequestSigner.Sign(request));
    }

    [Fact]
    public void Sign_rejects_null_requests_default_collections_and_null_members()
    {
        Assert.ThrowsAny<ArgumentException>(() => S3RequestSigner.Sign(null!));
        Assert.ThrowsAny<ArgumentException>(() => S3RequestSigner.Sign(Request() with { Query = default }));
        Assert.ThrowsAny<ArgumentException>(() => S3RequestSigner.Sign(Request() with { Headers = default }));
        Assert.ThrowsAny<ArgumentException>(() => S3RequestSigner.Sign(Request() with { Query = [null!] }));
        Assert.ThrowsAny<ArgumentException>(() => S3RequestSigner.Sign(Request() with { Query = [new(null!, "value")] }));
        Assert.ThrowsAny<ArgumentException>(() => S3RequestSigner.Sign(Request() with { Headers = [null!] }));
        Assert.ThrowsAny<ArgumentException>(() => S3RequestSigner.Sign(Request() with { Headers = [new("Host", null!)] }));
    }

    private static SigningRequest Request() => new()
    {
        Headers = [new("Host", "examplebucket.s3.amazonaws.com")],
        Timestamp = new DateTimeOffset(2013, 5, 24, 0, 0, 0, TimeSpan.Zero)
    };
}
