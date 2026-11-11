using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using SigV4.Core;
using SigV4.Experiments;
using SigV4.Reporting;

namespace SigV4.Tests;

public sealed class HtmlReportTests
{
    [Fact]
    public void ReportIncludesEveryPublicSigningStageAndExactByteInspection()
    {
        SigningTrace trace = SignRequest();

        string html = HtmlReport.Render(trace);

        foreach (string stage in new[] { "request", "canonical", "hash", "string-to-sign", "signing-key", "signature", "metrics" })
        {
            Assert.Contains($"id=\"{stage}\"", html, StringComparison.Ordinal);
        }

        foreach (string value in new[]
        {
            trace.HttpRequest, trace.CanonicalRequest, trace.CanonicalRequestHash,
            trace.CredentialScope, trace.StringToSign, trace.Signature, trace.AuthorizationHeader,
        })
        {
            Assert.Contains(WebUtility.HtmlEncode(value), html, StringComparison.Ordinal);
        }

        Assert.Contains($"{Encoding.UTF8.GetByteCount(trace.CanonicalRequest).ToString(CultureInfo.InvariantCulture)} UTF-8 bytes", html, StringComparison.Ordinal);
        Assert.Contains("UTF-8 hexadecimal bytes", html, StringComparison.Ordinal);
        Assert.Contains("SHA-256 calls", html, StringComparison.Ordinal);
        Assert.Contains("HMAC-SHA256 calls", html, StringComparison.Ordinal);
        Assert.Contains("excluding report generation and file I/O", html, StringComparison.Ordinal);
    }

    [Fact]
    public void UntrustedTraceAndExperimentTextCannotBecomeHtml()
    {
        const string markup = "</code></pre><script>alert('x')</script><img src=x onerror=alert(1)>";
        SigningTrace trace = SignRequest();
        SigningTrace untrusted = trace with
        {
            Request = trace.Request with
            {
                Path = markup,
                Query = [new QueryParameter(markup, markup)],
                Headers = [new RequestHeader(markup, markup)],
                CredentialPreset = markup,
            },
            HttpRequest = markup,
            Canonical = trace.Canonical with { Uri = markup, Headers = markup },
            Signature = markup,
            AuthorizationHeader = markup,
            KeyDerivation = [new KeyDerivationStep(markup, markup, markup)],
        };
        var experiment = new ExperimentResult(markup, markup, markup, trace, untrusted, false, false, markup);

        string html = HtmlReport.Render(experiment);

        Assert.Contains(WebUtility.HtmlEncode(markup), html, StringComparison.Ordinal);
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<img", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(markup, html, StringComparison.Ordinal);
        Assert.Contains("default-src 'none'", html, StringComparison.Ordinal);
    }

    [Fact]
    public void ReportContainsNoSecretOrDerivedKeyBytes()
    {
        const string exampleSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        byte[] key = Encoding.UTF8.GetBytes("AWS4" + exampleSecret);
        string html = HtmlReport.Render(SignRequest());

        Assert.DoesNotContain(exampleSecret, html, StringComparison.Ordinal);
        foreach (string message in new[] { "20130524", "us-east-1", "s3", "aws4_request" })
        {
            key = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(message));
            Assert.DoesNotContain(Convert.ToHexString(key), html, StringComparison.OrdinalIgnoreCase);
        }

        Assert.Equal(4, CountOccurrences(html, "class=\"redacted\">[redacted]</span>"));
    }

    [Theory]
    [InlineData("query-order", "Same signature", "None — canonical signing values match")]
    [InlineData("skip-query-sort", "Different signatures", "Canonical query")]
    [InlineData("space-as-plus", "Different signatures", "Canonical URI")]
    public void ExperimentReportExplainsExpectedOutcomeAndDivergence(string id, string outcome, string stage)
    {
        ExperimentResult experiment = ExperimentCatalog.Run(id);

        string html = HtmlReport.Render(experiment);

        Assert.Contains("class=\"outcome\">PASS</span>", html, StringComparison.Ordinal);
        Assert.Contains(WebUtility.HtmlEncode(outcome), html, StringComparison.Ordinal);
        Assert.Contains(WebUtility.HtmlEncode(stage), html, StringComparison.Ordinal);
        Assert.Contains("Baseline and variant, field by field", html, StringComparison.Ordinal);
        Assert.Contains("Baseline</h3>", html, StringComparison.Ordinal);
        Assert.Contains("Variant</h3>", html, StringComparison.Ordinal);
    }

    [Fact]
    public void UnexpectedExperimentOutcomeIsReportedAsFailure()
    {
        ExperimentResult experiment = ExperimentCatalog.Run("query-order") with { ExpectMatch = false };

        string html = HtmlReport.Render(experiment);

        Assert.Contains("class=\"outcome\">FAIL</span>", html, StringComparison.Ordinal);
        Assert.Contains("Different signatures", html, StringComparison.Ordinal);
        Assert.Contains("Same signature", html, StringComparison.Ordinal);
    }

    [Fact]
    public void WhitespaceViewsPreserveExactTextAndExposeControlBytes()
    {
        SigningTrace trace = SignRequest() with { HttpRequest = "GET / HTTP/1.1\r\nX-Note: a\tb  c\r\n" };

        string html = HtmlReport.Render(trace);

        Assert.Contains(WebUtility.HtmlEncode(trace.HttpRequest), html, StringComparison.Ordinal);
        Assert.Contains(WebUtility.HtmlEncode("GET·/·HTTP/1.1␍↵\nX-Note:·a⇥b··c␍↵\n"), html, StringComparison.Ordinal);
        Assert.Contains("0D 0A", html, StringComparison.Ordinal);
        Assert.Contains("61 09 62 20 20 63", html, StringComparison.Ordinal);
    }

    [Fact]
    public void ReportHasNoRemoteAssetsOrExecutableScript()
    {
        string html = HtmlReport.Render(SignRequest());

        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<link", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<img", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("url(", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("href=\"#canonical\"", html, StringComparison.Ordinal);
        Assert.Contains("prefers-reduced-motion", html, StringComparison.Ordinal);
    }

    private static SigningTrace SignRequest() => S3RequestSigner.Sign(new SigningRequest
    {
        Path = "/test.txt",
        Timestamp = new DateTimeOffset(2013, 5, 24, 0, 0, 0, TimeSpan.Zero),
        Headers = [new RequestHeader("Host", "examplebucket.s3.amazonaws.com")],
    });

    private static int CountOccurrences(string text, string value)
        => (text.Length - text.Replace(value, "", StringComparison.Ordinal).Length) / value.Length;
}
