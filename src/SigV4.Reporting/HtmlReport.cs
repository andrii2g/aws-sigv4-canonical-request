using System.Globalization;
using System.Net;
using System.Text;
using SigV4.Core;
using SigV4.Experiments;

namespace SigV4.Reporting;

/// <summary>Renders portable, offline reports without exposing key material.</summary>
public static class HtmlReport
{
    private static readonly string Styles = ReadStyles();

    public static string Render(SigningTrace trace)
    {
        ArgumentNullException.ThrowIfNull(trace);
        return RenderDocument("A request, explained", trace, null);
    }

    public static string Render(ExperimentResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return RenderDocument(result.Title, result.Baseline, result);
    }

    private static string RenderDocument(string title, SigningTrace baseline, ExperimentResult? experiment)
    {
        var html = new StringBuilder();
        html.Append(CultureInfo.InvariantCulture, $$"""
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
              <meta name="color-scheme" content="light dark">
              <title>{{H(title)}} · SigV4 Request Lab</title>
              <style>{{Styles}}</style>
            </head>
            <body>
            <a class="skip-link" href="#request">Skip to request details</a>
            <main>
            <header class="hero">
              <p class="eyebrow">SIGV4 REQUEST LAB <span>OFFLINE EXPLANATION</span></p>
              <h1>{{H(title)}}</h1>
              <p class="lede">Follow an S3 GET request from its original fields to its cryptographic signature. Every displayed value comes from this signing run.</p>
              <div class="tags"><span>Synthetic credentials</span><span>No AWS requests</span><span>Empty request body</span></div>
            </header>
            <nav class="pipeline" aria-label="Signing pipeline">
              <a href="#request"><small>01</small>HTTP request</a><span aria-hidden="true">→</span>
              <a href="#canonical"><small>02</small>Canonical request</a><span aria-hidden="true">→</span>
              <a href="#hash"><small>03</small>SHA-256 hash</a><span aria-hidden="true">→</span>
              <a href="#string-to-sign"><small>04</small>String to sign</a><span aria-hidden="true">→</span>
              <a href="#signature"><small>06</small>HMAC signature</a>
              <a class="key-branch" href="#signing-key"><small>05</small>Scoped signing key ↗</a>
            </nav>
            """);

        if (experiment is not null)
        {
            AppendComparison(html, experiment);
        }

        AppendSection(html, "request", "01", "HTTP request", "The logical input uses unescaped paths and query values. The generated HTTP view encodes them for the request target; it is never sent.", baseline, experiment?.Variant, AppendRequest);
        AppendSection(html, "canonical", "02", "Canonical request", "Six canonical components are joined with LF (\\n) separators. Header lines also end in LF, creating the required blank line before SignedHeaders.", baseline, experiment?.Variant, AppendCanonical);
        AppendSection(html, "hash", "03", "SHA-256 hash", "The empty-body digest and the canonical-request digest are separate SHA-256 operations. The latter binds every canonical byte into the string to sign.", baseline, experiment?.Variant, AppendHashes);
        AppendSection(html, "string-to-sign", "04", "String to sign", "Algorithm, UTC timestamp, credential scope, and canonical-request hash form the final message. This string has no trailing newline.", baseline, experiment?.Variant, AppendStringToSign);
        AppendSection(html, "signing-key", "05", "Scoped signing key", "Four HMAC-SHA256 operations scope the key to a date, Region, and service. Only operation labels and public inputs are retained; every key output is redacted.", baseline, experiment?.Variant, AppendDerivation);
        AppendSection(html, "signature", "06", "Signature & Authorization", "The fifth HMAC-SHA256 operation signs the string to sign with the scoped key. Its output is formatted as lowercase hexadecimal.", baseline, experiment?.Variant, AppendSignature);
        AppendSection(html, "metrics", "RUN", "Processing metrics", "Counts cover one uncached signing run. Elapsed time measures signing only, excluding report generation and file I/O; it is diagnostic, not a benchmark.", baseline, experiment?.Variant, AppendMetrics);

        html.Append("""
            <footer><strong>An educational signer.</strong> This report explains a local calculation with synthetic credentials. Matching a published vector does not establish live AWS acceptance. Use the AWS SDK for production signing.</footer>
            </main>
            </body>
            </html>
            """);
        return html.ToString();
    }

    private static void AppendSection(StringBuilder html, string id, string number, string title, string description, SigningTrace baseline, SigningTrace? variant, Action<StringBuilder, SigningTrace> appendContent)
    {
        html.Append(CultureInfo.InvariantCulture, $"<section class=\"stage\" id=\"{id}\" aria-labelledby=\"{id}-title\"><div class=\"stage-heading\"><span class=\"stage-number\">{number}</span><h2 id=\"{id}-title\">{H(title)}</h2></div><p class=\"stage-description\">{H(description)}</p>");
        html.Append(variant is null ? "<div class=\"trace-grid\">" : "<div class=\"trace-grid comparison-grid\">");
        html.Append("<article class=\"trace-card\">");
        if (variant is not null)
        {
            html.Append("<h3 class=\"trace-label\">Baseline</h3>");
        }

        appendContent(html, baseline);
        html.Append("</article>");
        if (variant is not null)
        {
            html.Append("<article class=\"trace-card\"><h3 class=\"trace-label\">Variant</h3>");
            appendContent(html, variant);
            html.Append("</article>");
        }

        html.Append("</div></section>");
    }

    private static void AppendRequest(StringBuilder html, SigningTrace trace)
    {
        AppendFields(html,
            ("Method", trace.Request.Method),
            ("Unescaped path", trace.Request.Path),
            ("UTC timestamp", trace.Request.Timestamp.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)),
            ("Region", trace.Request.Region),
            ("Service", trace.Request.Service),
            ("Credential preset", trace.Request.CredentialPreset));
        AppendPairs(html, "Original query pairs (input order)", "Name", "Value", trace.Request.Query.Select(pair => (pair.Name, pair.Value)));
        AppendPairs(html, "Original supplied headers (input order)", "Name", "Value", trace.Request.Headers.Select(header => (header.Name, header.Value)));
        AppendText(html, "Generated HTTP request", trace.HttpRequest);
    }

    private static void AppendCanonical(StringBuilder html, SigningTrace trace)
    {
        AppendFields(html,
            ("HTTP method", trace.Canonical.Method),
            ("Canonical URI", trace.Canonical.Uri),
            ("Canonical query", trace.Canonical.Query),
            ("Signed headers", trace.Canonical.SignedHeaders),
            ("Payload SHA-256", trace.Canonical.PayloadHash));
        AppendText(html, "Canonical headers", trace.Canonical.Headers);
        AppendText(html, "Exact canonical request", trace.CanonicalRequest);
    }

    private static void AppendHashes(StringBuilder html, SigningTrace trace)
    {
        AppendText(html, "SHA-256 of empty body (0 bytes)", trace.Canonical.PayloadHash);
        AppendText(html, "SHA-256 of canonical request", trace.CanonicalRequestHash);
    }

    private static void AppendStringToSign(StringBuilder html, SigningTrace trace)
    {
        AppendText(html, "Credential scope", trace.CredentialScope);
        AppendText(html, "Exact string to sign", trace.StringToSign);
    }

    private static void AppendDerivation(StringBuilder html, SigningTrace trace)
    {
        html.Append("<div class=\"table-scroll\"><table><caption>HMAC-SHA256 key derivation</caption><thead><tr><th scope=\"col\">Step</th><th scope=\"col\">Key source</th><th scope=\"col\">Public message</th><th scope=\"col\">Key output</th></tr></thead><tbody>");
        foreach (var step in trace.KeyDerivation)
        {
            html.Append(CultureInfo.InvariantCulture, $"<tr><th scope=\"row\">{H(step.Name)}</th><td>{H(step.KeyLabel)}</td><td><code>{H(step.Input)}</code></td><td><span class=\"redacted\">[redacted]</span></td></tr>");
        }

        html.Append("</tbody></table></div><p class=\"note\">The secret access key and intermediate key bytes are absent from the report model.</p>");
    }

    private static void AppendSignature(StringBuilder html, SigningTrace trace)
    {
        AppendText(html, "Final signature", trace.Signature);
        AppendText(html, "Authorization header", trace.AuthorizationHeader);
    }

    private static void AppendMetrics(StringBuilder html, SigningTrace trace)
    {
        var metrics = trace.Metrics;
        html.Append("<dl class=\"metrics\">");
        AppendMetric(html, "Canonical components", metrics.CanonicalComponents.ToString(CultureInfo.InvariantCulture));
        AppendMetric(html, "Query pairs", metrics.QueryParameters.ToString(CultureInfo.InvariantCulture));
        AppendMetric(html, "Signed header names", metrics.SignedHeaderCount.ToString(CultureInfo.InvariantCulture));
        AppendMetric(html, "SHA-256 calls", metrics.Sha256Operations.ToString(CultureInfo.InvariantCulture));
        AppendMetric(html, "HMAC-SHA256 calls", metrics.HmacSha256Operations.ToString(CultureInfo.InvariantCulture));
        AppendMetric(html, "Signing elapsed", metrics.ElapsedMicroseconds.ToString("0.###", CultureInfo.InvariantCulture) + " µs");
        html.Append("</dl>");
    }

    private static void AppendMetric(StringBuilder html, string label, string value)
        => html.Append(CultureInfo.InvariantCulture, $"<div><dt>{H(label)}</dt><dd>{H(value)}</dd></div>");

    private static void AppendComparison(StringBuilder html, ExperimentResult experiment)
    {
        var outcome = experiment.Passed ? "PASS" : "FAIL";
        var statusClass = experiment.Passed ? "pass" : "fail";
        html.Append(CultureInfo.InvariantCulture, $$"""
            <section class="experiment {{statusClass}}" aria-labelledby="experiment-title">
              <div class="experiment-heading"><p class="eyebrow">CONTROLLED EXPERIMENT · {{H(experiment.Id)}}</p><span class="outcome">{{outcome}}</span></div>
              <h2 id="experiment-title">{{H(experiment.Title)}}</h2>
              <p>{{H(experiment.Description)}}</p>
              <dl class="experiment-summary">
                <div><dt>Expected</dt><dd>{{(experiment.ExpectMatch ? "Same signature" : "Different signatures")}}</dd></div>
                <div><dt>Observed</dt><dd>{{(experiment.SignaturesMatch ? "Same signature" : "Different signatures")}}</dd></div>
                <div><dt>First divergent stage</dt><dd>{{H(experiment.FirstDivergentStage ?? "None — canonical signing values match")}}</dd></div>
                <div><dt>Signature mismatches</dt><dd>{{(experiment.SignaturesMatch ? "0" : "1")}}</dd></div>
              </dl>
              <div class="table-scroll"><table class="diff-table"><caption>Baseline and variant, field by field</caption><thead><tr><th scope="col">Field</th><th scope="col">Comparison</th><th scope="col">Baseline</th><th scope="col">Variant</th></tr></thead><tbody>
            """);
        foreach (var field in ComparisonFields(experiment.Baseline, experiment.Variant))
        {
            var equal = StringComparer.Ordinal.Equals(field.Baseline, field.Variant);
            html.Append(CultureInfo.InvariantCulture, $"<tr class=\"{(equal ? "unchanged" : "changed")}\"><th scope=\"row\">{H(field.Name)}</th><td>{(equal ? "Same" : "Different")}</td><td><code>{H(field.Baseline)}</code></td><td><code>{H(field.Variant)}</code></td></tr>");
        }

        html.Append("</tbody></table></div><p class=\"note\">Different original presentations can canonicalize to the same values. A deliberately faulty signing rule is an experiment, not a valid alternate SigV4 implementation.</p></section>");
    }

    private static IEnumerable<(string Name, string Baseline, string Variant)> ComparisonFields(SigningTrace baseline, SigningTrace variant)
    {
        yield return ("HTTP method", baseline.Canonical.Method, variant.Canonical.Method);
        yield return ("Canonical URI", baseline.Canonical.Uri, variant.Canonical.Uri);
        yield return ("Canonical query", baseline.Canonical.Query, variant.Canonical.Query);
        yield return ("Canonical headers", baseline.Canonical.Headers, variant.Canonical.Headers);
        yield return ("Signed headers", baseline.Canonical.SignedHeaders, variant.Canonical.SignedHeaders);
        yield return ("Payload SHA-256", baseline.Canonical.PayloadHash, variant.Canonical.PayloadHash);
        yield return ("Canonical-request SHA-256", baseline.CanonicalRequestHash, variant.CanonicalRequestHash);
        yield return ("Credential scope", baseline.CredentialScope, variant.CredentialScope);
        yield return ("String to sign", baseline.StringToSign, variant.StringToSign);
        yield return ("Signature", baseline.Signature, variant.Signature);
        yield return ("Authorization header", baseline.AuthorizationHeader, variant.AuthorizationHeader);
    }

    private static void AppendFields(StringBuilder html, params (string Name, string Value)[] fields)
    {
        html.Append("<dl class=\"fields\">");
        foreach (var (name, value) in fields)
        {
            html.Append(CultureInfo.InvariantCulture, $"<div><dt>{H(name)}</dt><dd><code>{H(value.Length == 0 ? "(empty)" : value)}</code></dd></div>");
        }

        html.Append("</dl>");
    }

    private static void AppendPairs(StringBuilder html, string title, string leftLabel, string rightLabel, IEnumerable<(string Left, string Right)> pairs)
    {
        html.Append(CultureInfo.InvariantCulture, $"<details class=\"input-details\"><summary>{H(title)}</summary><div class=\"table-scroll\"><table><thead><tr><th scope=\"col\">{H(leftLabel)}</th><th scope=\"col\">{H(rightLabel)}</th></tr></thead><tbody>");
        var count = 0;
        foreach (var (left, right) in pairs)
        {
            html.Append(CultureInfo.InvariantCulture, $"<tr><td><code>{H(left)}</code></td><td><code>{H(right.Length == 0 ? "(empty)" : right)}</code></td></tr>");
            count++;
        }

        if (count == 0)
        {
            html.Append("<tr><td colspan=\"2\">No supplied values</td></tr>");
        }

        html.Append("</tbody></table></div></details>");
    }

    private static void AppendText(StringBuilder html, string title, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        html.Append(CultureInfo.InvariantCulture, $"<div class=\"text-block\"><div class=\"text-heading\"><h4>{H(title)}</h4><span>{bytes.Length.ToString(CultureInfo.InvariantCulture)} UTF-8 bytes</span></div><pre><code>{H(value)}</code></pre><details class=\"byte-details\"><summary>Inspect whitespace and bytes</summary><p class=\"note\">Visual markers: · space, ⇥ tab, ↵ LF, ␍ CR. The exact text above is unchanged.</p><pre class=\"whitespace\"><code>{H(VisibleWhitespace(value))}</code></pre><details><summary>UTF-8 hexadecimal bytes</summary><pre><code>{H(HexBytes(bytes))}</code></pre></details></details></div>");
    }

    private static string VisibleWhitespace(string value)
        => value.Replace(" ", "·", StringComparison.Ordinal)
            .Replace("\t", "⇥", StringComparison.Ordinal)
            .Replace("\r", "␍", StringComparison.Ordinal)
            .Replace("\n", "↵\n", StringComparison.Ordinal);

    private static string HexBytes(byte[] bytes)
    {
        var hex = new StringBuilder(bytes.Length * 3);
        for (var i = 0; i < bytes.Length; i++)
        {
            if (i > 0)
            {
                hex.Append(i % 16 == 0 ? '\n' : ' ');
            }

            hex.Append(bytes[i].ToString("X2", CultureInfo.InvariantCulture));
        }

        return hex.ToString();
    }

    private static string H(string value) => WebUtility.HtmlEncode(value);

    private static string ReadStyles()
    {
        using var stream = typeof(HtmlReport).Assembly.GetManifestResourceStream("SigV4.Reporting.report.css")
            ?? throw new InvalidOperationException("The embedded report stylesheet is missing.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
