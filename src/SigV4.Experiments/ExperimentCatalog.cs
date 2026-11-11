using System.Collections.Immutable;
using SigV4.Core;

namespace SigV4.Experiments;

/// <summary>Offline lessons that distinguish equivalent requests from signing defects and tampering.</summary>
public static class ExperimentCatalog
{
    public static ImmutableArray<ExperimentDefinition> All { get; } =
    [
        new("query-order", "Query order is irrelevant", "Reorder the input query pairs. Correct canonicalization sorts them, preserving the signature.", true),
        new("header-normalization", "Header presentation is irrelevant", "Change header-name casing and permitted spaces or tabs. Correct normalization preserves the signature.", true),
        new("skip-query-sort", "Fault: skip query sorting", "Preserve input query order in the canonical request instead of sorting the encoded pairs.", false),
        new("space-as-plus", "Fault: encode spaces as plus", "Use form-style '+' for a space instead of the required '%20'. The signer now signs different bytes.", false),
        new("skip-header-normalization", "Fault: preserve header whitespace", "Retain leading, trailing, and repeated header whitespace instead of normalizing it.", false),
        new("request-tampering", "Change the signed object key", "Change the actual object key while signing both requests correctly. The canonical URI and signature change.", false),
    ];

    public static ExperimentResult Run(string id)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        var definition = All.FirstOrDefault(item => StringComparer.Ordinal.Equals(item.Id, id))
            ?? throw new ArgumentException("Unknown experiment. Use 'list' to see the available experiment IDs.", nameof(id));

        var request = CreateRequest();
        return id switch
        {
            "query-order" => Compare(definition, request, request with { Query = request.Query.Reverse().ToImmutableArray() }),
            "header-normalization" => CompareHeaderPresentation(definition, request),
            "skip-query-sort" => Compare(definition, request, request, parts => parts with { Query = QueryInInputOrder(request) }),
            "space-as-plus" => Compare(definition, request, request, parts => parts with
            {
                Uri = parts.Uri.Replace("%20", "+", StringComparison.Ordinal),
                Query = parts.Query.Replace("%20", "+", StringComparison.Ordinal),
            }),
            "skip-header-normalization" => Compare(definition, request, request, parts => parts with
            {
                Headers = parts.Headers.Replace("x-demo-note:alpha beta\n", "x-demo-note:  alpha\t  beta  \n", StringComparison.Ordinal),
            }),
            "request-tampering" => Compare(definition, request, request with { Path = "/photos/different image.jpg" }),
            _ => throw new InvalidOperationException("An experiment definition has no implementation."),
        };
    }

    private static SigningRequest CreateRequest() => new()
    {
        Path = "/photos/sample image.jpg",
        Timestamp = new DateTimeOffset(2013, 5, 24, 0, 0, 0, TimeSpan.Zero),
        Query = [new("prefix", "J"), new("max-keys", "2")],
        Headers = [new("Host", "examplebucket.s3.amazonaws.com"), new("X-Demo-Note", "  alpha\t  beta  ")],
    };

    private static ExperimentResult CompareHeaderPresentation(ExperimentDefinition definition, SigningRequest request)
    {
        var variant = request with
        {
            Headers = [new("HOST", "examplebucket.s3.amazonaws.com"), new("x-demo-note", "alpha beta")],
        };
        return Compare(definition, request, variant);
    }

    private static string QueryInInputOrder(SigningRequest request) => string.Join('&', request.Query.Select(pair =>
        $"{S3UriEncoder.Encode(pair.Name)}={S3UriEncoder.Encode(pair.Value)}"));

    private static ExperimentResult Compare(
        ExperimentDefinition definition,
        SigningRequest baselineRequest,
        SigningRequest variantRequest,
        Func<CanonicalRequestParts, CanonicalRequestParts>? transform = null)
    {
        var baseline = S3RequestSigner.Sign(baselineRequest);
        var variant = transform is null
            ? S3RequestSigner.Sign(variantRequest)
            : S3RequestSigner.SignTransformed(variantRequest, transform);

        return new ExperimentResult(
            definition.Id,
            definition.Title,
            definition.Description,
            baseline,
            variant,
            definition.ExpectMatch,
            StringComparer.Ordinal.Equals(baseline.Signature, variant.Signature),
            FindFirstDivergence(baseline, variant));
    }

    private static string? FindFirstDivergence(SigningTrace baseline, SigningTrace variant)
    {
        (string Stage, string Baseline, string Variant)[] stages =
        [
            ("HTTP method", baseline.Canonical.Method, variant.Canonical.Method),
            ("Canonical URI", baseline.Canonical.Uri, variant.Canonical.Uri),
            ("Canonical query", baseline.Canonical.Query, variant.Canonical.Query),
            ("Canonical headers", baseline.Canonical.Headers, variant.Canonical.Headers),
            ("Signed headers", baseline.Canonical.SignedHeaders, variant.Canonical.SignedHeaders),
            ("Payload hash", baseline.Canonical.PayloadHash, variant.Canonical.PayloadHash),
            ("Canonical request", baseline.CanonicalRequest, variant.CanonicalRequest),
            ("Canonical request hash", baseline.CanonicalRequestHash, variant.CanonicalRequestHash),
            ("Credential scope", baseline.CredentialScope, variant.CredentialScope),
            ("String to sign", baseline.StringToSign, variant.StringToSign),
            ("Signature", baseline.Signature, variant.Signature),
        ];

        foreach (var stage in stages)
        {
            if (!StringComparer.Ordinal.Equals(stage.Baseline, stage.Variant))
            {
                return stage.Stage;
            }
        }

        return null;
    }
}
