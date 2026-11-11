using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;
using SigV4.Core;

namespace SigV4.Cli;

public sealed record SigningScenario
{
    public string Id { get; init; } = "custom";
    public string Title { get; init; } = "Custom scenario";
    public string? SourceUrl { get; init; }
    public required SigningRequest Request { get; init; }
    public ExpectedSigningValues? Expected { get; init; }
}

public sealed record ExpectedSigningValues(
    string CanonicalRequest,
    string CanonicalRequestHash,
    string CredentialScope,
    string StringToSign,
    string Signature);

public static class ScenarioCatalog
{
    public static JsonSerializerOptions JsonOptions { get; } = CreateOptions();
    public static ImmutableArray<SigningScenario> All { get; } = LoadBuiltIns();

    public static SigningScenario Find(string id) => All.FirstOrDefault(scenario => scenario.Id == id)
        ?? throw new ArgumentException("Unknown example. Use 'list' to see available example IDs.", nameof(id));

    public static SigningScenario Load(string path)
    {
        using var stream = File.OpenRead(path);
        return Read(stream);
    }

    public static ImmutableArray<string> FindMismatches(SigningScenario scenario, SigningTrace trace)
    {
        ArgumentNullException.ThrowIfNull(scenario);
        ArgumentNullException.ThrowIfNull(trace);
        var expected = scenario.Expected ?? throw new ArgumentException("Scenario has no expected signing values.", nameof(scenario));
        (string Name, string Expected, string Actual)[] fields =
        [
            ("Canonical request", expected.CanonicalRequest, trace.CanonicalRequest),
            ("Canonical request hash", expected.CanonicalRequestHash, trace.CanonicalRequestHash),
            ("Credential scope", expected.CredentialScope, trace.CredentialScope),
            ("String to sign", expected.StringToSign, trace.StringToSign),
            ("Signature", expected.Signature, trace.Signature),
        ];
        return [.. fields.Where(field => !StringComparer.Ordinal.Equals(field.Expected, field.Actual)).Select(field => field.Name)];
    }

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            RespectNullableAnnotations = true,
            RespectRequiredConstructorParameters = true,
            WriteIndented = true,
        };
        options.MakeReadOnly(populateMissingResolver: true);
        return options;
    }

    private static ImmutableArray<SigningScenario> LoadBuiltIns()
    {
        var assembly = typeof(ScenarioCatalog).Assembly;
        var scenarios = ImmutableArray.CreateBuilder<SigningScenario>();
        foreach (string name in assembly.GetManifestResourceNames().Where(name => name.EndsWith(".json", StringComparison.Ordinal)).Order(StringComparer.Ordinal))
        {
            using var stream = assembly.GetManifestResourceStream(name)
                ?? throw new InvalidOperationException("Missing embedded example.");
            scenarios.Add(Read(stream));
        }

        return scenarios.ToImmutable();
    }

    private static SigningScenario Read(Stream stream)
    {
        var scenario = JsonSerializer.Deserialize<SigningScenario>(stream, JsonOptions)
            ?? throw new JsonException("The scenario must be a JSON object.");
        if (scenario.Request is null)
        {
            throw new JsonException("The scenario requires a request object.");
        }

        return scenario;
    }
}
