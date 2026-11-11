using System.Globalization;
using System.Text;
using System.Text.Json;
using SigV4.Core;
using SigV4.Experiments;
using SigV4.Reporting;

namespace SigV4.Cli;

public static class CliApplication
{
    private const string Help = """
        SigV4 Lab - offline educational S3 GET signing (.NET 10)

        Commands:
          list
          explain (--example ID | --input FILE) [--html FILE] [--json FILE] [--force]
          compare --experiment ID [--html FILE] [--json FILE] [--force]
          verify-examples
          verify-experiments
          help

        Paths/query pairs are unescaped logical text. Only synthetic credentials are supported.
        Reports are self-contained local files. No AWS requests or credential discovery occur.
        Existing output files require --force. Exit codes: 0 success, 1 verification failure, 2 input/IO error.
        """;

    public static int Run(string[] args, TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        try
        {
            if (args.Length == 0 || (args.Length == 1 && args[0] is "help" or "--help" or "-h"))
            {
                output.WriteLine(Help);
                return 0;
            }

            return args[0] switch
            {
                "list" when args.Length == 1 => List(output),
                "verify-examples" when args.Length == 1 => VerifyExamples(output),
                "verify-experiments" when args.Length == 1 => VerifyExperiments(output),
                "explain" => Explain(ParseOptions(args, ["--example", "--input", "--html", "--json", "--force"]), output),
                "compare" => Compare(ParseOptions(args, ["--experiment", "--html", "--json", "--force"]), output),
                _ => throw new ArgumentException("Unknown command or unexpected arguments. Run 'help' for usage."),
            };
        }
        catch (Exception exception) when (exception is ArgumentException or JsonException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            error.WriteLine($"Error: {exception.Message}");
            return 2;
        }
    }

    private static int List(TextWriter output)
    {
        output.WriteLine("Published AWS examples:");
        foreach (var scenario in ScenarioCatalog.All)
        {
            output.WriteLine($"  {scenario.Id}: {scenario.Title}");
        }

        output.WriteLine("Controlled experiments:");
        foreach (var experiment in ExperimentCatalog.All)
        {
            output.WriteLine($"  {experiment.Id}: {experiment.Title}");
        }

        return 0;
    }

    private static int Explain(Dictionary<string, string?> options, TextWriter output)
    {
        bool hasExample = options.TryGetValue("--example", out string? id);
        bool hasInput = options.TryGetValue("--input", out string? input);
        if (hasExample == hasInput)
        {
            throw new ArgumentException("Supply exactly one of --example ID or --input FILE.");
        }

        ValidateOutputPaths(options, input);
        var scenario = hasExample ? ScenarioCatalog.Find(id!) : ScenarioCatalog.Load(input!);
        var trace = S3RequestSigner.Sign(scenario.Request);
        output.WriteLine(scenario.Title);
        output.WriteLine($"Canonical request (UTF-8, LF):\n{trace.CanonicalRequest}\n");
        output.WriteLine($"Canonical request SHA-256: {trace.CanonicalRequestHash}");
        output.WriteLine($"String to sign:\n{trace.StringToSign}\n");
        output.WriteLine($"Signature: {trace.Signature}");
        output.WriteLine($"Authorization: {trace.AuthorizationHeader}");
        PrintMetrics(trace.Metrics, output);
        WriteReports(options, () => HtmlReport.Render(trace), trace, output);

        if (scenario.Expected is null)
        {
            return 0;
        }

        var mismatches = ScenarioCatalog.FindMismatches(scenario, trace);
        output.WriteLine(mismatches.IsEmpty ? "PASS: all expected signing values match." : $"FAIL: {string.Join(", ", mismatches)} differ from expectations.");
        return mismatches.IsEmpty ? 0 : 1;
    }

    private static int Compare(Dictionary<string, string?> options, TextWriter output)
    {
        if (!options.TryGetValue("--experiment", out string? id))
        {
            throw new ArgumentException("Supply --experiment ID.");
        }

        ValidateOutputPaths(options, input: null);
        var result = ExperimentCatalog.Run(id!);
        output.WriteLine(result.Title);
        output.WriteLine(result.Description);
        output.WriteLine($"Expected: {(result.ExpectMatch ? "matching" : "different")} signatures; observed: {(result.SignaturesMatch ? "matching" : "different")} signatures.");
        output.WriteLine($"First divergent stage: {result.FirstDivergentStage ?? "none"}");
        output.WriteLine($"Baseline signature: {result.Baseline.Signature}");
        output.WriteLine($"Variant signature:  {result.Variant.Signature}");
        output.WriteLine(result.Passed ? "PASS: the experiment behaved as expected." : "FAIL: unexpected experiment outcome.");
        WriteReports(options, () => HtmlReport.Render(result), result, output);
        return result.Passed ? 0 : 1;
    }

    private static int VerifyExamples(TextWriter output)
    {
        int matched = 0;
        foreach (var scenario in ScenarioCatalog.All)
        {
            var mismatches = ScenarioCatalog.FindMismatches(scenario, S3RequestSigner.Sign(scenario.Request));
            if (mismatches.IsEmpty) { matched++; }
            output.WriteLine($"{(mismatches.IsEmpty ? "PASS" : "FAIL")} {scenario.Id}{(mismatches.IsEmpty ? "" : $": {string.Join(", ", mismatches)}")}");
        }

        output.WriteLine($"{matched}/{ScenarioCatalog.All.Length} AWS vectors match all expected stages (offline verification).");
        return matched == ScenarioCatalog.All.Length ? 0 : 1;
    }

    private static int VerifyExperiments(TextWriter output)
    {
        int passed = 0;
        int mismatches = 0;
        foreach (var definition in ExperimentCatalog.All)
        {
            var result = ExperimentCatalog.Run(definition.Id);
            if (result.Passed) { passed++; }
            if (!result.SignaturesMatch) { mismatches++; }
            output.WriteLine($"{(result.Passed ? "PASS" : "FAIL")} {result.Id}: {(result.SignaturesMatch ? "matching signatures" : $"different signatures; first divergence: {result.FirstDivergentStage}")}");
        }

        output.WriteLine($"{passed}/{ExperimentCatalog.All.Length} experiments behaved as expected; {mismatches} signature mismatches.");
        return passed == ExperimentCatalog.All.Length ? 0 : 1;
    }

    private static Dictionary<string, string?> ParseOptions(string[] args, string[] allowed)
    {
        var options = new Dictionary<string, string?>(StringComparer.Ordinal);
        for (int index = 1; index < args.Length; index++)
        {
            string key = args[index];
            if (!allowed.Contains(key, StringComparer.Ordinal) || options.ContainsKey(key))
            {
                throw new ArgumentException("Unknown or duplicate option. Run 'help' for usage.");
            }

            if (key == "--force")
            {
                options.Add(key, null);
                continue;
            }

            if (++index >= args.Length || string.IsNullOrWhiteSpace(args[index]) || args[index].StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Option {key} requires a value.");
            }

            options.Add(key, args[index]);
        }

        return options;
    }

    private static void ValidateOutputPaths(Dictionary<string, string?> options, string? input)
    {
        StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var paths = new HashSet<string>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        if (input is not null) { paths.Add(Path.GetFullPath(input)); }
        foreach (string key in new[] { "--html", "--json" })
        {
            if (!options.TryGetValue(key, out string? path)) { continue; }
            string fullPath = Path.GetFullPath(path!);
            if (paths.Any(existing => existing.Equals(fullPath, comparison) ||
                existing.StartsWith(fullPath + Path.DirectorySeparatorChar, comparison) ||
                fullPath.StartsWith(existing + Path.DirectorySeparatorChar, comparison)))
            {
                throw new ArgumentException("Input, HTML, and JSON paths must be different and cannot contain one another.");
            }

            paths.Add(fullPath);

            if (Directory.Exists(fullPath) || (File.Exists(fullPath) && !options.ContainsKey("--force")))
            {
                throw new IOException("Output already exists. Choose a new path or use --force for an existing file.");
            }

            for (string? parent = Path.GetDirectoryName(fullPath); parent is not null; parent = Path.GetDirectoryName(parent))
            {
                if (File.Exists(parent))
                {
                    throw new IOException("An output directory path points to an existing file.");
                }
            }
        }
    }

    private static void WriteReports<T>(Dictionary<string, string?> options, Func<string> renderHtml, T value, TextWriter output)
    {
        if (options.TryGetValue("--html", out string? html))
        {
            WriteFile(html!, renderHtml(), options.ContainsKey("--force"));
            output.WriteLine($"HTML report: {Path.GetFullPath(html!)}");
        }

        if (options.TryGetValue("--json", out string? json))
        {
            WriteFile(json!, JsonSerializer.Serialize(value, ScenarioCatalog.JsonOptions), options.ContainsKey("--force"));
            output.WriteLine($"JSON trace: {Path.GetFullPath(json!)}");
        }
    }

    private static void WriteFile(string path, string content, bool overwrite)
    {
        string fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        string temporaryPath = fullPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporaryPath, content, new UTF8Encoding(false));
            File.Move(temporaryPath, fullPath, overwrite);
        }
        finally
        {
            if (File.Exists(temporaryPath)) { File.Delete(temporaryPath); }
        }
    }

    private static void PrintMetrics(SigningMetrics metrics, TextWriter output) =>
        output.WriteLine(string.Create(CultureInfo.InvariantCulture,
            $"Metrics: {metrics.CanonicalComponents} canonical components, {metrics.QueryParameters} query pairs, {metrics.SignedHeaderCount} signed headers, {metrics.Sha256Operations} SHA-256 + {metrics.HmacSha256Operations} HMAC-SHA256 calls; {metrics.ElapsedMicroseconds:F2} us (diagnostic, excludes rendering/IO)."));
}
