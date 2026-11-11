using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SigV4.Cli;
using SigV4.Core;

namespace SigV4.Tests;

public sealed class CliTests
{
    private const string ObjectSignature = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [Theory]
    [InlineData("")]
    [InlineData("help")]
    [InlineData("--help")]
    public void Help_describes_the_available_commands(string command)
    {
        var result = Run(command.Length == 0 ? [] : [command]);

        Assert.Equal(0, result.ExitCode);
        Assert.Empty(result.Error);
        Assert.Contains("explain", result.Output, StringComparison.Ordinal);
        Assert.Contains("compare", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public void List_contains_the_published_examples_and_experiments()
    {
        var result = Run("list");

        Assert.Equal(0, result.ExitCode);
        Assert.Empty(result.Error);
        Assert.Contains("aws-get-object", result.Output, StringComparison.Ordinal);
        Assert.Contains("aws-get-lifecycle", result.Output, StringComparison.Ordinal);
        Assert.Contains("aws-list-objects", result.Output, StringComparison.Ordinal);
        Assert.Contains("query-order", result.Output, StringComparison.Ordinal);
        Assert.Contains("space-as-plus", result.Output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("verify-examples")]
    [InlineData("verify-experiments")]
    public void Verification_commands_report_success_for_the_supplied_lessons(string command)
    {
        var result = Run(command);

        Assert.Equal(0, result.ExitCode);
        Assert.Empty(result.Error);
        Assert.NotEmpty(result.Output);
    }

    [Fact]
    public void Explain_exports_the_published_signature_as_valid_json_and_html()
    {
        using var directory = new TemporaryDirectory();
        string htmlPath = directory.File("request.html");
        string jsonPath = directory.File("request.json");

        var result = Run("explain", "--example", "aws-get-object", "--html", htmlPath, "--json", jsonPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Empty(result.Error);
        string html = ReadUtf8(htmlPath);
        string json = ReadUtf8(jsonPath);
        using var document = JsonDocument.Parse(json);
        Assert.Equal(JsonValueKind.Object, document.RootElement.ValueKind);
        Assert.Equal(ObjectSignature, document.RootElement.GetProperty("signature").GetString());
        Assert.Contains(ObjectSignature, html, StringComparison.Ordinal);
        Assert.Contains("<!doctype html>", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("EXAMPLEKEY", html + json + result.Output + result.Error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Explain_accepts_an_input_without_expected_results_and_encodes_markup(bool explicitNullExpected)
    {
        using var directory = new TemporaryDirectory();
        string inputPath = directory.File("input.json");
        string htmlPath = directory.File("request.html");
        string jsonPath = directory.File("request.json");
        WriteInput(inputPath, new SigningRequest
        {
            Path = "/reports/<script>.txt",
            Timestamp = new DateTimeOffset(2013, 5, 24, 0, 0, 0, TimeSpan.Zero),
            Headers = [new("Host", "examplebucket.s3.amazonaws.com"), new("X-Note", "<script>alert(1)</script> &")],
        });
        if (explicitNullExpected)
        {
            var input = JsonNode.Parse(ReadUtf8(inputPath))!.AsObject();
            input["expected"] = null;
            File.WriteAllText(inputPath, input.ToJsonString(), new UTF8Encoding(false));
        }

        var result = Run("explain", "--input", inputPath, "--html", htmlPath, "--json", jsonPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Empty(result.Error);
        string html = ReadUtf8(htmlPath);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<script>", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("[redacted]", html, StringComparison.Ordinal);
        using var document = JsonDocument.Parse(ReadUtf8(jsonPath));
        Assert.Equal(JsonValueKind.Object, document.RootElement.ValueKind);
    }

    [Fact]
    public void An_expected_experiment_mismatch_is_a_successful_command()
    {
        using var directory = new TemporaryDirectory();
        string jsonPath = directory.File("comparison.json");

        var result = Run("compare", "--experiment", "space-as-plus", "--json", jsonPath);

        Assert.Equal(0, result.ExitCode);
        Assert.Empty(result.Error);
        string json = ReadUtf8(jsonPath);
        using var document = JsonDocument.Parse(json);
        Assert.Equal(JsonValueKind.Object, document.RootElement.ValueKind);
        Assert.Equal("space-as-plus", document.RootElement.GetProperty("id").GetString());
        Assert.True(document.RootElement.GetProperty("passed").GetBoolean());
        Assert.False(document.RootElement.GetProperty("signaturesMatch").GetBoolean());
        Assert.Equal("Canonical URI", document.RootElement.GetProperty("firstDivergentStage").GetString());
        Assert.DoesNotContain("EXAMPLEKEY", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Incorrect_expected_values_return_verification_failure_and_export_the_computed_trace()
    {
        using var directory = new TemporaryDirectory();
        string inputPath = directory.File("input.json");
        string jsonPath = directory.File("request.json");
        var fixture = AwsVectorFixture.Load("aws-get-object");
        string incorrectFixture = JsonSerializer.Serialize(fixture with
        {
            Expected = fixture.Expected with { Signature = new string('0', 64) },
        }, JsonOptions);
        File.WriteAllText(inputPath, incorrectFixture, new UTF8Encoding(false));

        var result = Run("explain", "--input", inputPath, "--json", jsonPath);

        Assert.Equal(1, result.ExitCode);
        Assert.Empty(result.Error);
        Assert.Contains("FAIL", result.Output, StringComparison.Ordinal);
        using var document = JsonDocument.Parse(ReadUtf8(jsonPath));
        Assert.Equal(ObjectSignature, document.RootElement.GetProperty("signature").GetString());
    }

    [Theory]
    [MemberData(nameof(InvalidArguments))]
    public void Invalid_usage_returns_a_concise_error(string[] arguments)
    {
        var result = Run(arguments);

        AssertInputError(result);
    }

    public static TheoryData<string[]> InvalidArguments { get; } = new()
    {
        new string[] { "unknown" },
        new string[] { "explain", "--unknown", "x" },
        new string[] { "explain", "--example" },
        new string[] { "explain", "--example", "aws-get-object", "--example", "aws-get-lifecycle" },
        new string[] { "explain", "--example", "aws-get-object", "--input", "scenario.json" },
        new string[] { "compare", "--experiment" },
        new string[] { "compare", "--experiment", "unknown" },
    };

    [Fact]
    public void Malformed_json_input_does_not_create_outputs()
    {
        using var directory = new TemporaryDirectory();
        string inputPath = directory.File("input.json");
        string htmlPath = directory.File("report.html");
        File.WriteAllText(inputPath, "{", new UTF8Encoding(false));

        var result = Run("explain", "--input", inputPath, "--html", htmlPath);

        AssertInputError(result);
        Assert.False(System.IO.File.Exists(htmlPath));
    }

    [Theory]
    [InlineData("envelope")]
    [InlineData("request")]
    public void Unknown_properties_in_otherwise_valid_json_are_rejected(string level)
    {
        using var directory = new TemporaryDirectory();
        string inputPath = directory.File("input.json");
        string htmlPath = directory.File("report.html");
        WriteInput(inputPath, AwsVectorFixture.Load("aws-get-object").Request);
        var input = JsonNode.Parse(ReadUtf8(inputPath))!.AsObject();
        var target = level == "request" ? input["request"]!.AsObject() : input;
        target["secretAccessKey"] = "not-allowed";
        File.WriteAllText(inputPath, input.ToJsonString(), new UTF8Encoding(false));

        var result = Run("explain", "--input", inputPath, "--html", htmlPath);

        AssertInputError(result);
        Assert.False(System.IO.File.Exists(htmlPath));
    }

    [Theory]
    [InlineData("query")]
    [InlineData("expected")]
    public void Missing_required_nested_values_are_input_errors(string incompleteValue)
    {
        using var directory = new TemporaryDirectory();
        string inputPath = directory.File("input.json");
        string htmlPath = directory.File("report.html");
        WriteInput(inputPath, AwsVectorFixture.Load("aws-get-object").Request);
        var input = JsonNode.Parse(ReadUtf8(inputPath))!.AsObject();
        if (incompleteValue == "query")
        {
            input["request"]!.AsObject()["query"] = new JsonArray(new JsonObject { ["name"] = "prefix" });
        }
        else
        {
            input["expected"] = new JsonObject();
        }

        File.WriteAllText(inputPath, input.ToJsonString(), new UTF8Encoding(false));

        var result = Run("explain", "--input", inputPath, "--html", htmlPath);

        AssertInputError(result);
        Assert.False(System.IO.File.Exists(htmlPath));
    }

    [Fact]
    public void Unknown_credential_preset_is_rejected_before_export()
    {
        using var directory = new TemporaryDirectory();
        string inputPath = directory.File("input.json");
        string htmlPath = directory.File("report.html");
        WriteInput(inputPath, AwsVectorFixture.Load("aws-get-object").Request with { CredentialPreset = "real-account" });

        var result = Run("explain", "--input", inputPath, "--html", htmlPath);

        AssertInputError(result);
        Assert.False(System.IO.File.Exists(htmlPath));
    }

    [Fact]
    public void Existing_outputs_are_preserved_and_no_other_output_is_created_without_force()
    {
        using var directory = new TemporaryDirectory();
        string htmlPath = directory.File("report.html");
        string jsonPath = directory.File("report.json");
        File.WriteAllText(htmlPath, "keep this file", new UTF8Encoding(false));

        var result = Run("explain", "--example", "aws-get-object", "--html", htmlPath, "--json", jsonPath);

        AssertInputError(result);
        Assert.Equal("keep this file", ReadUtf8(htmlPath));
        Assert.False(System.IO.File.Exists(jsonPath));
    }

    [Fact]
    public void Force_explicitly_replaces_an_existing_output()
    {
        using var directory = new TemporaryDirectory();
        string jsonPath = directory.File("report.json");
        File.WriteAllText(jsonPath, "replace this file", new UTF8Encoding(false));

        var result = Run("explain", "--example", "aws-get-object", "--json", jsonPath, "--force");

        Assert.Equal(0, result.ExitCode);
        Assert.Empty(result.Error);
        string json = ReadUtf8(jsonPath);
        using var document = JsonDocument.Parse(json);
        Assert.Contains(ObjectSignature, json, StringComparison.Ordinal);
    }

    [Fact]
    public void Colliding_output_paths_are_rejected_before_writing()
    {
        using var directory = new TemporaryDirectory();
        string outputPath = directory.File("report.txt");

        var result = Run("explain", "--example", "aws-get-object", "--html", outputPath,
            "--json", Path.Combine(directory.Path, ".", "report.txt"), "--force");

        AssertInputError(result);
        Assert.False(System.IO.File.Exists(outputPath));
    }

    [Fact]
    public void Output_cannot_replace_its_input_even_with_force()
    {
        using var directory = new TemporaryDirectory();
        string inputPath = directory.File("input.json");
        WriteInput(inputPath, AwsVectorFixture.Load("aws-get-object").Request);
        string original = ReadUtf8(inputPath);

        var result = Run("explain", "--input", inputPath,
            "--json", Path.Combine(directory.Path, ".", "input.json"), "--force");

        AssertInputError(result);
        Assert.Equal(original, ReadUtf8(inputPath));
    }

    [Fact]
    public void An_invalid_second_output_is_detected_before_the_first_is_written()
    {
        using var directory = new TemporaryDirectory();
        string htmlPath = directory.File("report.html");

        var result = Run("explain", "--example", "aws-get-object", "--html", htmlPath, "--json", directory.Path);

        AssertInputError(result);
        Assert.False(System.IO.File.Exists(htmlPath));
    }

    [Fact]
    public void An_output_below_a_file_is_rejected_before_another_report_is_written()
    {
        using var directory = new TemporaryDirectory();
        string htmlPath = directory.File("report.html");
        string blockerPath = directory.File("existing-file");
        File.WriteAllText(blockerPath, "keep this file", new UTF8Encoding(false));

        var result = Run("explain", "--example", "aws-get-object", "--html", htmlPath,
            "--json", Path.Combine(blockerPath, "report.json"));

        AssertInputError(result);
        Assert.False(System.IO.File.Exists(htmlPath));
        Assert.Equal("keep this file", ReadUtf8(blockerPath));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Planned_output_paths_cannot_be_ancestors_of_each_other(bool htmlIsParent)
    {
        using var directory = new TemporaryDirectory();
        string parentPath = directory.File("report");
        string childPath = Path.Combine(parentPath, "trace.json");
        string htmlPath = htmlIsParent ? parentPath : childPath;
        string jsonPath = htmlIsParent ? childPath : parentPath;

        var result = Run("explain", "--example", "aws-get-object", "--html", htmlPath, "--json", jsonPath);

        AssertInputError(result);
        Assert.False(System.IO.File.Exists(parentPath));
        Assert.False(System.IO.File.Exists(childPath));
        Assert.False(Directory.Exists(parentPath));
    }

    private static CliResult Run(params string[] arguments)
    {
        using var output = new StringWriter(CultureInfo.InvariantCulture);
        using var error = new StringWriter(CultureInfo.InvariantCulture);
        int exitCode = CliApplication.Run(arguments, output, error);
        return new CliResult(exitCode, output.ToString(), error.ToString());
    }

    private static void AssertInputError(CliResult result)
    {
        Assert.Equal(2, result.ExitCode);
        Assert.NotEmpty(result.Error);
        Assert.DoesNotContain("   at ", result.Error, StringComparison.Ordinal);
    }

    private static void WriteInput(string path, SigningRequest request)
    {
        string json = JsonSerializer.Serialize(new
        {
            id = "custom",
            title = "Custom synthetic request",
            sourceUrl = "https://example.invalid/scenario",
            request,
        }, JsonOptions);
        File.WriteAllText(path, json, new UTF8Encoding(false));
    }

    private static string ReadUtf8(string path) => File.ReadAllText(path, new UTF8Encoding(false, true));

    private sealed record CliResult(int ExitCode, string Output, string Error);

    private sealed class TemporaryDirectory : IDisposable
    {
        private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("sigv4-cli-tests-");

        public string Path => directory.FullName;

        public string File(string name) => System.IO.Path.Combine(Path, name);

        public void Dispose() => directory.Delete(recursive: true);
    }
}
