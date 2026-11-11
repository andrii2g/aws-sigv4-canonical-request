using SigV4.Core;

namespace SigV4.Experiments;

/// <summary>A controlled comparison, including the outcome predicted by the lesson.</summary>
public sealed record ExperimentResult(
    string Id,
    string Title,
    string Description,
    SigningTrace Baseline,
    SigningTrace Variant,
    bool ExpectMatch,
    bool SignaturesMatch,
    string? FirstDivergentStage)
{
    public bool Passed => ExpectMatch == SignaturesMatch;
}

public sealed record ExperimentDefinition(string Id, string Title, string Description, bool ExpectMatch);
