# Contributing

Use the SDK selected by `global.json`. Keep nullable reference types enabled, recommended .NET analyzers clean, and warnings treated as errors. Follow `.editorconfig`; use file-scoped namespaces and descriptive names. Prefer small pure transformations with explicit inputs over ambient configuration or time.

Before committing an implementation step, run the Release build and relevant tests. Use `dotnet format --verify-no-changes` to check formatting. Add tests for protocol behavior, published examples, and input boundaries rather than mirroring implementation details.

Keep the correct signing pipeline separate from deliberately broken experiment rules. Never change a published fixture's expected output to make a test pass. Preserve source URLs and clearly distinguish AWS vectors from locally specified edge cases.

Runtime code must remain offline. Do not add AWS credential discovery, network clients, arbitrary credential inputs, or secret/derived-key fields to report models. HTML-encode displayed input. Treat changes to the supported input contract as behavior changes and document them.
