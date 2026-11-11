# AWS SigV4 Canonical Request

An offline, educational implementation of AWS Signature Version 4 for S3 GET requests, built with .NET 10. It exposes canonicalization and cryptographic stages using fixed timestamps and AWS's published synthetic credentials. It never sends requests to AWS or discovers local credentials.

## Build and verify

Install a stable .NET 10 SDK, then run:

```sh
dotnet restore
dotnet build -c Release --no-restore
dotnet test -c Release --no-build
```

The tests compare exact canonical-request bytes, hashes, scopes, strings to sign, and signatures against three [published AWS S3 GET examples](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html#examples-signature-calculations). Additional tests specify encoding, duplicate query pairs, header normalization, and invalid-input behavior locally. Passing these offline tests does not establish live AWS interoperability.

## Supported signing contract

- Header-based SigV4 for S3 `GET`, with an empty body hashed using SHA-256.
- Explicit whole-second UTC timestamps, Region, and the `aws-documentation` synthetic credential preset.
- Unescaped logical paths and query names/values; percent signs are literal input and are encoded once. Repeated slashes and dot segments in S3 paths are preserved.
- Query pairs retain duplicates and empty values, and sort by encoded name then encoded value using ordinal comparison.
- Exactly one `Host` header is required. Every supplied header is signed. The signer adds `x-amz-date` and `x-amz-content-sha256` when missing, and checks consistency when supplied.
- Header names are lowercase and sorted; spaces/tabs in values are trimmed and collapsed; repeated values join with commas in input order.
- Canonical text uses UTF-8 and LF newlines. The HTTP display uses CRLF and preserves caller-supplied header presentation.
- Secret and derived-key bytes are excluded from traces; derivation outputs display `[redacted]`.

Presigned URLs, request bodies, temporary credentials, volatile transport headers, arbitrary secret keys, and SigV4a are outside scope. This project is an educational signer, not a replacement for the AWS SDK.

## Structure

- `src/SigV4.Core`: validated request model, S3 encoding, canonicalization, signing, and nonsecret trace.
- `src/SigV4.Experiments`: controlled comparisons and deliberately faulty rules, isolated from the correct public signer.
- `examples/aws-*.json`: frozen published vectors with expected intermediate values and provenance.
- `tests/SigV4.Tests`: published-vector and edge-case regression tests.

## Controlled experiments

`ExperimentCatalog.Run(id)` returns baseline and variant traces, the predicted result, and the first divergent signing stage. A successful experiment can intentionally produce different signatures: `Passed` means the observed outcome agrees with the prediction.

| ID | Lesson | Expected signatures |
| --- | --- | --- |
| `query-order` | Sorting removes query input-order differences | Same |
| `header-normalization` | Header-name casing and permitted whitespace normalize | Same |
| `skip-query-sort` | A faulty signer preserves unsorted query input | Different |
| `space-as-plus` | A faulty signer uses `+` instead of `%20` | Different |
| `skip-header-normalization` | A faulty signer retains header whitespace | Different |
| `request-tampering` | The actual signed object key changes | Different |

Faulty rules only change the canonical representation through an internal entry point available to the experiment assembly. `S3RequestSigner.Sign` always uses the correct rules. The HTTP display represents the supplied request and generated Authorization header; faulty canonical fields deliberately disagree with that request.

A CLI and HTML explanations are the next implementation step.
