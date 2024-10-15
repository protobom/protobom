# Regenerate Protobuf Autogenerate Libraries

The main protobom go types are generated from the [protocol buffers definitions](api/sbom.proto).
If the protobuf definitions are changed, the go libraries need to be regenerated.

To regenerate, [install the Buf CLI](https://buf.build/docs/installation).

If using `task` ([installation instructions](https://taskfile.dev/installation)), this can be done by running:

```bash
task install:buf install:protoc-gen-go
```

To ensure the protocol buffer definitions are properly formatted, contain no lint errors or breaking changes,
and rebuild the libraries, simply run one of the following:

```bash
# Run buf CLI directly
buf format --write
buf lint
git_tag=$(git describe --tags --abbrev=0)
buf breaking --against .git#tag=$git_tag,subdir=api
buf generate

# Run using `make`
make buf-format buf-lint proto

# Run using `task`
task fix:buf lint:buf proto
```

After invoking the compiler, the auto generated library [`pkg/sbom/sbom.pb.go`](../pkg/sbom/sbom.pb.go)
should be overwritten with the new version, reflecting any changes.
