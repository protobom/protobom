# Regenerate Protobuf Autogenerate Libraries

The main protobom go types are generated from the
[protocol buffers definitions](api/sbom.proto). If the protobuf definitions are
changed, the go libraries need to be regenerated.

To regenerate, install the protobuf compiler `protoc`. It is available from
the [protobuf GitHub releases page](https://github.com/protocolbuffers/protobuf/releases/latest).

Once installed, simply run:

```bash
protoc --go_out=pkg api/sbom.proto
```

The main repository Makefile has a target to rebuild the libraries, you can
also rebuild them by running:

```bash
make proto
```

After invoking the compiler, the auto generated library
[`pkg/sbom/sbom.pb.go`](../pkg/sbom/sbom.pb.go) should be overwritten with the new
version, reflecting any changes.
