# Serializer and Unserializer Options

Each native format serializer supports options that control how protobom behaves
when reading and writing SBOM formats.

## Passing Options

Options are passed to the writer and reader with `WithFormatOptions` (or
`Options.SetFormatOptions`), keyed by the driver they are for. The key is one
of:

- The format string, for example `string(formats.SPDX3JSON)`, which is
  `"text/spdx+json;version=3.0.1"`. The options apply to that format only.
- The Go type of the serializer or unserializer, as `fmt`'s `%T` prints it,
  for example `"*serializers.SPDX3"` or `"*serializers.CDX"`. The options
  apply to every format the driver handles.

When both keys are set, the format string wins, as it is the more specific
of the two. The options passed to a single call (`WriteStreamWithOptions`,
`ParseStreamWithOptions` and friends) are looked up before the writer's or
reader's own, so a call's options under either key win over those set with
`WithFormatOptions`. A key that matches no driver is ignored.

The built-in serializers return an error when handed options of a type they
do not expect. None of the built-in unserializers take options today, so
they ignore any options they are handed; custom unserializers decide
themselves what to do with them.

The built-in serializers use these keys and options types:

| Format | Driver type key | Options type |
| --- | --- | --- |
| `formats.SPDX3JSON` | `*serializers.SPDX3` | `serializers.SPDX3Options` |
| `formats.SPDX23JSON` | `*serializers.SPDX23` | `serializers.SPDX23Options` |
| `formats.SPDX23TV` | `*serializers.SPDX23TV` | `serializers.SPDX23Options` |
| `formats.SPDX22JSON` | `*serializers.SPDX22` | `serializers.SPDX23Options` |
| `formats.SPDX22TV` | `*serializers.SPDX22TV` | `serializers.SPDX23Options` |
| `formats.CDX10JSON` to `formats.CDX17JSON` | `*serializers.CDX` (all versions) | `serializers.CDXOptions` |

Each SPDX 2 format has a driver type of its own, so options keyed by
`*serializers.SPDX23` do not reach the tag-value or SPDX 2.2 serializers. A
single CycloneDX driver type covers every CycloneDX version, so key options by
the format string to set them for one version only.

```go
opts := serializers.DefaultSPDX3Options
opts.ListCollectionElements = true

w := writer.New(
	writer.WithFormat(formats.SPDX3JSON),
	writer.WithFormatOptions(string(formats.SPDX3JSON), opts),
)
```

## [Serializer Options](serializers/)

## Unserializer Options
