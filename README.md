# protobom

`protobom` is a [protocol buffers](https://protobuf.dev/getting-started/)
representation of SBOM data able to ingest documents in modern 
[SPDX](https://spdx.dev/) and [CycloneDX](https://cyclonedx.org/) versions
without loss. It has an accompanying Go library generated from the protocol
buffers definiton that also implements ingesters for those formats.

Standard SBOMs are read by a reader using [parsers](docs/parsers.md) that
understand the common formats. Parsers create a neutral protobom from data
read from CycloneDX or SPDX documents.

A protobom can be rendered into standard SBOM formats by the writer using 
[serializers](docs/serializers.md) that know how to generate those documents.

## Supported Versions and Formats

The following table summarizes the current support for formats and encodings in
the golang library.

| Format | Version | Encoding | Read | Write |
| --- | --- | --- | --- | --- |
| SPDX | 2.2 | JSON | planned | - |
| SPDX | 2.2 | tag-value | planned | - |
| SPDX | 2.3 | JSON | supported | planned |
| SPDX | 2.3 | tag-value | planned | - |
| SPDX | 3.0 | JSON | planned | planned |
| CycloneDX | 1.4 | JSON | planned | supported |
| CycloneDX | 1.5 | JSON | planned | planned |

Other read and write implementations can potentially be written in 
other [languages supported by protobuf](https://protobuf.dev/getting-started/) 
