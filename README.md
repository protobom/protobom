# protobom

`protobom` is a [protocol buffers](https://protobuf.dev/getting-started/)
representation of SBOM data able to ingest documents in modern 
[SPDX](https://spdx.dev/) and [CycloneDX](https://cyclonedx.org/) versions
without loss. It has an accompaining go library generated from the protocol
buffers that also implements ingesters for those formats.

## Suupported Versions and Formats

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
