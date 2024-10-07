# Unserializer

Unserializers implement the `native.Unserializer` interface. They are tasked to
transform standard SBOM documents in [CycloneDX](https://cyclonedx.org/) or
[SPDX](https://spdx.dev/) formats into a protobom. Readers use unserializers to
read an SBOM document into neutral protobom objects.

## Writing new Unserializers

- Implement the `native.Unserializer` interface
- Write the `Unserialize()` method to read an SBOM format into a protobom object

> See CDX [unserialization example](../pkg/native/unserializers/unserializer_cdx.go)

