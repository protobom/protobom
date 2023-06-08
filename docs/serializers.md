# The protobom Writer and SBOM Serializers

Serializers implement the `Serializer` interface. These simple objects
have two tasks in life:

1. __Serialize to another format:__ This means taking a protobom, reading its
data and returning a new SBOM data structure in a standard format
(CycloneDX or SPDX). This is what will be known in these docs as
_serialization_. Any data loss or modification due to the conversion process
occurs during serialization. 

1. __Rendering new documents:__ Once the protobom has been serialized to another
format, the serializer needs to know how to write the SBOM (now in SPDX or CDX)
to an `io.Writer` (a file, network stream, etc). The serializer takes the standard 
SBOM as an `interface{}` so it needs to know how to cast the SBOM into the
expected type.

Both tasks of the serializer are invoked by the `Writer` object when calling
the [`WriteStream()` function](https://github.com/bom-squad/protobom/blob/ca25413addfc841c1c91ee667ee1296194c231b0/pkg/writer/writer.go#L30C18-L44).

## Writing New Serializers 

Each serializer is tasked with turning a protobom to a standard SBOM object. In
general, serializers will be in charge of one format-version-encoding combination.
For example, one serializer should handle CycloneDX + 1.4 + JSON. There is 
opportunity for code reuse and optimization but in general, the idea is that one
serializer type handles a single format.

Implementing a new serializer means writing two methods: `Serialize()` and
`Render()`. The first one creates a standard SBOM object from a protobom and the 
second writes the SBOM object in the serializer's encoding (JSON, tag-value, XML, 
etc) to any stream that implements `io.Writer`. 

