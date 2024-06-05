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
the [`WriteStream()` function](https://github.com/protobom/protobom/blob/ca25413addfc841c1c91ee667ee1296194c231b0/pkg/writer/writer.go#L30C18-L44).

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

The initial POC of protobom shows a simple example on how to write a serializer:

1. A [type is defined](https://github.com/protobom/protobom/blob/ec58d8485c3df0f516a4c1896124e505c2d4bc9c/pkg/writer/serializer_cdx14.go#L19) to implement the interface (`SerializerCDX14`).
2. It `defines the Serialize` method:
    - The basic job of this function is [creating a standard SBOM object](https://github.com/protobom/protobom/blob/ec58d8485c3df0f516a4c1896124e505c2d4bc9c/pkg/writer/serializer_cdx14.go#L21)
    (a CycloneDX 1.4 document in this case) and populate its fields from the protobom
    data.
    - The main parts to note in this example are how it first [creates all the
    CycloneDX components from the protobom Nodes](https://github.com/protobom/protobom/blob/ec58d8485c3df0f516a4c1896124e505c2d4bc9c/pkg/writer/serializer_cdx14.go#L47-L55). Then, it [reads the edges from the
    graph](https://github.com/protobom/protobom/blob/ec58d8485c3df0f516a4c1896124e505c2d4bc9c/pkg/writer/serializer_cdx14.go#L85)
    and [based on the relationship kind](https://github.com/protobom/protobom/blob/ec58d8485c3df0f516a4c1896124e505c2d4bc9c/pkg/writer/serializer_cdx14.go#L98), either [assigns the nodes to the
    components tree](https://github.com/protobom/protobom/blob/ec58d8485c3df0f516a4c1896124e505c2d4bc9c/pkg/writer/serializer_cdx14.go#L99-L111) or just [notes them on the dependency tree](https://github.com/protobom/protobom/blob/ec58d8485c3df0f516a4c1896124e505c2d4bc9c/pkg/writer/serializer_cdx14.go#LL125C10-L128C7).
3. Note that the code has notes on where data degradation or loss is done
([example 1](https://github.com/protobom/protobom/blob/ec58d8485c3df0f516a4c1896124e505c2d4bc9c/pkg/writer/serializer_cdx14.go#L77-L78) [example 2](https://github.com/protobom/protobom/blob/ec58d8485c3df0f516a4c1896124e505c2d4bc9c/pkg/writer/serializer_cdx14.go#L132) ). These
comments need to be documented and will become the degradation stargey doc that
users can then read to understand when data loss due to translation occurs.
4. Finally, it [implements the `Render()` method](https://github.com/protobom/protobom/blob/ec58d8485c3df0f516a4c1896124e505c2d4bc9c/pkg/writer/serializer_cdx14.go#L155). In the POC the method is very simple, it just [creates a json.Encoder() and writes the
cast SBOM object to the writer](https://github.com/protobom/protobom/blob/ec58d8485c3df0f516a4c1896124e505c2d4bc9c/pkg/writer/serializer_cdx14.go#L159).
