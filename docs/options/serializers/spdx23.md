# SPDX 2.3 Serializer Options

The following options are supported by the SPDX 2.3 serializer

Options Type: `serializers.SPDX23Options`

| Option | Type | Default | Description
| --- | --- | --- | --- |
| `FailOnInvalidDocIdFragment` | `bool` | `false` | FailOnInvalidDocIdFragment makes the serializer return an error if the document ID has a fragment but  t is not set to "SPDXRef-Document". |
| `GenerateDocumentId` | `bool` | `true` | // GenerateDocumentId causes the serializer to generate a non-deterministic document ID when a protobom doesn't have one defined. |
