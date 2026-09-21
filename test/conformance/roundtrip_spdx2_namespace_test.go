// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/writer"
)

const spdx2Namespace = "https://example.com/spdxdocs/namespace-roundtrip"

const spdx23NamespaceJSON = `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "namespace-roundtrip",
  "documentNamespace": "` + spdx2Namespace + `",
  "creationInfo": {"creators": ["Tool: test"], "created": "2026-01-01T00:00:00Z"},
  "packages": [{
    "name": "pkg", "SPDXID": "SPDXRef-Package-pkg", "versionInfo": "1.0",
    "downloadLocation": "NOASSERTION", "filesAnalyzed": false
  }],
  "relationships": [{
    "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
    "relatedSpdxElement": "SPDXRef-Package-pkg"
  }]
}`

var spdx22NamespaceJSON = strings.Replace(spdx23NamespaceJSON, "SPDX-2.3", "SPDX-2.2", 1)

const spdx23NamespaceTV = `SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: namespace-roundtrip
DocumentNamespace: ` + spdx2Namespace + `
Creator: Tool: test
Created: 2026-01-01T00:00:00Z

PackageName: pkg
SPDXID: SPDXRef-Package-pkg
PackageVersion: 1.0
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false

Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-pkg
`

var spdx22NamespaceTV = strings.Replace(spdx23NamespaceTV, "SPDX-2.3", "SPDX-2.2", 1)

// TestRoundTripSPDX2Namespace reads SPDX 2 documents and writes them again in
// every SPDX format, checking that the document keeps its namespace. The SPDX 2
// readers identify the document as "<namespace>#DOCUMENT", and the writers must
// recognize that identifier as naming the namespace rather than minting a new
// one.
func TestRoundTripSPDX2Namespace(t *testing.T) {
	inputs := []struct {
		name   string
		format formats.Format
		data   string
	}{
		{"SPDX 2.3 JSON", formats.SPDX23JSON, spdx23NamespaceJSON},
		{"SPDX 2.2 JSON", formats.SPDX22JSON, spdx22NamespaceJSON},
		{"SPDX 2.3 tag-value", formats.SPDX23TV, spdx23NamespaceTV},
		{"SPDX 2.2 tag-value", formats.SPDX22TV, spdx22NamespaceTV},
	}
	outputs := []struct {
		name   string
		format formats.Format
		// id is the document identifier the output reads back as.
		id string
		// namespace returns the namespace the output states.
		namespace func(t *testing.T, data []byte) string
	}{
		{"SPDX 2.3 JSON", formats.SPDX23JSON, spdx2Namespace + "#DOCUMENT", spdx2JSONNamespace},
		{"SPDX 2.2 JSON", formats.SPDX22JSON, spdx2Namespace + "#DOCUMENT", spdx2JSONNamespace},
		{"SPDX 2.3 tag-value", formats.SPDX23TV, spdx2Namespace + "#DOCUMENT", spdx2TVNamespace},
		{"SPDX 2.2 tag-value", formats.SPDX22TV, spdx2Namespace + "#DOCUMENT", spdx2TVNamespace},
		{"SPDX 3 JSON", formats.SPDX3JSON, spdx2Namespace, spdx3DocumentID},
	}

	for _, in := range inputs {
		for _, out := range outputs {
			t.Run(in.name+" to "+out.name, func(t *testing.T) {
				doc, err := reader.New().ParseStreamWithOptions(
					strings.NewReader(in.data),
					&reader.Options{Format: in.format, UnserializeOptions: &native.UnserializeOptions{}},
				)
				require.NoError(t, err)
				require.Equal(t, spdx2Namespace+"#DOCUMENT", doc.Metadata.Id)

				var buf bytes.Buffer
				require.NoError(t, writer.New().WriteStreamWithOptions(
					doc, &buf, &writer.Options{Format: out.format},
				))
				require.Equal(t, spdx2Namespace, out.namespace(t, buf.Bytes()))

				// And once more, to show the identifier is stable.
				again, err := reader.New().ParseStreamWithOptions(
					bytes.NewReader(buf.Bytes()),
					&reader.Options{Format: out.format, UnserializeOptions: &native.UnserializeOptions{}},
				)
				require.NoError(t, err)
				require.Equal(t, out.id, again.Metadata.Id)
			})
		}
	}
}

// spdx2JSONNamespace returns the namespace of an SPDX 2 JSON document.
func spdx2JSONNamespace(t *testing.T, data []byte) string {
	t.Helper()
	var doc struct {
		DocumentNamespace string `json:"documentNamespace"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	return doc.DocumentNamespace
}

// spdx2TVNamespace returns the namespace of an SPDX 2 tag-value document.
func spdx2TVNamespace(t *testing.T, data []byte) string {
	t.Helper()
	for line := range strings.Lines(string(data)) {
		if namespace, ok := strings.CutPrefix(line, "DocumentNamespace:"); ok {
			return strings.TrimSpace(namespace)
		}
	}
	t.Fatal("no DocumentNamespace in the tag-value document")
	return ""
}

// spdx3DocumentID returns the identifier of the SpdxDocument element of an
// SPDX 3 document, which is where its namespace ends up.
func spdx3DocumentID(t *testing.T, data []byte) string {
	t.Helper()
	var doc struct {
		Graph []struct {
			Type   string `json:"type"`
			SPDXID string `json:"spdxId"`
		} `json:"@graph"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	for _, element := range doc.Graph {
		if element.Type == "SpdxDocument" {
			return element.SPDXID
		}
	}
	t.Fatal("no SpdxDocument in the SPDX 3 document")
	return ""
}
