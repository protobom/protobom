// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package unserializers

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// spdx3Doc wraps a graph in the envelope every SPDX 3 document has, so the
// tests below only have to say what is in the graph.
func spdx3Doc(graph string) string {
	return `{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
		"@graph": [` + graph + `]
	}`
}

// spdx3CreationInfo is the creation information the tests point their
// elements at. Every element in an SPDX 3 document has to have one.
const spdx3CreationInfo = `{
	"type": "CreationInfo",
	"@id": "_:creationinfo",
	"specVersion": "3.0.1",
	"created": "2026-08-07T12:30:45Z",
	"createdBy": ["https://spdx.org/rdf/3.0.1/terms/Core/SpdxOrganization"]
}`

func TestSPDX3UnserializeMetadata(t *testing.T) {
	t.Parallel()

	doc, err := NewSPDX3().Unserialize(strings.NewReader(spdx3Doc(spdx3CreationInfo+`,
		{
			"type": "SpdxDocument",
			"spdxId": "https://spdx.org/spdxdocs/protobom/test",
			"name": "a name",
			"comment": "a comment",
			"creationInfo": "_:creationinfo"
		}`)), nil, nil)
	require.NoError(t, err)

	// The document element is what protobom reads its metadata from, and
	// its identifier is the document's own.
	require.Equal(t, "https://spdx.org/spdxdocs/protobom/test", doc.Metadata.Id)
	require.Equal(t, "a name", doc.Metadata.Name)
	require.Equal(t, "a comment", doc.Metadata.Comment)
	require.Equal(t,
		time.Date(2026, 8, 7, 12, 30, 45, 0, time.UTC),
		doc.Metadata.Date.AsTime(),
	)

	// The graph itself is read in the steps that follow this one.
	require.NotNil(t, doc.NodeList)
	require.Empty(t, doc.NodeList.Nodes)
	require.Empty(t, doc.NodeList.Edges)
}

func TestSPDX3UnserializeRejects(t *testing.T) {
	t.Parallel()

	for name, graph := range map[string]string{
		// A document protobom cannot place: SPDX 3 allows a graph of loose
		// elements, but a bill of materials is always carried by a document.
		"a graph with no document element": spdx3CreationInfo,

		// A version this reader does not understand is refused rather than
		// read as though it were 3.0.1.
		"a later version": `{
			"type": "CreationInfo", "@id": "_:creationinfo",
			"specVersion": "3.1", "created": "2026-08-07T12:30:45Z",
			"createdBy": ["https://spdx.org/rdf/3.0.1/terms/Core/SpdxOrganization"]
		}, {
			"type": "SpdxDocument", "spdxId": "https://example.com/doc",
			"creationInfo": "_:creationinfo"
		}`,

		// A document that says nothing about its version is not guessed at.
		"no version at all": `{
			"type": "CreationInfo", "@id": "_:creationinfo",
			"created": "2026-08-07T12:30:45Z",
			"createdBy": ["https://spdx.org/rdf/3.0.1/terms/Core/SpdxOrganization"]
		}, {
			"type": "SpdxDocument", "spdxId": "https://example.com/doc",
			"creationInfo": "_:creationinfo"
		}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := NewSPDX3().Unserialize(strings.NewReader(spdx3Doc(graph)), nil, nil)
			require.Error(t, err)
		})
	}

	t.Run("a document whose context disagrees with itself", func(t *testing.T) {
		t.Parallel()
		data := `{
			"@context": "https://spdx.org/rdf/3.1/spdx-context.jsonld",
			"@graph": [` + spdx3CreationInfo + `, {
				"type": "SpdxDocument", "spdxId": "https://example.com/doc",
				"creationInfo": "_:creationinfo"
			}]
		}`
		_, err := NewSPDX3().Unserialize(strings.NewReader(data), nil, nil)
		require.ErrorContains(t, err, "@context")
	})

	t.Run("not JSON at all", func(t *testing.T) {
		t.Parallel()
		_, err := NewSPDX3().Unserialize(strings.NewReader("not a document"), nil, nil)
		require.Error(t, err)
	})
}
