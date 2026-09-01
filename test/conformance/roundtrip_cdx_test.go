// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/prototext"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
)

// TestRoundTripCDXRealDocuments feeds the real-world CycloneDX documents of
// the conformance testdata through a full write/read cycle: each fixture is
// parsed into protobom, written back out as CycloneDX of the same version,
// parsed again, and the two protobom documents are compared with
// Document.Diff. Data the first read cannot capture never reaches the first
// document and is out of scope here: this test is about protobom's CycloneDX
// writer and reader agreeing with each other on real data.
func TestRoundTripCDXRealDocuments(t *testing.T) {
	for _, format := range []formats.Format{
		formats.CDX14JSON,
		formats.CDX15JSON,
		formats.CDX16JSON,
		formats.CDX17JSON,
	} {
		for _, fname := range findFiles(t, format) {
			t.Run(fname, func(t *testing.T) {
				original, err := reader.New().ParseFile(fname)
				require.NoError(t, err)

				var buf bytes.Buffer
				require.NoError(t, writer.New().WriteStreamWithOptions(
					original, &buf, &writer.Options{
						Format:        format,
						RenderOptions: &native.RenderOptions{Indent: 2},
					},
				))

				reread, err := reader.New().ParseStream(bytes.NewReader(buf.Bytes()))
				require.NoError(t, err)

				if d := original.Diff(reread); d != nil {
					t.Errorf("the document changed in the round trip:\n%s", describeDocumentDiff(d))
				}
			})
		}
	}
}

// TestRoundTripCDXTools writes a document's creation tools and reads them
// back. Protobom writes the legacy tools array, the only form its flat Tool
// type maps onto, and reads that same form back (tools expressed as
// components or services are not read; see docs/tool-representation.md).
func TestRoundTripCDXTools(t *testing.T) {
	for _, format := range []formats.Format{
		formats.CDX14JSON,
		formats.CDX15JSON,
		formats.CDX16JSON,
		formats.CDX17JSON,
	} {
		t.Run(string(format), func(t *testing.T) {
			original := &sbom.Document{
				Metadata: &sbom.Metadata{
					Id: "urn:uuid:11111111-2222-3333-4444-555555555555",
					Tools: []*sbom.Tool{
						{Vendor: "Anchore", Name: "syft", Version: "0.96.0"},
						{Name: "unversioned-tool"},
					},
				},
				NodeList: &sbom.NodeList{
					Nodes: []*sbom.Node{
						{Id: "root", Type: sbom.Node_PACKAGE, Name: "a package"},
					},
					Edges:        []*sbom.Edge{},
					RootElements: []string{"root"},
				},
			}

			var buf bytes.Buffer
			require.NoError(t, writer.New().WriteStreamWithOptions(
				original, &buf, &writer.Options{
					Format:        format,
					RenderOptions: &native.RenderOptions{Indent: 2},
				},
			))

			reread, err := reader.New().ParseStream(bytes.NewReader(buf.Bytes()))
			require.NoError(t, err)

			require.Equal(t, original.Metadata.Tools, reread.Metadata.Tools)
		})
	}
}

// TestRoundTripCDXAuthors writes a document's authors and reads them back.
// A CycloneDX author is an organizational contact holding only name, email
// and phone, so those fields survive; a person's URL, org flag and contacts
// have nowhere to go and are dropped on write.
func TestRoundTripCDXAuthors(t *testing.T) {
	for _, format := range []formats.Format{
		formats.CDX14JSON,
		formats.CDX15JSON,
		formats.CDX16JSON,
		formats.CDX17JSON,
	} {
		t.Run(string(format), func(t *testing.T) {
			original := &sbom.Document{
				Metadata: &sbom.Metadata{
					Id: "urn:uuid:11111111-2222-3333-4444-555555555555",
					Authors: []*sbom.Person{
						{Name: "Jane Doe", Email: "jane@example.com", Phone: "555-1234"},
						{Name: "Acme Inc", IsOrg: true, Email: "sbom@acme.example", Url: "https://acme.example"},
					},
				},
				NodeList: &sbom.NodeList{
					Nodes: []*sbom.Node{
						{Id: "root", Type: sbom.Node_PACKAGE, Name: "a package"},
					},
					Edges:        []*sbom.Edge{},
					RootElements: []string{"root"},
				},
			}

			var buf bytes.Buffer
			require.NoError(t, writer.New().WriteStreamWithOptions(
				original, &buf, &writer.Options{
					Format:        format,
					RenderOptions: &native.RenderOptions{Indent: 2},
				},
			))

			reread, err := reader.New().ParseStream(bytes.NewReader(buf.Bytes()))
			require.NoError(t, err)

			require.Equal(t, []*sbom.Person{
				{Name: "Jane Doe", Email: "jane@example.com", Phone: "555-1234"},
				// TODO(degradation): the URL and the org flag cannot be
				// stated on a CycloneDX author contact.
				{Name: "Acme Inc", Email: "sbom@acme.example"},
			}, reread.Metadata.Authors)
		})
	}
}

// maxDiffItems caps how many entries of each kind a diff description lists.
const maxDiffItems = 10

// describeDocumentDiff renders a DocumentDiff in a compact form for test
// failure messages.
func describeDocumentDiff(d *sbom.DocumentDiff) string {
	compact := prototext.MarshalOptions{Multiline: false}
	var b strings.Builder

	if d.Metadata != nil {
		fmt.Fprintf(&b, "metadata changes (%d):\n", d.Metadata.DiffCount)
		fmt.Fprintf(&b, "  added: %s\n", compact.Format(d.Metadata.Added))
		fmt.Fprintf(&b, "  removed: %s\n", compact.Format(d.Metadata.Removed))
	}

	nld := d.NodeList
	if nld == nil {
		return b.String()
	}

	fmt.Fprintf(&b, "nodes: %d added, %d removed, %d modified\n",
		len(nld.Added), len(nld.Removed), len(nld.Modified))
	for i, n := range nld.Added {
		if i == maxDiffItems {
			fmt.Fprintf(&b, "  ... %d more\n", len(nld.Added)-maxDiffItems)
			break
		}
		fmt.Fprintf(&b, "  + %s (%s)\n", n.Id, n.Name)
	}
	for i, n := range nld.Removed {
		if i == maxDiffItems {
			fmt.Fprintf(&b, "  ... %d more\n", len(nld.Removed)-maxDiffItems)
			break
		}
		fmt.Fprintf(&b, "  - %s (%s)\n", n.Id, n.Name)
	}
	for i, nd := range nld.Modified {
		if i == maxDiffItems {
			fmt.Fprintf(&b, "  ... %d more\n", len(nld.Modified)-maxDiffItems)
			break
		}
		fmt.Fprintf(&b, "  ~ %s (%d changes)\n", nd.Node1.Id, nd.DiffCount)
		fmt.Fprintf(&b, "      added: %s\n", compact.Format(nd.Added))
		fmt.Fprintf(&b, "      removed: %s\n", compact.Format(nd.Removed))
	}

	fmt.Fprintf(&b, "edges: %d added, %d removed\n", len(nld.EdgesAdded), len(nld.EdgesRemoved))
	for i, e := range nld.EdgesAdded {
		if i == maxDiffItems {
			fmt.Fprintf(&b, "  ... %d more\n", len(nld.EdgesAdded)-maxDiffItems)
			break
		}
		fmt.Fprintf(&b, "  + %s -[%s]-> %s\n", e.From, e.Type, strings.Join(e.To, ", "))
	}
	for i, e := range nld.EdgesRemoved {
		if i == maxDiffItems {
			fmt.Fprintf(&b, "  ... %d more\n", len(nld.EdgesRemoved)-maxDiffItems)
			break
		}
		fmt.Fprintf(&b, "  - %s -[%s]-> %s\n", e.From, e.Type, strings.Join(e.To, ", "))
	}

	if len(nld.RootElementsAdded) > 0 || len(nld.RootElementsRemoved) > 0 {
		fmt.Fprintf(&b, "root elements: +%v -%v\n", nld.RootElementsAdded, nld.RootElementsRemoved)
	}

	return b.String()
}
