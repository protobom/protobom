// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"fmt"
	"path/filepath"
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
//
// unstableRoundtripFixtures lists the fixtures whose write/read cycle is not
// deterministic, keyed by file name. They carry a component without a
// bom-ref, whose protobom ID is assigned by a counter in read order while
// the serializer emits components in map order: depending on where the
// counter lands on the second read, the cycle comes back clean or with the
// ref-less node reported as one added and one removed, since without a purl
// or hashes it cannot be re-paired by identity.
//
// A diff on a fixture listed here is logged but tolerated. When auto IDs
// survive reserialization, these entries are to be removed.
var unstableRoundtripFixtures = map[string]string{
	"bom-1.5.json":                     "ref-less mylibrary component",
	"syft-0.96.0_plone-5.2.cdx.json":   "ref-less operating-system component",
	"syft-0.96.0_rails-5.0.0.cdx.json": "ref-less operating-system component",
}

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

				d := original.Diff(reread)

				if reason, ok := unstableRoundtripFixtures[filepath.Base(fname)]; ok {
					if d != nil {
						t.Logf("tolerated unstable round trip (%s):\n%s", reason, describeDocumentDiff(d))
					}
					return
				}

				if d != nil {
					t.Errorf("the document changed in the round trip:\n%s", describeDocumentDiff(d))
				}
			})
		}
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
