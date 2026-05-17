// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/mod"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
)

// newMultirootDoc returns a synthetic protobom document with two top-level
// roots wired by a cross-root dependsOn edge. This is the minimal shape that
// exercises the headless write path (multiple roots + a dependency graph) and
// the symmetric read path.
func newMultirootDoc() *sbom.Document {
	return &sbom.Document{
		Metadata: &sbom.Metadata{
			Id:      "urn:uuid:11111111-2222-3333-4444-555555555555",
			Version: "1",
		},
		NodeList: &sbom.NodeList{
			RootElements: []string{"root-a", "root-b"},
			Nodes: []*sbom.Node{
				{
					Id:                 "root-a",
					Type:               sbom.Node_PACKAGE,
					Name:               "root-a",
					Version:            "1.0.0",
					PrimaryPurpose:     []sbom.Purpose{sbom.Purpose_APPLICATION},
					Licenses:           []string{},
					Attribution:        []string{},
					Suppliers:          []*sbom.Person{},
					Originators:        []*sbom.Person{},
					ExternalReferences: []*sbom.ExternalReference{},
					FileTypes:          []string{},
					Identifiers:        map[int32]string{},
					Hashes:             map[int32]string{},
				},
				{
					Id:                 "root-b",
					Type:               sbom.Node_PACKAGE,
					Name:               "root-b",
					Version:            "2.0.0",
					PrimaryPurpose:     []sbom.Purpose{sbom.Purpose_APPLICATION},
					Licenses:           []string{},
					Attribution:        []string{},
					Suppliers:          []*sbom.Person{},
					Originators:        []*sbom.Person{},
					ExternalReferences: []*sbom.ExternalReference{},
					FileTypes:          []string{},
					Identifiers:        map[int32]string{},
					Hashes:             map[int32]string{},
				},
			},
			Edges: []*sbom.Edge{
				{From: "root-a", Type: sbom.Edge_dependsOn, To: []string{"root-b"}},
			},
		},
	}
}

func headlessOptions(format formats.Format) *writer.Options {
	return &writer.Options{
		Format: format,
		RenderOptions: &native.RenderOptions{
			Indent: 2,
		},
		SerializeOptions: &native.SerializeOptions{
			Mods: map[mod.Mod]struct{}{
				mod.CYCLONEDX_MULTIROOT_HEADLESS: {},
			},
		},
	}
}

// TestCycloneDXHeadlessRoundtrip exercises the mod.CYCLONEDX_MULTIROOT_HEADLESS
// write path and the symmetric headless read path: a multiroot protobom
// document is serialized to a "headless" CycloneDX BOM (no metadata.component)
// and parsed back, then the result is compared to the original via
// NodeList.Equal.
//
// CycloneDX 1.7 is omitted because the cyclonedx-go library cannot decode
// it (the protobom serializer patches the specVersion on output, but the
// decoder still rejects 1.7 on read).
func TestCycloneDXHeadlessRoundtrip(t *testing.T) {
	for _, format := range []formats.Format{
		formats.CDX14JSON,
		formats.CDX15JSON,
		formats.CDX16JSON,
	} {
		t.Run(string(format), func(t *testing.T) {
			original := newMultirootDoc()

			w := writer.New()
			var buf bytes.Buffer
			require.NoError(t, w.WriteStreamWithOptions(original, &buf, headlessOptions(format)))

			// The rendered document must be genuinely headless: parse it
			// directly via cyclonedx-go and assert metadata.component is nil
			// and both roots are present as top-level components.
			rendered := buf.Bytes()
			decoded := &cdx.BOM{}
			require.NoError(t,
				cdx.NewBOMDecoder(bytes.NewReader(rendered), cdx.BOMFileFormatJSON).Decode(decoded),
			)
			require.NotNil(t, decoded.Metadata)
			require.Nil(t, decoded.Metadata.Component, "headless BOM must not carry metadata.component")
			require.NotNil(t, decoded.Components)
			require.Len(t, *decoded.Components, 2, "both roots should be top-level components")

			topRefs := map[string]bool{}
			for _, c := range *decoded.Components {
				topRefs[c.BOMRef] = true
			}
			require.True(t, topRefs["root-a"], "root-a should be a top-level component")
			require.True(t, topRefs["root-b"], "root-b should be a top-level component")

			// Now go through protobom's reader and verify equivalence.
			roundtripped, err := reader.New().ParseStream(bytes.NewReader(rendered))
			require.NoError(t, err)

			require.True(t,
				original.NodeList.Equal(roundtripped.NodeList),
				"roundtripped nodelist must equal original\noriginal: %+v\nroundtripped: %+v",
				original.NodeList, roundtripped.NodeList,
			)
		})
	}
}

// TestCycloneDXHeadlessReadWithoutMod confirms the unserializer side: a CDX
// document that lacks metadata.component is always read as headless, with
// each top-level component surfaced as a protobom root. The reader does not
// require any mod to do this.
func TestCycloneDXHeadlessReadWithoutMod(t *testing.T) {
	const headlessJSON = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "version": 1,
  "components": [
    {
      "bom-ref": "root-a",
      "type": "application",
      "name": "root-a",
      "version": "1.0.0"
    },
    {
      "bom-ref": "root-b",
      "type": "application",
      "name": "root-b",
      "version": "2.0.0"
    }
  ],
  "dependencies": [
    {"ref": "root-a", "dependsOn": ["root-b"]}
  ]
}`

	doc, err := reader.New().ParseStream(strings.NewReader(headlessJSON))
	require.NoError(t, err)

	require.ElementsMatch(t, []string{"root-a", "root-b"}, doc.NodeList.RootElements)
	require.Len(t, doc.NodeList.Nodes, 2)
	require.Len(t, doc.NodeList.Edges, 1)
	require.Equal(t, "root-a", doc.NodeList.Edges[0].From)
	require.Equal(t, sbom.Edge_dependsOn, doc.NodeList.Edges[0].Type)
	require.Equal(t, []string{"root-b"}, doc.NodeList.Edges[0].To)
}

// TestCycloneDXMultirootRejectedWithoutMod confirms the pre-existing safety
// net: a multiroot document still fails to serialize when the headless mod
// is not opted in.
func TestCycloneDXMultirootRejectedWithoutMod(t *testing.T) {
	original := newMultirootDoc()
	w := writer.New()

	opts := &writer.Options{
		Format:           formats.CDX15JSON,
		RenderOptions:    &native.RenderOptions{Indent: 2},
		SerializeOptions: &native.SerializeOptions{},
	}

	var buf bytes.Buffer
	err := w.WriteStreamWithOptions(original, &buf, opts)
	require.Error(t, err)
	require.Contains(t, err.Error(), "multiroot")
}
