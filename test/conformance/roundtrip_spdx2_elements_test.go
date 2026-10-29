// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
)

// spdx2Formats are the SPDX 2 encodings a document round trips through.
var spdx2Formats = []formats.Format{
	formats.SPDX23JSON, formats.SPDX22JSON, formats.SPDX23TV, formats.SPDX22TV,
}

// spdx2RoundTrip writes a document in an SPDX 2 format and reads it back.
func spdx2RoundTrip(t *testing.T, doc *sbom.Document, format formats.Format) *sbom.Document {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, writer.New().WriteStreamWithOptions(
		doc, &buf, &writer.Options{Format: format, RenderOptions: &native.RenderOptions{Indent: 2}},
	))
	got, err := reader.New().ParseStreamWithOptions(
		bytes.NewReader(buf.Bytes()),
		&reader.Options{Format: format, UnserializeOptions: &native.UnserializeOptions{}},
	)
	require.NoError(t, err)
	return got
}

// TestRoundTripSPDX2Metadata pins the document level fields that survive a
// trip through every SPDX 2 encoding.
func TestRoundTripSPDX2Metadata(t *testing.T) {
	date := timestamppb.New(time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC))
	original := &sbom.Document{
		Metadata: &sbom.Metadata{
			Id:      "https://example.com/spdxdocs/metadata#DOCUMENT",
			Name:    "a round trip",
			Comment: "a document comment",
			Date:    date,
		},
		NodeList: &sbom.NodeList{
			Nodes:        []*sbom.Node{{Id: "pkg", Type: sbom.Node_PACKAGE, Name: "pkg"}},
			Edges:        []*sbom.Edge{},
			RootElements: []string{"pkg"},
		},
	}
	for _, format := range spdx2Formats {
		t.Run(string(format), func(t *testing.T) {
			got := spdx2RoundTrip(t, original, format)
			require.Equal(t, "a round trip", got.Metadata.Name)
			require.Equal(t, "a document comment", got.Metadata.Comment)
			require.Equal(t, date.AsTime(), got.Metadata.Date.AsTime())
		})
	}
}

// TestRoundTripSPDX2File pins the file fields that survive a trip through
// every SPDX 2 encoding.
func TestRoundTripSPDX2File(t *testing.T) {
	file := &sbom.Node{
		Id:          "file-1",
		Type:        sbom.Node_FILE,
		Name:        "a/file.txt",
		Comment:     "a comment",
		Copyright:   "Copyright someone",
		Attribution: []string{"attributed to someone", "and someone else"},
		Hashes:      map[int32]string{int32(sbom.HashAlgorithm_SHA256): "0123456789abcdef"},
	}
	original := &sbom.Document{
		Metadata: &sbom.Metadata{Id: "https://example.com/spdxdocs/file#DOCUMENT"},
		NodeList: &sbom.NodeList{
			Nodes:        []*sbom.Node{{Id: "pkg", Type: sbom.Node_PACKAGE, Name: "pkg"}, file},
			Edges:        []*sbom.Edge{{Type: sbom.Edge_contains, From: "pkg", To: []string{"file-1"}}},
			RootElements: []string{"pkg"},
		},
	}
	for _, format := range spdx2Formats {
		t.Run(string(format), func(t *testing.T) {
			got := spdx2RoundTrip(t, original, format).NodeList.GetNodeByID(file.Id)
			require.NotNil(t, got)
			require.Equal(t, sbom.Node_FILE, got.Type)
			require.Equal(t, file.Name, got.Name)
			require.Equal(t, file.Comment, got.Comment)
			require.Equal(t, file.Copyright, got.Copyright)
			require.Equal(t, file.Attribution, got.Attribution)
			require.Equal(t, file.Hashes, got.Hashes)
		})
	}
}

// TestRoundTripSPDX2Actors pins that the people and organizations a document
// credits keep their emails through every SPDX 2 encoding, which states an
// actor as "name (email)".
func TestRoundTripSPDX2Actors(t *testing.T) {
	authors := []*sbom.Person{
		{Name: "Jane Doe", Email: "jane@example.com"},
		{Name: "Acme", IsOrg: true, Email: "acme@example.com"},
		{Name: "Nameless Org", IsOrg: true},
	}
	pkg := &sbom.Node{
		Id: "pkg", Type: sbom.Node_PACKAGE, Name: "pkg",
		Suppliers:   []*sbom.Person{{Name: "Supplier Inc", IsOrg: true, Email: "supply@example.com"}},
		Originators: []*sbom.Person{{Name: "An Author", Email: "author@example.com"}},
	}
	original := &sbom.Document{
		Metadata: &sbom.Metadata{Id: "https://example.com/spdxdocs/actors#DOCUMENT", Authors: authors},
		NodeList: &sbom.NodeList{
			Nodes: []*sbom.Node{pkg}, Edges: []*sbom.Edge{}, RootElements: []string{"pkg"},
		},
	}
	for _, format := range spdx2Formats {
		t.Run(string(format), func(t *testing.T) {
			got := spdx2RoundTrip(t, original, format)
			require.Equal(t, authors, got.Metadata.Authors)
			gotPkg := got.NodeList.GetNodeByID("pkg")
			require.NotNil(t, gotPkg)
			require.Equal(t, pkg.Suppliers, gotPkg.Suppliers)
			require.Equal(t, pkg.Originators, gotPkg.Originators)
		})
	}
}
