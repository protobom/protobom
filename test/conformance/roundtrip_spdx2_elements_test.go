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
			Id:   "https://example.com/spdxdocs/metadata#DOCUMENT",
			Name: "a round trip",
			Date: date,
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
			require.Equal(t, date.AsTime(), got.Metadata.Date.AsTime())
		})
	}
}
