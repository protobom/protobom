// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"database/sql/driver"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// valuerScanner is what every persistable protobom type implements.
type valuerScanner interface {
	proto.Message
	Value() (driver.Value, error)
	Scan(src any) error
}

// TestValueScanRoundTrip stores each of the persistable types through its
// database driver interface and reads it back.
func TestValueScanRoundTrip(t *testing.T) {
	docType := DocumentType_BUILD
	name := "doctype"

	for _, original := range []valuerScanner{
		&Document{
			Metadata: &Metadata{Id: "urn:uuid:11111111-2222-3333-4444-555555555555", Version: "1"},
			NodeList: &NodeList{
				Nodes:        []*Node{fullNode()},
				Edges:        []*Edge{{Type: Edge_dependsOn, From: "a", To: []string{"b"}}},
				RootElements: []string{"a"},
			},
		},
		&DocumentType{Type: &docType, Name: &name},
		&Edge{Type: Edge_contains, From: "a", To: []string{"b", "c"}},
		&ExternalReference{Url: "https://example.com", Type: ExternalReference_VCS, Comment: "c"},
		&Metadata{
			Id: "urn:uuid:11111111-2222-3333-4444-555555555555", Version: "3",
			Name:  "a document",
			Tools: []*Tool{{Vendor: "ACME", Name: "tool", Version: "1.0"}},
			Authors: []*Person{
				{Name: "Jane", Email: "jane@example.com"},
			},
		},
		fullNode(),
		&NodeList{
			Nodes:        []*Node{fullNode()},
			Edges:        []*Edge{{Type: Edge_dependsOn, From: "a", To: []string{"b"}}},
			RootElements: []string{"a"},
		},
		fullPerson(),
		&Property{Name: "prop", Data: "data"},
		&SourceData{Format: "text/spdx+json;version=2.3", Size: 1024},
		&Tool{Vendor: "ACME", Name: "tool", Version: "1.0"},
	} {
		t.Run(string(original.ProtoReflect().Descriptor().Name()), func(t *testing.T) {
			stored, err := original.Value()
			require.NoError(t, err)
			data, ok := stored.([]byte)
			require.True(t, ok, "the driver value is a byte slice")
			require.NotEmpty(t, data)

			read, ok := original.ProtoReflect().New().Interface().(valuerScanner)
			require.True(t, ok)
			require.NoError(t, read.Scan(data))
			require.True(t, proto.Equal(original, read),
				"the scanned message does not match the stored one")
		})
	}
}

// TestValueIsDeterministic checks that storing the same message twice
// produces the same bytes, which the driver value promises by marshaling
// deterministically.
func TestValueIsDeterministic(t *testing.T) {
	// A node with several map entries is where map ordering would show.
	node := fullNode()
	node.Hashes = map[int32]string{
		int32(HashAlgorithm_SHA1):   "aaa",
		int32(HashAlgorithm_SHA256): "bbb",
		int32(HashAlgorithm_SHA512): "ccc",
	}
	node.Identifiers = map[int32]string{
		int32(SoftwareIdentifierType_PURL):  "pkg:generic/a@1",
		int32(SoftwareIdentifierType_CPE23): "cpe:2.3:a:example:a:1:*:*:*:*:*:*:*",
	}

	first, err := node.Value()
	require.NoError(t, err)
	second, err := node.Value()
	require.NoError(t, err)
	require.Equal(t, first, second)
}

// TestScanContract checks the scanning corner cases: a database NULL leaves
// the message untouched, and anything but bytes is refused.
func TestScanContract(t *testing.T) {
	t.Run("nil leaves the message untouched", func(t *testing.T) {
		node := fullNode()
		before := proto.Clone(node)
		require.NoError(t, node.Scan(nil))
		require.True(t, proto.Equal(before, node))
	})

	t.Run("an unexpected type errors", func(t *testing.T) {
		require.Error(t, (&Node{}).Scan("not bytes"))
		require.Error(t, (&Node{}).Scan(42))
	})

	t.Run("garbage bytes error", func(t *testing.T) {
		require.Error(t, (&Node{}).Scan([]byte{0xff, 0xff, 0xff, 0xff}))
	})
}
