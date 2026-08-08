// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package serializers

import (
	"crypto/sha1" //nolint:gosec // the algorithm is fixed by the SPDX specification
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/protobom/protobom/pkg/sbom"
)

func file(id, sha string) *sbom.Node {
	n := &sbom.Node{Id: id, Type: sbom.Node_FILE, Name: id}
	if sha != "" {
		n.Hashes = map[int32]string{int32(sbom.HashAlgorithm_SHA1): sha}
	}
	return n
}

// expected computes the code the way the specification words it, so the test
// does not simply restate the implementation.
func expected(shas ...string) string {
	joined := ""
	for _, s := range shas { // callers pass them already sorted
		joined += s
	}
	//nolint:gosec // the algorithm is fixed by the SPDX specification
	return fmt.Sprintf("%x", sha1.Sum([]byte(joined)))
}

const (
	shaA = "0000000000000000000000000000000000000001"
	shaB = "0000000000000000000000000000000000000002"
	shaC = "0000000000000000000000000000000000000003"
)

func TestPackageVerificationCode(t *testing.T) {
	pkg := &sbom.Node{Id: "pkg", Type: sbom.Node_PACKAGE, Name: "p"}

	t.Run("hashes are sorted, not taken in document order", func(t *testing.T) {
		nl := &sbom.NodeList{
			Nodes: []*sbom.Node{pkg, file("c", shaC), file("a", shaA), file("b", shaB)},
			Edges: []*sbom.Edge{{Type: sbom.Edge_contains, From: "pkg", To: []string{"c", "a", "b"}}},
		}
		require.Equal(t, expected(shaA, shaB, shaC), packageVerificationCode(nl, pkg))
	})

	// A node may be the source of several edges of the same type, which is how
	// the SPDX unserializer builds them: one edge per contained file.
	t.Run("files spread over several contains edges are all counted", func(t *testing.T) {
		nl := &sbom.NodeList{
			Nodes: []*sbom.Node{pkg, file("a", shaA), file("b", shaB), file("c", shaC)},
			Edges: []*sbom.Edge{
				{Type: sbom.Edge_contains, From: "pkg", To: []string{"a"}},
				{Type: sbom.Edge_contains, From: "pkg", To: []string{"b"}},
				{Type: sbom.Edge_contains, From: "pkg", To: []string{"c"}},
			},
		}
		require.Equal(t, expected(shaA, shaB, shaC), packageVerificationCode(nl, pkg))
	})

	t.Run("only the package's own files count", func(t *testing.T) {
		other := &sbom.Node{Id: "other", Type: sbom.Node_PACKAGE, Name: "o"}
		nl := &sbom.NodeList{
			Nodes: []*sbom.Node{pkg, other, file("a", shaA), file("b", shaB)},
			Edges: []*sbom.Edge{
				{Type: sbom.Edge_contains, From: "pkg", To: []string{"a"}},
				{Type: sbom.Edge_contains, From: "other", To: []string{"b"}},
			},
		}
		require.Equal(t, expected(shaA), packageVerificationCode(nl, pkg))
	})

	t.Run("a contained package is not a file", func(t *testing.T) {
		inner := &sbom.Node{
			Id: "inner", Type: sbom.Node_PACKAGE, Name: "i",
			Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA1): shaB},
		}
		nl := &sbom.NodeList{
			Nodes: []*sbom.Node{pkg, inner, file("a", shaA)},
			Edges: []*sbom.Edge{{Type: sbom.Edge_contains, From: "pkg", To: []string{"a", "inner"}}},
		}
		require.Equal(t, expected(shaA), packageVerificationCode(nl, pkg))
	})

	// A code standing for an incomplete list is worse than no code, since a
	// consumer cannot tell that it is incomplete.
	t.Run("no code when a file has no SHA1", func(t *testing.T) {
		nl := &sbom.NodeList{
			Nodes: []*sbom.Node{pkg, file("a", shaA), file("b", "")},
			Edges: []*sbom.Edge{{Type: sbom.Edge_contains, From: "pkg", To: []string{"a", "b"}}},
		}
		require.Empty(t, packageVerificationCode(nl, pkg))
	})

	t.Run("no code when there is nothing to stand for", func(t *testing.T) {
		empty := &sbom.NodeList{Nodes: []*sbom.Node{pkg}}
		require.Empty(t, packageVerificationCode(empty, pkg))

		noFiles := &sbom.NodeList{
			Nodes: []*sbom.Node{pkg, {Id: "inner", Type: sbom.Node_PACKAGE}},
			Edges: []*sbom.Edge{{Type: sbom.Edge_contains, From: "pkg", To: []string{"inner"}}},
		}
		require.Empty(t, packageVerificationCode(noFiles, pkg))
	})

	t.Run("nothing to compute for a file or for nothing at all", func(t *testing.T) {
		nl := &sbom.NodeList{Nodes: []*sbom.Node{file("a", shaA)}}
		require.Empty(t, packageVerificationCode(nl, file("a", shaA)))
		require.Empty(t, packageVerificationCode(nl, nil))
		require.Empty(t, packageVerificationCode(nil, pkg))
	})

	t.Run("hashes are compared in lower case", func(t *testing.T) {
		nl := &sbom.NodeList{
			Nodes: []*sbom.Node{pkg, file("a", "ABCDEF0000000000000000000000000000000001")},
			Edges: []*sbom.Edge{{Type: sbom.Edge_contains, From: "pkg", To: []string{"a"}}},
		}
		require.Equal(t, expected("abcdef0000000000000000000000000000000001"),
			packageVerificationCode(nl, pkg))
	})
}
