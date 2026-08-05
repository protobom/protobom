package unserializers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
)

// testTagValueDocument places the file section after the package
// section. The tag-value parser attaches such files to the preceding
// package, which exercises the hoisting to the document level.
const testTagValueDocument = `SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: tv-test-doc
DocumentNamespace: https://example.com/test/tv
Creator: Organization: protobom
Created: 2026-01-01T00:00:00Z

PackageName: kubectl
SPDXID: SPDXRef-Package-kubectl
PackageVersion: v1.33.0
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: Apache-2.0
PackageLicenseDeclared: NOASSERTION
PackageCopyrightText: NOASSERTION

FileName: bin/kubectl
SPDXID: SPDXRef-File-kubectl
FileChecksum: SHA256: e5f7a7ed445673057c73686cb846e0c33ff0d5701fd43bf6aff16bb39ae14de2
LicenseConcluded: Apache-2.0
FileCopyrightText: NOASSERTION

Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-kubectl
`

func TestSPDX23TVUnserialize(t *testing.T) {
	doc, err := NewSPDX23TV().Unserialize(
		strings.NewReader(testTagValueDocument), &native.UnserializeOptions{}, nil,
	)
	require.NoError(t, err)
	require.Equal(t, "tv-test-doc", doc.GetMetadata().GetName())
	// tools-golang strips the SPDXRef- prefix from element identifiers,
	// so the document fragment reads DOCUMENT, as in the JSON path.
	require.Equal(t, "https://example.com/test/tv#DOCUMENT", doc.GetMetadata().GetId())

	require.Len(t, doc.GetNodeList().GetNodes(), 2)
	var pkgNode, fileNode *sbom.Node
	for _, n := range doc.GetNodeList().GetNodes() {
		switch n.GetType() {
		case sbom.Node_PACKAGE:
			pkgNode = n
		case sbom.Node_FILE:
			fileNode = n
		}
	}
	require.NotNil(t, pkgNode, "package node not found")
	require.NotNil(t, fileNode, "file node not found (package files not hoisted)")
	require.Equal(t, "kubectl", pkgNode.GetName())
	require.Equal(t, "v1.33.0", pkgNode.GetVersion())
	require.Equal(t, "Apache-2.0", pkgNode.GetLicenseConcluded())
	require.Equal(t, "bin/kubectl", fileNode.GetName())
	require.Equal(t,
		"e5f7a7ed445673057c73686cb846e0c33ff0d5701fd43bf6aff16bb39ae14de2",
		fileNode.GetHashes()[int32(sbom.HashAlgorithm_SHA256)],
	)

	// The document DESCRIBES relationship becomes the root element.
	require.Contains(t, doc.GetNodeList().GetRootElements(), pkgNode.GetId())

	// The hoisted file must be related to its package with an edge.
	related := false
	for _, edge := range doc.GetNodeList().GetEdges() {
		if edge.GetFrom() == pkgNode.GetId() {
			for _, to := range edge.GetTo() {
				if to == fileNode.GetId() {
					require.Equal(t, sbom.Edge_contains, edge.GetType())
					related = true
				}
			}
		}
	}
	require.True(t, related, "package -> file edge not found")
}

func TestSPDX23TVUnserializeInvalid(t *testing.T) {
	_, err := NewSPDX23TV().Unserialize(
		strings.NewReader("not a tag value document"), &native.UnserializeOptions{}, nil,
	)
	require.Error(t, err)
}
