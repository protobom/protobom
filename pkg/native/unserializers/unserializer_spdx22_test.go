package unserializers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
)

const testJSON22Document = `{
  "spdxVersion": "SPDX-2.2",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "json22-test-doc",
  "documentNamespace": "https://example.com/test/json22",
  "creationInfo": {
    "created": "2026-01-01T00:00:00Z",
    "creators": ["Organization: protobom"]
  },
  "packages": [
    {
      "name": "kubectl",
      "SPDXID": "SPDXRef-Package-kubectl",
      "versionInfo": "v1.33.0",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseConcluded": "Apache-2.0",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    }
  ],
  "documentDescribes": ["SPDXRef-Package-kubectl"]
}`

func TestSPDX22Unserialize(t *testing.T) {
	doc, err := NewSPDX22().Unserialize(
		strings.NewReader(testJSON22Document), &native.UnserializeOptions{}, nil,
	)
	require.NoError(t, err)
	require.Equal(t, "json22-test-doc", doc.GetMetadata().GetName())
	require.Len(t, doc.GetNodeList().GetNodes(), 1)

	node := doc.GetNodeList().GetNodes()[0]
	require.Equal(t, "kubectl", node.GetName())
	require.Equal(t, "v1.33.0", node.GetVersion())
	require.Equal(t, "Apache-2.0", node.GetLicenseConcluded())
	require.Contains(t, doc.GetNodeList().GetRootElements(), node.GetId())
}

func TestSPDX22TVUnserialize(t *testing.T) {
	// The 2.3 test document with the version replaced parses through
	// the same shared conversion.
	tv := strings.Replace(testTagValueDocument, "SPDXVersion: SPDX-2.3", "SPDXVersion: SPDX-2.2", 1)

	doc, err := NewSPDX22TV().Unserialize(
		strings.NewReader(tv), &native.UnserializeOptions{}, nil,
	)
	require.NoError(t, err)
	require.Equal(t, "tv-test-doc", doc.GetMetadata().GetName())
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
	require.Equal(t, "bin/kubectl", fileNode.GetName())
}
