package serializers

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
)

// testTVDocument builds a protobom document with a package containing
// a file.
func testTVDocument(t *testing.T) *sbom.Document {
	t.Helper()
	doc := sbom.NewDocument()
	doc.Metadata.Id = "https://example.com/test/spdx23tv#SPDXRef-DOCUMENT"
	doc.Metadata.Name = "spdx23tv-test"
	doc.Metadata.Date = timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	pkg := &sbom.Node{
		Id:               "Package-nginx",
		Type:             sbom.Node_PACKAGE,
		Name:             "nginx",
		Version:          "1.25.3",
		LicenseConcluded: "Apache-2.0",
		Identifiers: map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:oci/nginx@1.25.3",
		},
		Hashes: map[int32]string{
			int32(sbom.HashAlgorithm_SHA256): "9f7fd60e5346e9b6b9e6dbc769ffca94a394a5253bb45a2cbca4fbe3f4d34a0f",
		},
	}
	doc.GetNodeList().AddRootNode(pkg)

	file := &sbom.Node{
		Id:   "File-nginx-conf",
		Type: sbom.Node_FILE,
		Name: "etc/nginx/nginx.conf",
		Hashes: map[int32]string{
			int32(sbom.HashAlgorithm_SHA256): "b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1",
		},
	}
	require.NoError(t, doc.GetNodeList().RelateNodeAtID(file, "Package-nginx", sbom.Edge_contains))
	return doc
}

func TestSPDX23TVRender(t *testing.T) {
	s := NewSPDX23TV()
	raw, err := s.Serialize(testTVDocument(t), &native.SerializeOptions{}, nil)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, s.Render(raw, &buf, &native.RenderOptions{}, nil))

	for _, expected := range []string{
		"SPDXVersion: SPDX-2.3",
		"DocumentNamespace: https://example.com/test/spdx23tv",
		"PackageName: nginx",
		"PackageVersion: 1.25.3",
		"ExternalRef: PACKAGE-MANAGER purl pkg:oci/nginx@1.25.3",
		"FileName: etc/nginx/nginx.conf",
	} {
		require.Contains(t, buf.String(), expected+"\n")
	}
}

func TestSPDX23TVRenderInvalidType(t *testing.T) {
	require.Error(t, NewSPDX23TV().Render(struct{}{}, &bytes.Buffer{}, &native.RenderOptions{}, nil))
}
