package serializers

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spdx/tools-golang/spdx/v2/common"
	v2_2 "github.com/spdx/tools-golang/spdx/v2/v2_2"
	"github.com/stretchr/testify/require"

	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/native/unserializers"
	"github.com/protobom/protobom/pkg/sbom"
)

func TestSPDX22Serialize(t *testing.T) {
	s := NewSPDX22()
	raw, err := s.Serialize(testTVDocument(t), &native.SerializeOptions{}, nil)
	require.NoError(t, err)

	doc22, ok := raw.(*v2_2.Document)
	require.True(t, ok, "serialized document is not SPDX 2.2")
	require.Equal(t, v2_2.Version, doc22.SPDXVersion)

	require.Len(t, doc22.Packages, 1)
	pkg := doc22.Packages[0]
	require.Equal(t, "nginx", pkg.PackageName)
	require.Equal(t, "Apache-2.0", pkg.PackageLicenseConcluded)
	// Optional in 2.3, required in 2.2: backfilled on downgrade.
	require.Equal(t, "NOASSERTION", pkg.PackageLicenseDeclared)
	require.NotEmpty(t, pkg.PackageCopyrightText)

	require.Len(t, doc22.Files, 1)
	file := doc22.Files[0]
	require.Equal(t, "etc/nginx/nginx.conf", file.FileName)
	require.Equal(t, "NOASSERTION", file.LicenseConcluded)
	require.Equal(t, []string{"NOASSERTION"}, file.LicenseInfoInFiles)
	require.NotEmpty(t, file.FileCopyrightText)
}

func TestSPDX22RenderJSON(t *testing.T) {
	s := NewSPDX22()
	raw, err := s.Serialize(testTVDocument(t), &native.SerializeOptions{}, nil)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, s.Render(raw, &buf, &native.RenderOptions{Indent: 2}, nil))
	require.Contains(t, buf.String(), `"spdxVersion": "SPDX-2.2"`)
	require.Contains(t, buf.String(), `"name": "nginx"`)
}

func TestSPDX22TVRender(t *testing.T) {
	s := NewSPDX22TV()
	raw, err := s.Serialize(testTVDocument(t), &native.SerializeOptions{}, nil)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, s.Render(raw, &buf, &native.RenderOptions{}, nil))
	for _, expected := range []string{
		"SPDXVersion: SPDX-2.2",
		"PackageName: nginx",
		"PackageVersion: 1.25.3",
		"FileName: etc/nginx/nginx.conf",
	} {
		require.Contains(t, buf.String(), expected+"\n")
	}
}

// TestSPDX22TVRoundTrip writes a document as SPDX 2.2 tag-value and
// reads it back through the 2.2 unserializer.
func TestSPDX22TVRoundTrip(t *testing.T) {
	s := NewSPDX22TV()
	raw, err := s.Serialize(testTVDocument(t), &native.SerializeOptions{}, nil)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, s.Render(raw, &buf, &native.RenderOptions{}, nil))

	doc, err := unserializers.NewSPDX22TV().Unserialize(
		strings.NewReader(buf.String()), &native.UnserializeOptions{}, nil,
	)
	require.NoError(t, err)
	require.Len(t, doc.GetNodeList().GetNodes(), 2)

	var pkgNode *sbom.Node
	for _, n := range doc.GetNodeList().GetNodes() {
		if n.GetType() == sbom.Node_PACKAGE {
			pkgNode = n
		}
	}
	require.NotNil(t, pkgNode)
	require.Equal(t, "nginx", pkgNode.GetName())
	require.Equal(t, "1.25.3", pkgNode.GetVersion())
}

func TestDowngradeDocument(t *testing.T) {
	doc := &v2_2.Document{
		Packages: []*v2_2.Package{{
			PackageName: "test",
			PackageChecksums: []common.Checksum{
				{Algorithm: common.SHA256, Value: "aa"},
				{Algorithm: common.BLAKE3, Value: "bb"},
				{Algorithm: common.SHA3_256, Value: "cc"},
			},
		}},
		Files: []*v2_2.File{{
			FileName: "test.txt",
			Checksums: []common.Checksum{
				{Algorithm: common.SHA1, Value: "dd"},
				{Algorithm: common.ADLER32, Value: "ee"},
			},
		}},
	}
	downgradeDocument(doc)

	// Algorithms 2.3 introduced are dropped, 2.2 ones are kept.
	require.Equal(t,
		[]common.Checksum{{Algorithm: common.SHA256, Value: "aa"}},
		doc.Packages[0].PackageChecksums,
	)
	require.Equal(t,
		[]common.Checksum{{Algorithm: common.SHA1, Value: "dd"}},
		doc.Files[0].Checksums,
	)

	// Fields required in 2.2 are backfilled.
	require.Equal(t, "NOASSERTION", doc.Packages[0].PackageDownloadLocation)
	require.Equal(t, "NOASSERTION", doc.Packages[0].PackageLicenseConcluded)
	require.Equal(t, "NOASSERTION", doc.Packages[0].PackageLicenseDeclared)
	require.Equal(t, "NOASSERTION", doc.Packages[0].PackageCopyrightText)
	require.Equal(t, "NOASSERTION", doc.Files[0].LicenseConcluded)
	require.Equal(t, []string{"NOASSERTION"}, doc.Files[0].LicenseInfoInFiles)
	require.Equal(t, "NOASSERTION", doc.Files[0].FileCopyrightText)
}
