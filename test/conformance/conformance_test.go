package conformance

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/reader"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestUnserializeFormats(t *testing.T) {
	for _, format := range formats.List {
		files := findFiles(t, format)
		r := reader.New()
		for _, fname := range files {
			sut, err := r.ParseFile(fname)
			require.NoError(t, err)
			golden := readProtobom(t, fname+".proto")
			t.Logf("sut: %s golden: %s", fname, fname+".proto")
			t.Run(
				fmt.Sprintf("testNodes-%s-%s-%s", format.Type(), format.Version(), format.Encoding()),
				func(t *testing.T) {
					testNodes(t, golden, sut)
					testEqualNodeList(t, golden, sut)
					testEdges(t, golden, sut)
					testDocument(t, golden, sut)
				},
			)
		}
	}
}

func findFiles(t *testing.T, f formats.Format) []string {
	ret := []string{}
	dirName := filepath.Join("testdata", f.Type(), f.Version(), f.Encoding())
	files, err := os.ReadDir(dirName)
	if errors.Is(err, os.ErrNotExist) {
		return ret
	}
	require.NoError(t, err)
	for _, fsentry := range files {
		if strings.HasSuffix(fsentry.Name(), ".proto") {
			continue
		}
		ret = append(ret, filepath.Join(dirName, fsentry.Name()))
	}
	return ret
}

func testNodes(t *testing.T, golden, sut *sbom.Document) {
	require.Equal(t, len(golden.NodeList.Nodes), len(sut.NodeList.Nodes), "number of nodes")

	nl := golden.NodeList.Nodes
	nl2 := sut.NodeList.Nodes
	sort.Slice(nl[:], func(i, j int) bool {
		return strings.Compare(nl[i].String(), nl[j].String()) <= 0
	})
	sort.Slice(nl2[:], func(i, j int) bool {
		return strings.Compare(nl2[i].String(), nl2[j].String()) <= 0
	})

	nl2Index := 0
	for _, n := range nl {
		n2 := nl2[nl2Index]
		nodeDiff := n.Diff(n2)
		t.Logf("Source: %s", n.Id)
		t.Logf("Destination: %s", n.Id)

		if nodeDiff != nil && nodeDiff.Added != nil {
			t.Logf("Should have %s:", nodeDiff.Added.String())
		}

		if nodeDiff != nil && nodeDiff.Removed != nil {
			t.Logf("Missing %s", nodeDiff.Removed.String())
		}

		require.Nil(t, nodeDiff)
		nl2Index = nl2Index + 1
	}
}

func testEqualNodeList(t *testing.T, golden, sut *sbom.Document) {
	require.True(t, golden.NodeList.Equal(sut.NodeList), "equal nodelist", golden, sut)
}

func readProtobom(t *testing.T, path string) *sbom.Document {
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	bom := &sbom.Document{}
	if err := proto.Unmarshal(data, bom); err != nil {
		logrus.Fatal(fmt.Errorf("unmarshaling protobuf: %v", err))
	}
	return bom
}

func testEdges(t *testing.T, golden, sut *sbom.Document) {
	require.Equal(t, len(golden.NodeList.Edges), len(sut.NodeList.Edges), "number of nodes")
}

// TODO(puerco): Implement comparison methods in the document metadata
func testDocument(t *testing.T, golden, sut *sbom.Document) {
	require.Equal(t, golden.Metadata.Comment, sut.Metadata.Comment)
	require.Equal(t, golden.Metadata.Date, sut.Metadata.Date)
	require.Equal(t, golden.Metadata.Id, sut.Metadata.Id)
	require.Equal(t, golden.Metadata.DocumentTypes, sut.Metadata.DocumentTypes)
	require.Equal(t, golden.Metadata.Version, sut.Metadata.Version)
}
