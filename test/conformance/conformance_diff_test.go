package conformance

import (
	"bufio"
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/bom-squad/protobom/pkg/formats"
	"github.com/bom-squad/protobom/pkg/reader"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

type fakeBuf struct {
	*bufio.ReadWriter
}

func (fwc *fakeBuf) Close() error {
	return nil
}

func (f *fakeBuf) Seek(offset int64, whence int) (int64, error) {
	return 0, nil
}

func TestDiffTranslationFormats(t *testing.T) {
	from := formats.SPDX23JSON
	to := formats.CDX14JSON

	fromFiles := findFiles(t, from)
	require.NotEqual(t, len(fromFiles), 0)

	fname := fromFiles[0]

	r := reader.New()
	fromSut, err := r.ParseFile(fname)

	require.NoError(t, err)
	w := writer.New()

	var b bytes.Buffer
	fakeWriter := bufio.NewWriter(&b)
	fakeReader := bufio.NewReader(&b)
	fakeReadWriter := bufio.NewReadWriter(fakeReader, fakeWriter)

	fake := fakeBuf{
		ReadWriter: fakeReadWriter,
	}

	w.WriteStreamWithOptions(
		fromSut, &fake, &writer.Options{Format: to},
	)
	toSut, err := r.ParseStreamWithOptions(&fake, &reader.Options{Format: to})
	require.NoError(t, err)

	golden := readProtobom(t, fname+".proto")
	t.Logf("to-sut: %s golden: %s", fname, fname+".proto")
	t.Run(
		fmt.Sprintf("From: testDiffNodes-%s-%s-%s-TO-%s-%s-%s", from.Type(), from.Version(), from.Encoding(), to.Type(), to.Version(), to.Encoding()),
		func(t *testing.T) {
			testNodes(t, golden, toSut)
			testDiffNodeList(t, golden, toSut)
			testEdges(t, golden, toSut)
			testDocumentDiff(t, golden, toSut)
		},
	)
}

func testDiffNodeList(t *testing.T, golden, sut *sbom.Document) {
	// Compare the nodes
	nl := golden.NodeList
	nl2 := sut.NodeList

	if len(nl.Edges) != len(nl2.Edges) {
		require.Equal(t, len(nl.Edges), len(nl2.Edges), "edges amount differs")
	}

	if len(nl.Nodes) != len(nl2.Nodes) {
		require.Equal(t, len(nl.Nodes), len(nl2.Nodes), "node amount differs")
	}

	if len(nl.RootElements) != len(nl2.RootElements) {
		require.Equal(t, len(nl.RootElements), len(nl2.RootElements), "root amount differs")
	}

	r1 := nl.RootElements
	r2 := nl2.RootElements
	sort.Strings(r1)
	sort.Strings(r2)
	require.True(t, reflect.DeepEqual(r1, r2), "roots are not equal") //2DO expand this for more details.

	// Compare the flattenned edges
	// nlEdges := []string{}
	// for _, e := range nl.Edges {
	// 	nlEdges = append(nlEdges, e.flatString())
	// }
	// sort.Strings(nlEdges)

	// nl2Edges := []string{}
	// for _, e := range nl2.Edges {
	// 	nl2Edges = append(nl2Edges, e.flatString())
	// }
	// sort.Strings(nl2Edges)
	// require.True(t, reflect.DeepEqual(nlEdges, nl2Edges), "edges are not equal") //2DO expand this for more details.

	nlNodes := map[string]string{}
	nl2Nodes := map[string]string{}
	for _, n := range nl.Nodes {
		nlNodes[n.Id] = n.Checksum()
	}

	for _, n := range nl2.Nodes {
		nl2Nodes[n.Id] = n.Checksum()
	}

	require.True(t, cmp.Equal(nlNodes, nl2Nodes), "nodes are not equal") //2DO expand this for more details.

}

func testDocumentDiff(t *testing.T, golden, sut *sbom.Document) {
	require.Equal(t, golden.Metadata.Comment, sut.Metadata.Comment)
	// require.Equal(t, golden.Metadata.Date, sut.Metadata.Date)
	require.Equal(t, golden.Metadata.Id, sut.Metadata.Id)
	require.Equal(t, golden.Metadata.DocumentTypes, sut.Metadata.DocumentTypes)
	require.Equal(t, golden.Metadata.Version, sut.Metadata.Version)
}
