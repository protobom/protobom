package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Union must return a NodeList detached from both inputs: later changes to
// either input must not show up in the result, and vice versa.
func TestNodeListUnionIsDetached(t *testing.T) {
	t.Parallel()

	// A root element list with spare capacity, as append leaves behind.
	roots := make([]string, 1, 4)
	roots[0] = "a"
	nl := &NodeList{Nodes: []*Node{{Id: "a", Name: "a"}}, RootElements: roots}
	nl2 := &NodeList{Nodes: []*Node{{Id: "b", Name: "b"}}, RootElements: []string{"b"}}

	ret := nl.Union(nl2)
	require.Equal(t, []string{"a", "b"}, ret.RootElements)

	// Appending to nl's roots must not write into the union's list.
	nl.AddRootNode(&Node{Id: "c"})
	require.Equal(t, []string{"a", "b"}, ret.RootElements)
	require.Equal(t, []string{"a", "c"}, nl.RootElements)

	// Nodes contributed by nl2 are copies, not the same pointers.
	b := ret.GetNodeByID("b")
	require.NotNil(t, b)
	require.NotSame(t, nl2.Nodes[0], b)
	nl2.Nodes[0].Name = "changed"
	require.Equal(t, "b", b.Name)

	// And nl's nodes were already copies.
	a := ret.GetNodeByID("a")
	require.NotSame(t, nl.Nodes[0], a)
}
