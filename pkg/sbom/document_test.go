package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetRootNodes(t *testing.T) {
	for _, tc := range []struct {
		sut      *Document
		expected []*Node
	}{
		// ID and node type should never change
		{
			sut: &Document{
				Metadata:     &Metadata{},
				RootElements: []string{"node1", "node3"},
				Nodes: []*Node{
					{Id: "node1"}, {Id: "node2"}, {Id: "node3"},
				},
				Edges: []*Edge{},
			},

			expected: []*Node{{Id: "node1"}, {Id: "node3"}},
		},
		// Missing nodes are not returned
		{
			sut: &Document{
				Metadata:     &Metadata{},
				RootElements: []string{"node1", "node3"},
				Nodes: []*Node{
					{Id: "node1"}, {Id: "node2"},
				},
				Edges: []*Edge{},
			},

			expected: []*Node{{Id: "node1"}},
		},
	} {
		nodes := tc.sut.GetRootNodes()
		require.Equal(t, tc.expected, nodes)
	}
}
