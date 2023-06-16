package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCleanEdges(t *testing.T) {
	for _, tc := range []struct {
		sut      *NodeList
		expected *NodeList
	}{
		// Edge does not need to be modified
		{
			sut: &NodeList{
				Nodes: []*Node{
					{Id: "node1"}, {Id: "node2"},
				},
				Edges: []*Edge{
					{Type: 0, From: "node1", To: []string{"node2"}},
				},
				RootElements: []string{"node1"},
			},

			expected: &NodeList{
				Nodes: []*Node{
					{Id: "node1"}, {Id: "node2"},
				},
				Edges: []*Edge{
					{Type: 0, From: "node1", To: []string{"node2"}},
				},
				RootElements: []string{"node1"},
			},
		},
		// Edge contains a broken To
		{
			sut: &NodeList{
				Nodes: []*Node{
					{Id: "node1"}, {Id: "node2"},
				},
				Edges: []*Edge{
					{Type: 0, From: "node1", To: []string{"node2", "node3"}},
				},
				RootElements: []string{"node1"},
			},
			expected: &NodeList{
				Nodes: []*Node{
					{Id: "node1"}, {Id: "node2"},
				},
				Edges: []*Edge{
					{Type: 0, From: "node1", To: []string{"node2"}},
				},
				RootElements: []string{"node1"},
			},
		},
		// Edge contains a broken From
		{
			sut: &NodeList{
				Nodes: []*Node{
					{Id: "node1"}, {Id: "node2"},
				},
				Edges: []*Edge{
					{Type: 0, From: "node3", To: []string{"node1"}},
				},
				RootElements: []string{"node1"},
			},
			expected: &NodeList{
				Nodes: []*Node{
					{Id: "node1"}, {Id: "node2"},
				},
				Edges:        []*Edge{},
				RootElements: []string{"node1"},
			},
		},
	} {
		tc.sut.cleanEdges()
		require.Equal(t, tc.sut, tc.expected)
	}
}

func TestRemoveNodes(t *testing.T) {
	for _, tc := range []struct {
		sut      *NodeList
		prep     func(*NodeList)
		expected *NodeList
	}{
		{
			// Two related edges. Remove the second
			sut: &NodeList{
				Nodes: []*Node{
					{Id: "node1"}, {Id: "node2"},
				},
				Edges: []*Edge{
					{
						Type: 0,
						From: "node1",
						To:   []string{"node2"},
					},
				},
				RootElements: []string{"node1"},
			},
			prep: func(nl *NodeList) {
				nl.RemoveNodes([]string{"node2"})
			},
			expected: &NodeList{
				Nodes: []*Node{
					{Id: "node1"},
				},
				Edges:        []*Edge{},
				RootElements: []string{"node1"},
			},
		},
	} {
		tc.prep(tc.sut)
		require.Equal(t, tc.sut, tc.expected)
	}
}
