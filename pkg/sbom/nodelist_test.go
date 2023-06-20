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

func TestAdd(t *testing.T) {
	for _, tc := range []struct {
		sut     *NodeList
		prepare func(*NodeList)
		expect  *NodeList
	}{
		// Adding an empty nodelist is effectively as noop
		{
			sut: &NodeList{
				Nodes: []*Node{
					{Id: "test1"},
					{Id: "test2"},
				},
				Edges: []*Edge{
					{From: "test1", Type: Edge_contains, To: []string{"test2"}},
				},
			},
			prepare: func(n *NodeList) {
				n.Add(&NodeList{})
			},
			expect: &NodeList{
				Nodes: []*Node{
					{Id: "test1"},
					{Id: "test2"},
				},
				Edges: []*Edge{
					{From: "test1", Type: Edge_contains, To: []string{"test2"}},
				},
			},
		},
		// Add one node, no relationship
		{
			sut: &NodeList{
				Nodes: []*Node{
					{Id: "test1"},
					{Id: "test2"},
				},
				Edges: []*Edge{
					{From: "test1", Type: Edge_contains, To: []string{"test2"}},
				},
			},
			prepare: func(n *NodeList) {
				n.Add(&NodeList{
					Nodes: []*Node{
						{Id: "test3"},
					},
					Edges: []*Edge{},
				})
			},
			expect: &NodeList{
				Nodes: []*Node{
					{Id: "test1"},
					{Id: "test2"},
					{Id: "test3"},
				},
				Edges: []*Edge{
					{From: "test1", Type: Edge_contains, To: []string{"test2"}},
				},
			},
		},
	} {
		tc.prepare(tc.sut)
		require.Equal(t, tc.sut, tc.expect)
	}
}

func TestIntersect(t *testing.T) {
	testNodeList := &NodeList{
		Nodes: []*Node{
			{
				Id:      "node1",
				Type:    Node_PACKAGE,
				Name:    "package1",
				Version: "1.0.0",
			},

			{
				Id:      "node2",
				Type:    Node_PACKAGE,
				Name:    "package1",
				Version: "1.0.0",
			},
			{
				Id:      "node3",
				Type:    Node_PACKAGE,
				Name:    "package1",
				Version: "1.0.0",
			},
		},
		Edges: []*Edge{
			{
				Type: Edge_contains,
				From: "node1",
				To:   []string{"node2"},
			},
			{
				Type: Edge_contains,
				From: "node1",
				To:   []string{"node3"},
			},
		},
		RootElements: []string{},
	}

	testNodeList2 := &NodeList{
		Nodes: []*Node{
			{
				Id:      "node1",
				Type:    Node_PACKAGE,
				Name:    "package2",
				Version: "2.0.0",
			},
			{
				Id:      "node2",
				Type:    Node_PACKAGE,
				Name:    "package1",
				Version: "1.0.0",
			},
		},
		Edges:        []*Edge{},
		RootElements: []string{},
	}

	for title, tc := range map[string]struct {
		sut    *NodeList
		isec   *NodeList
		expect *NodeList
	}{
		"same nodelist intersected, returns same nodelist": {
			sut:    testNodeList,
			isec:   testNodeList,
			expect: testNodeList,
		},
		"combined nodes": {
			sut:  testNodeList,
			isec: testNodeList2,
			expect: &NodeList{
				Nodes: []*Node{
					{
						Id:      "node1",
						Type:    Node_PACKAGE,
						Name:    "package2",
						Version: "2.0.0",
					},
					{
						Id:      "node2",
						Type:    Node_PACKAGE,
						Name:    "package1",
						Version: "1.0.0",
					},
				},
				Edges: []*Edge{{
					Type: Edge_contains,
					From: "node1",
					To:   []string{"node2"},
				}},
				RootElements: []string{},
			},
		},
	} {
		new := tc.sut.Intersect(tc.isec)
		require.Equal(t, tc.expect, new, title)
	}

}
