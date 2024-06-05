package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNodeListDiff(t *testing.T) {
	testNodeList := NodeList{
		Nodes: []*Node{
			{Id: "node1"}, {Id: "node2"}, {Id: "node3"},
		},
	}

	for _, tc := range []struct {
		name     string
		prepare  func(*NodeList, *NodeList)
		sut      *NodeList
		node     *NodeList
		expected *NodeListDiff
	}{
		{
			name: "add node with new id",
			prepare: func(sutNodeList *NodeList, newNodeList *NodeList) {
				newNodeList.Nodes = append(newNodeList.Nodes, &Node{
					Id: "added",
				})
			},
			sut:  &NodeList{},
			node: &NodeList{},
			expected: &NodeListDiff{
				Nodes: NodeSetDiff{
					Added: []*Node{
						{
							Id: "added",
						},
					},
				},
			},
		},
		{
			name: "remove node",
			prepare: func(sutNodeList *NodeList, newNodeList *NodeList) {
				tmpNodes := []*Node{}
				for i, node := range newNodeList.Nodes {
					if i > 0 {
						tmpNodes = append(tmpNodes, node.Copy())
					}
				}
				newNodeList.Nodes = tmpNodes
			},
			sut:  &NodeList{},
			node: &NodeList{},
			expected: &NodeListDiff{
				Nodes: NodeSetDiff{
					Removed: []*Node{
						{
							Id: "node1",
						},
					},
				},
			},
		},
		{
			name: "modified name",
			prepare: func(sutNodeList *NodeList, newNodeList *NodeList) {
				tmpNodes := newNodeList.Nodes
				for i, node := range tmpNodes {
					if i == 0 {
						node.Name = "modified"
					}
				}

				newNodeList.Nodes = tmpNodes
			},
			sut:  &NodeList{},
			node: &NodeList{},
			expected: &NodeListDiff{
				Nodes: NodeSetDiff{
					NodeDiff: []*NodeDiff{
						{
							Removed: &Node{},
							Added: &Node{
								Name: "modified",
							},
							DiffCount: 1,
						},
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.sut = testNodeList.Copy()
			tc.node = testNodeList.Copy()
			tc.prepare(tc.sut, tc.node)
			result := tc.sut.Diff(tc.node)
			if tc.expected == nil {
				require.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			compareNodeListDiff(t, tc.expected.Nodes, result.Nodes)
		})
	}
}

func TestNodeListDiffEdge(t *testing.T) {
	testNodeList := NodeList{
		Nodes: []*Node{
			{Id: "test1"},
			{Id: "test2"},
			{Id: "test3"},
			{Id: "test4"},
		},
		Edges: []*Edge{
			{From: "test1", Type: Edge_contains, To: []string{"test2", "test3"}},
			{From: "test3", Type: Edge_contains, To: []string{"test4"}},
		},
	}

	for _, tc := range []struct {
		name     string
		prepare  func(*NodeList, *NodeList)
		sut      *NodeList
		node     *NodeList
		expected *NodeListDiff
	}{
		{
			name: "add edge with new id",
			prepare: func(sutNodeList *NodeList, newNodeList *NodeList) {
				newNodeList.Edges = append(newNodeList.Edges, &Edge{
					From: "added",
					To:   []string{"test", "test2"},
				})
			},
			sut:  &NodeList{},
			node: &NodeList{},
			expected: &NodeListDiff{
				Edges: EdgeSetDiff{
					Added: []*Edge{
						{
							From: "added",
							To:   []string{"test", "test2"},
						},
					},
				},
			},
		},
		{
			name: "remove edge with new id",
			prepare: func(sutNodeList *NodeList, newNodeList *NodeList) {
				tmpNodes := []*Edge{}
				for i, edge := range newNodeList.Edges {
					if i > 0 {
						tmpNodes = append(tmpNodes, edge.Copy())
					}
				}
				newNodeList.Edges = tmpNodes
			},
			sut:  &NodeList{},
			node: &NodeList{},
			expected: &NodeListDiff{
				Edges: EdgeSetDiff{
					Removed: []*Edge{
						{
							From: "test1",
							Type: Edge_contains,
							To:   []string{"test2", "test3"},
						},
					},
				},
			},
		},
		{
			name: "remove from to",
			prepare: func(sutNodeList *NodeList, newNodeList *NodeList) {
				tmpNodes := []*Edge{}
				for i, edge := range newNodeList.Edges {
					if i == 0 {
						edge.To = []string{"test2"}
						tmpNodes = append(tmpNodes, edge.Copy())
					} else {
						tmpNodes = append(tmpNodes, edge.Copy())
					}
				}
				newNodeList.Edges = tmpNodes
			},
			sut:  &NodeList{},
			node: &NodeList{},
			expected: &NodeListDiff{
				Edges: EdgeSetDiff{
					Removed: []*Edge{
						{
							From: "test1",
							Type: Edge_contains,
							To:   []string{"test3"},
						},
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Tests start with a copy of the test node
			tc.sut = testNodeList.Copy()
			tc.node = testNodeList.Copy()

			// The prepare function modifies them for the test
			tc.prepare(tc.sut, tc.node)
			result := tc.sut.Diff(tc.node)
			if tc.expected == nil {
				require.Nil(t, result)
				return
			}
			require.NotNil(t, result)

			compareEdgesDiff(t, tc.expected.Edges, result.Edges)
		})
	}
}

func TestNodeListDiffRootElements(t *testing.T) {
	testNodeList := NodeList{
		RootElements: []string{"root1", "root2", "root3"},
	}

	for _, tc := range []struct {
		name     string
		prepare  func(*NodeList, *NodeList)
		sut      *NodeList
		node     *NodeList
		expected *NodeListDiff
	}{
		{
			name: "add root element",
			prepare: func(sutNodeList *NodeList, newNodeList *NodeList) {
				newNodeList.RootElements = append(newNodeList.RootElements, "added")
			},
			sut: &NodeList{},
			node: &NodeList{
				RootElements: []string{"root1", "root2", "root3"},
			},
			expected: &NodeListDiff{
				RootElements: RootElementsDiff{
					Added: []string{"added"},
				},
			},
		},
		{
			name: "remove root element",
			prepare: func(sutNodeList *NodeList, newNodeList *NodeList) {
				tmpRoots := []string{}
				for i, root := range newNodeList.RootElements {
					if i > 0 {
						tmpRoots = append(tmpRoots, root)
					}
				}
				newNodeList.RootElements = tmpRoots
			},
			sut: &NodeList{},
			node: &NodeList{
				RootElements: []string{"root1", "root2", "root3"},
			},
			expected: &NodeListDiff{
				RootElements: RootElementsDiff{
					Removed: []string{"root1"},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.sut = testNodeList.Copy()
			tc.node = testNodeList.Copy()
			tc.prepare(tc.sut, tc.node)
			result := tc.sut.Diff(tc.node)
			require.NotNil(t, result)

			compareNodeListRootElementDiff(t, tc.expected.RootElements, result.RootElements)
		})
	}
}

func TestFullNodeListDiff(t *testing.T) {
	testNodeList := NodeList{
		Nodes: []*Node{
			{Id: "node1", Name: "Node 1"},
			{Id: "node2", Name: "Node 2"},
			{Id: "node3", Name: "Node 3"},
		},
		Edges: []*Edge{
			{From: "node1", Type: Edge_contains, To: []string{"node2"}},
			{From: "node2", Type: Edge_dependsOn, To: []string{"node3"}},
		},
		RootElements: []string{"node1", "node2"},
	}

	for _, tc := range []struct {
		name     string
		prepare  func(*NodeList, *NodeList)
		sut      *NodeList
		node     *NodeList
		expected *NodeListDiff
	}{
		{
			name: "add node, edge, and root element",
			prepare: func(sutNodeList, newNodeList *NodeList) {
				newNodeList.Nodes = append(newNodeList.Nodes, &Node{Id: "node4", Name: "Node 4"})
				newNodeList.Edges = append(newNodeList.Edges, &Edge{From: "node3", Type: Edge_contains, To: []string{"node4"}})
				newNodeList.RootElements = append(newNodeList.RootElements, "node3")
			},
			sut: testNodeList.Copy(),
			node: &NodeList{
				Nodes:        []*Node{{Id: "node1", Name: "Node 1"}, {Id: "node2", Name: "Node 2"}, {Id: "node3", Name: "Node 3"}},
				Edges:        []*Edge{{From: "node1", Type: Edge_contains, To: []string{"node2"}}, {From: "node2", Type: Edge_dependsOn, To: []string{"node3"}}},
				RootElements: []string{"node1", "node2"},
			},
			expected: &NodeListDiff{
				Nodes: NodeSetDiff{
					Added: []*Node{{Id: "node4", Name: "Node 4"}},
				},
				Edges: EdgeSetDiff{
					Added: []*Edge{{From: "node3", Type: Edge_contains, To: []string{"node4"}}},
				},
				RootElements: RootElementsDiff{
					Added: []string{"node3"},
				},
			},
		},
		{
			name: "remove node, edge, and root element",
			prepare: func(sutNodeList, newNodeList *NodeList) {
			},
			sut: testNodeList.Copy(),
			node: &NodeList{
				Nodes:        []*Node{{Id: "node1", Name: "Node 1"}},
				Edges:        []*Edge{{From: "node1", Type: Edge_contains, To: []string{"node2"}}},
				RootElements: []string{"node1"},
			},
			expected: &NodeListDiff{
				Nodes: NodeSetDiff{
					Removed: []*Node{{Id: "node2", Name: "Node 2"}, {Id: "node3", Name: "Node 3"}},
				},
				Edges: EdgeSetDiff{
					Removed: []*Edge{{From: "node2", Type: Edge_dependsOn, To: []string{"node3"}}},
				},
				RootElements: RootElementsDiff{
					Removed: []string{"node2"},
				},
			},
		},
		{
			name: "modify node,edge and root element",
			prepare: func(sutNodeList, newNodeList *NodeList) {
			},
			sut: testNodeList.Copy(),
			node: &NodeList{
				Nodes:        []*Node{{Id: "node1", Name: "Modified Node 1"}, {Id: "node2", Name: "Node 2"}, {Id: "node3", Name: "Node 3"}},
				Edges:        []*Edge{{From: "node1", Type: Edge_dependsOn, To: []string{"node2"}}, {From: "node2", Type: Edge_dependsOn, To: []string{"node3"}}},
				RootElements: []string{"node3"},
			},
			expected: &NodeListDiff{
				Nodes: NodeSetDiff{
					NodeDiff: []*NodeDiff{
						{
							Removed:   &Node{},
							Added:     &Node{Name: "Modified Node 1"},
							DiffCount: 1,
						},
					},
				},
				Edges: EdgeSetDiff{
					Added: []*Edge{{From: "node1", Type: Edge_dependsOn, To: []string{"node2"}}},
				},
				RootElements: RootElementsDiff{
					Added:   []string{"node3"},
					Removed: []string{"node1", "node2"},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.prepare(tc.sut, tc.node)
			result := tc.sut.Diff(tc.node)
			if tc.expected == nil {
				require.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			compareDiff(t, tc.expected, &result)
		})
	}
}

func compareDiff(t *testing.T, expected, actual *NodeListDiff) {
	compareNodeListDiff(t, expected.Nodes, actual.Nodes)
	compareEdgesDiff(t, expected.Edges, actual.Edges)
	compareNodeListRootElementDiff(t, expected.RootElements, actual.RootElements)
}

func compareEdgesDiff(t *testing.T, expected, actual EdgeSetDiff) {
	compareEdgesDiffSlice(t, expected.Added, actual.Added, "added")
	compareEdgesDiffSlice(t, expected.Removed, actual.Removed, "removed")
}

func compareEdgesDiffSlice(t *testing.T, expected, actual []*Edge, action string) {
	for i, edge := range expected {
		require.GreaterOrEqual(t, len(actual), i+1, "expected edge %s but not found %s", action, edge.flatString())
		require.Equal(t, edge.flatString(), actual[i].flatString(), "edge mismatch for %s", action)
	}
}

func compareNodeListRootElementDiff(t *testing.T, expected, actual RootElementsDiff) {
	require.ElementsMatch(t, expected.Added, actual.Added, "expected root elements added but not found")
	require.ElementsMatch(t, expected.Removed, actual.Removed, "expected root elements removed but not found")
}

func compareNodeListDiff(t *testing.T, expected, actual NodeSetDiff) {
	for i, add := range expected.Added {
		require.GreaterOrEqual(t, len(actual.Added), i+1, "expected node added but not found %s", add.flatString())
		require.Equal(t, actual.Added[i].flatString(), add.flatString())
	}

	for i, rem := range expected.Removed {
		require.GreaterOrEqual(t, len(actual.Removed), i+1, "expected node removed but not found %s", rem.flatString())
		require.Equal(t, actual.Removed[i].flatString(), rem.flatString(), "node missmatch")
	}

	for i, diff := range expected.NodeDiff {
		require.GreaterOrEqual(t, len(actual.NodeDiff), i+1, "expected node diff but not found")
		require.Truef(t, actual.NodeDiff[i].Added.Equal(diff.Added), "comparing node diff added: %s %s", diff.Added.flatString(), actual.NodeDiff[i].Added)
		require.Truef(t, actual.NodeDiff[i].Removed.Equal(diff.Removed), "comparing  node diff removed: %s %s", diff.Removed.flatString(), actual.NodeDiff[i].Removed)
		require.Equal(t, actual.NodeDiff[i].DiffCount, diff.DiffCount)
	}
}
