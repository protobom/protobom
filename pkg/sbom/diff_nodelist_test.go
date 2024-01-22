package sbom

import (
	"encoding/json"
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
				newNodeList.Nodes = append(sutNodeList.Copy().Nodes, &Node{
					Id: "added",
				})
			},
			sut:  &NodeList{},
			node: &NodeList{},
			expected: &NodeListDiff{
				NodesDiff: NodeListDiffNodes{

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
				NodesDiff: NodeListDiffNodes{
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
				NodesDiff: NodeListDiffNodes{
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
			v, e := json.MarshalIndent(result, "", " ")
			t.Log(string(v), e)
			require.NotNil(t, result)

			for i, add := range tc.expected.NodesDiff.Added {
				require.GreaterOrEqual(t, len(result.NodesDiff.Added), i+1, "expected node added but not found %s", add.flatString())
				require.Equal(t, result.NodesDiff.Added[i].flatString(), add.flatString())
			}
			for i, rem := range tc.expected.NodesDiff.Removed {
				require.GreaterOrEqual(t, len(result.NodesDiff.Removed), i+1, "expected node removed but not found %s", rem.flatString())
				require.Equal(t, result.NodesDiff.Removed[i].flatString(), rem.flatString())
			}
			for i, diff := range tc.expected.NodesDiff.NodeDiff {
				require.GreaterOrEqual(t, len(result.NodesDiff.NodeDiff), i+1, "expected node diff but not found")
				require.Truef(t, result.NodesDiff.NodeDiff[i].Added.Equal(diff.Added), "comparing node diff added: %s %s", diff.Added.flatString(), result.NodesDiff.NodeDiff[i].Added)
				require.Truef(t, result.NodesDiff.NodeDiff[i].Removed.Equal(diff.Removed), "comparing  node diff removed: %s %s", diff.Removed.flatString(), result.NodesDiff.NodeDiff[i].Removed)
				require.Equal(t, result.NodesDiff.NodeDiff[i].DiffCount, diff.DiffCount)
			}

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
			{From: "test1", Type: Edge_contains, To: []string{"test2"}},
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
				EdgesDiff: NodeListDiffEdges{
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
				EdgesDiff: NodeListDiffEdges{
					Removed: []*Edge{
						{
							From: "test1",
							Type: Edge_contains,
							To:   []string{"test2"},
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
			v, e := json.MarshalIndent(result, "", " ")
			t.Log(string(v), e)
			require.NotNil(t, result)

			for i, add := range tc.expected.EdgesDiff.Added {
				require.GreaterOrEqual(t, len(result.EdgesDiff.Added), i+1, "expected edge added but not found %s", add.flatString())
				require.Equal(t, result.EdgesDiff.Added[i].flatString(), add.flatString())
			}
			for i, rem := range tc.expected.EdgesDiff.Removed {
				require.GreaterOrEqual(t, len(result.EdgesDiff.Removed), i+1, "expected edge removed but not found %s", rem.flatString())
				require.Equal(t, result.EdgesDiff.Removed[i].flatString(), rem.flatString())
			}

		})
	}
}
