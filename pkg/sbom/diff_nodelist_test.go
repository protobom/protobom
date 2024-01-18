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
				newNodeList.Nodes = append(newNodeList.Nodes, &Node{
					Id: "added",
				})
			},
			sut:  &NodeList{},
			node: &NodeList{},
			expected: &NodeListDiff{
				Added: []*Node{
					{
						Id: "added",
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
				Removed: []*Node{
					{
						Id: "node1",
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

			for i, add := range tc.expected.Added {
				require.GreaterOrEqual(t, len(result.Added), i+1, "expected added but not found", add.flatString())
				// if len(result.Added) > i {
				require.Equal(t, result.Added[i].flatString(), add.flatString())
				// }
			}
			for i, rem := range result.Removed {
				require.GreaterOrEqual(t, len(result.Removed), i+1, "expected removed but not found", rem.flatString())
				require.Equal(t, result.Removed[i].flatString(), rem.flatString())
			}
			// for i, diff := range result.NodeDiff {
			// 	require.GreaterOrEqual(t, len(result.NodeDiff), i+1, "expected Diff but not found")
			// require.Equal(t, result.Removed[i].flatString(), diff.flatString())
			// }

		})
	}
}
