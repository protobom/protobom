package sbom

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCleanEdges(t *testing.T) {
	for m, tc := range map[string]struct {
		sut      *NodeList
		expected *NodeList
	}{
		"Edge does not need to be modified": {
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
		"Edge contains a broken To": {
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
		"Edge contains a broken From": {
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
		"Duplicated edges should be consolidated": {
			sut: &NodeList{
				Nodes: []*Node{
					{Id: "node1"}, {Id: "node2"}, {Id: "node3"},
				},
				Edges: []*Edge{
					{Type: Edge_contains, From: "node1", To: []string{"node2"}},
					{Type: Edge_contains, From: "node1", To: []string{"node3"}},
				},
				RootElements: []string{"node1"},
			},

			expected: &NodeList{
				Nodes: []*Node{
					{Id: "node1"}, {Id: "node2"}, {Id: "node3"},
				},
				Edges: []*Edge{
					{Type: Edge_contains, From: "node1", To: []string{"node2", "node3"}},
				},
				RootElements: []string{"node1"},
			},
		},
	} {
		tc.sut.cleanEdges()
		require.True(t, tc.sut.Equal(tc.expected), m)
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

func TestNodeListIntersect(t *testing.T) {
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
				To:   []string{"node2", "node3"},
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
		newNodeList := tc.sut.Intersect(tc.isec)
		require.True(t, tc.expect.Equal(newNodeList), fmt.Sprintf("%s: %v %v", title, tc.expect, newNodeList))
	}
}

func TestNodeListUnion(t *testing.T) {
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
				To:   []string{"node2", "node3"},
			},
			{
				Type: Edge_dependsOn,
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
		"same nodelist unioned on itself, returns same nodelist": {
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
						To:   []string{"node2", "node3"},
					},
					{
						Type: Edge_dependsOn,
						From: "node1",
						To:   []string{"node3"},
					},
				},
				RootElements: []string{},
			},
		},
	} {
		newNodeList := tc.sut.Union(tc.isec)
		require.True(t, tc.expect.Equal(newNodeList), title)
	}
}

func TestGetNodesByName(t *testing.T) {
	for _, tc := range []struct {
		sut      *NodeList
		name     string
		expected []*Node
	}{
		{
			&NodeList{
				Nodes: []*Node{
					{Id: "node1", Name: "apache-tomcat"}, {Id: "node2", Name: "apache"},
				},
				Edges:        []*Edge{},
				RootElements: []string{},
			},
			"apache",
			[]*Node{
				{Id: "node2", Name: "apache"},
			},
		},
		{
			&NodeList{
				Nodes: []*Node{
					{Id: "nginx-arm64", Name: "nginx"},
					{Id: "nginx-arm64", Name: "nginx"},
					{Id: "nginx-libs", Name: "nginx-libs"},
					{Id: "nginx-docs", Name: "nginx-docs"},
				},
				Edges:        []*Edge{},
				RootElements: []string{},
			},
			"nginx",
			[]*Node{
				{Id: "nginx-arm64", Name: "nginx"}, {Id: "nginx-arm64", Name: "nginx"},
			},
		},
	} {
		res := tc.sut.GetNodesByName(tc.name)
		require.Equal(t, tc.expected, res)
	}
}

func TestGetNodeByID(t *testing.T) {
	for _, tc := range []struct {
		sut      *NodeList
		id       string
		expected *Node
	}{
		{
			&NodeList{
				Nodes: []*Node{
					{Id: "node1", Name: "apache-tomcat"}, {Id: "node2", Name: "apache"},
				},
				Edges:        []*Edge{},
				RootElements: []string{},
			},
			"node2",
			&Node{Id: "node2", Name: "apache"},
		},
		{
			&NodeList{
				Nodes: []*Node{
					{Id: "nginx-arm64", Name: "nginx"},
					{Id: "nginx-arm64", Name: "nginx"},
					{Id: "nginx-libs", Name: "nginx-libs"},
					{Id: "nginx-docs", Name: "nginx-docs"},
				},
				Edges:        []*Edge{},
				RootElements: []string{},
			},
			"nginx-libs",
			&Node{Id: "nginx-libs", Name: "nginx-libs"},
		},
	} {
		res := tc.sut.GetNodeByID(tc.id)
		require.Equal(t, tc.expected, res)
	}
}

func TestGetNodesByIdentifier(t *testing.T) {
	for _, tc := range []struct {
		sut        *NodeList
		identifier *Identifier
		expected   []*Node
	}{
		{
			&NodeList{
				Nodes: []*Node{
					{Id: "node1", Name: "apache-tomcat", Identifiers: []*Identifier{
						{Type: "purl", Value: "pkg:/apk/wolfi/bash@4.0.1"},
					}},
					{Id: "node2", Name: "apache"},
				},
				Edges:        []*Edge{},
				RootElements: []string{},
			},
			&Identifier{Type: "purl", Value: "pkg:/apk/wolfi/bash@4.0.1"},
			[]*Node{{Id: "node1", Name: "apache-tomcat", Identifiers: []*Identifier{
				{Type: "purl", Value: "pkg:/apk/wolfi/bash@4.0.1"},
			}}},
		},
		{
			&NodeList{
				Nodes: []*Node{
					{Id: "nginx-arm64", Name: "nginx"},
					{Id: "nginx-arm64", Name: "nginx", Identifiers: []*Identifier{
						{Type: "purl", Value: "pkg:/apk/wolfi/nginx@1.21.1"},
						{Type: "cpe", Value: "cpe:2.3:a:nginx:nginx:1.21.1:*:*:*:*:*:*:*"},
					}},
					{Id: "bash-4", Name: "bash", Identifiers: []*Identifier{
						{Type: "purl", Value: "pkg:/apk/wolfi/bash@4.0.1"},
						{Type: "cpe", Value: "cpe:2.3:a:bash:bash:5.0-4:*:*:*:*:*:*:*"},
					}},
					{Id: "nginx-docs", Name: "nginx-docs"},
				},
				Edges:        []*Edge{},
				RootElements: []string{},
			},
			&Identifier{Type: "cpe", Value: "cpe:2.3:a:nginx:nginx:1.21.1:*:*:*:*:*:*:*"},
			[]*Node{{Id: "nginx-arm64", Name: "nginx", Identifiers: []*Identifier{
				{Type: "purl", Value: "pkg:/apk/wolfi/nginx@1.21.1"},
				{Type: "cpe", Value: "cpe:2.3:a:nginx:nginx:1.21.1:*:*:*:*:*:*:*"},
			}}},
		},
	} {
		res := tc.sut.GetNodesByIdentifier(tc.identifier.Type, tc.identifier.Value)
		require.Equal(t, tc.expected, res)
	}
}

func TestEqual(t *testing.T) {
	getTestNodeList := func() *NodeList {
		return &NodeList{
			Nodes: []*Node{
				{Id: "nginx-arm64", Name: "nginx"},
				{Id: "nginx-amd64", Name: "nginx", Identifiers: []*Identifier{
					{Type: "purl", Value: "pkg:/apk/wolfi/nginx@1.21.1"},
					{Type: "cpe", Value: "cpe:2.3:a:nginx:nginx:1.21.1:*:*:*:*:*:*:*"},
				}},
				{Id: "bash-4", Name: "bash", Identifiers: []*Identifier{
					{Type: "purl", Value: "pkg:/apk/wolfi/bash@4.0.1"},
					{Type: "cpe", Value: "cpe:2.3:a:bash:bash:5.0-4:*:*:*:*:*:*:*"},
				}},
				{Id: "nginx-docs", Name: "nginx-docs"},
			},
			Edges: []*Edge{
				{
					Type: Edge_dependsOn,
					From: "nginx-amd64",
					To:   []string{"bash-4"},
				},
				{
					Type: Edge_dependsOn,
					From: "nginx-arm64",
					To:   []string{"bash-4"},
				},
			},
			RootElements: []string{"nginx-arm64", "nginx-amd64"},
		}
	}
	for msg, tc := range map[string]struct {
		sut1     *NodeList
		sut2     *NodeList
		shouldEq bool
		prepare  func(*NodeList, *NodeList)
	}{
		"same nodelist": {
			sut1:     getTestNodeList(),
			sut2:     getTestNodeList(),
			shouldEq: true,
			prepare:  func(*NodeList, *NodeList) {},
		},
		"change top level elements": {
			sut1:     getTestNodeList(),
			sut2:     getTestNodeList(),
			shouldEq: false,
			prepare: func(_ *NodeList, sut2 *NodeList) {
				sut2.RootElements = append(sut2.RootElements, "nginx-docs")
			},
		},
		"add an edge": {
			sut1:     getTestNodeList(),
			sut2:     getTestNodeList(),
			shouldEq: false,
			prepare: func(_ *NodeList, sut2 *NodeList) {
				sut2.Edges = append(sut2.Edges, &Edge{
					Type: Edge_documentation,
					From: "nginx-docs",
					To:   []string{"nginx-arm64", "nginx-amd64"},
				})
			},
		},
		"modify an edge": {
			sut1:     getTestNodeList(),
			sut2:     getTestNodeList(),
			shouldEq: false,
			prepare: func(_ *NodeList, sut2 *NodeList) {
				sut2.Edges[0].To = append(sut2.Edges[0].To, "nginx-docs")
			},
		},
		"add a node": {
			sut1:     getTestNodeList(),
			sut2:     getTestNodeList(),
			shouldEq: false,
			prepare: func(_ *NodeList, sut2 *NodeList) {
				sut2.Nodes = append(sut2.Nodes, &Node{
					Id:       "new-node",
					Type:     Node_FILE,
					Name:     "README",
					FileName: "README.md",
					Summary:  "Awesome readme",
				})
			},
		},
		"modify a node": {
			sut1:     getTestNodeList(),
			sut2:     getTestNodeList(),
			shouldEq: false,
			prepare: func(_ *NodeList, sut2 *NodeList) {
				sut2.Nodes[1].FileName = "package.tar"
			},
		},
	} {
		tc.prepare(tc.sut1, tc.sut2)
		res := tc.sut1.Equal(tc.sut2)
		require.Equal(t, tc.shouldEq, res, msg)
	}
}
