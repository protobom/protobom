package sbom

import (
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
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
		sut      *NodeList
		expected []*Node
		idType   string
		idValue  string
	}{
		{
			&NodeList{
				Nodes: []*Node{
					{
						Id:          "node1",
						Name:        "apache-tomcat",
						Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:/apk/wolfi/bash@4.0.1"},
					},
					{Id: "node2", Name: "apache"},
				},
				Edges:        []*Edge{},
				RootElements: []string{},
			},
			[]*Node{
				{Id: "node1", Name: "apache-tomcat", Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:/apk/wolfi/bash@4.0.1"}},
			},
			"purl", "pkg:/apk/wolfi/bash@4.0.1",
		},
		{
			&NodeList{
				Nodes: []*Node{
					{Id: "nginx-arm64", Name: "nginx"},
					{Id: "nginx-arm64", Name: "nginx", Identifiers: map[int32]string{
						int32(SoftwareIdentifierType_PURL):  "pkg:/apk/wolfi/nginx@1.21.1",
						int32(SoftwareIdentifierType_CPE23): "cpe:2.3:a:nginx:nginx:1.21.1:*:*:*:*:*:*:*",
					}},
					{Id: "bash-4", Name: "bash", Identifiers: map[int32]string{
						int32(SoftwareIdentifierType_PURL):  "pkg:/apk/wolfi/bash@4.0.1",
						int32(SoftwareIdentifierType_CPE23): "cpe:2.3:a:bash:bash:5.0-4:*:*:*:*:*:*:*",
					}},
					{Id: "nginx-docs", Name: "nginx-docs"},
				},
				Edges:        []*Edge{},
				RootElements: []string{},
			},
			[]*Node{{Id: "nginx-arm64", Name: "nginx", Identifiers: map[int32]string{
				int32(SoftwareIdentifierType_PURL):  "pkg:/apk/wolfi/nginx@1.21.1",
				int32(SoftwareIdentifierType_CPE23): "cpe:2.3:a:nginx:nginx:1.21.1:*:*:*:*:*:*:*",
			}}},
			"cpe23", "cpe:2.3:a:nginx:nginx:1.21.1:*:*:*:*:*:*:*",
		},
	} {
		res := tc.sut.GetNodesByIdentifier(tc.idType, tc.idValue)
		require.Equal(t, tc.expected, res)
	}
}

func TestEqual(t *testing.T) {
	getTestNodeList := func() *NodeList {
		return &NodeList{
			Nodes: []*Node{
				{Id: "nginx-arm64", Name: "nginx"},
				{Id: "nginx-amd64", Name: "nginx", Identifiers: map[int32]string{
					int32(SoftwareIdentifierType_PURL):  "pkg:/apk/wolfi/nginx@1.21.1",
					int32(SoftwareIdentifierType_CPE23): "cpe:2.3:a:nginx:nginx:1.21.1:*:*:*:*:*:*:*",
				}},
				{Id: "bash-4", Name: "bash", Identifiers: map[int32]string{
					int32(SoftwareIdentifierType_PURL):  "pkg:/apk/wolfi/bash@4.0.1",
					int32(SoftwareIdentifierType_CPE23): "cpe:2.3:a:bash:bash:5.0-4:*:*:*:*:*:*:*",
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

func TestIndexByHash(t *testing.T) {
	for label, tc := range map[string]struct {
		sut            *NodeList
		expected       hashIndex
		expectedLength int
		mustEqual      bool
	}{
		"1 node, no hashes": {
			sut: &NodeList{
				Nodes: []*Node{
					{Id: "nginx-arm64", Name: "nginx"},
				},
			},
			expected:       hashIndex{},
			expectedLength: 0,
			mustEqual:      true,
		},
		"1 node, with hashes": {
			sut: &NodeList{
				Nodes: []*Node{
					{Id: "nginx-amd64", Name: "nginx", Hashes: map[int32]string{
						int32(HashAlgorithm_SHA1):   "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1",
						int32(HashAlgorithm_SHA256): "e3fc9093ffd6eb531055f8f3bde275e7e9e8ab1884589c195d5f78d0a9b3d2b3",
					}},
				},
			},
			expected:       hashIndex{},
			expectedLength: 2,
			mustEqual:      true,
		},
		"2 node, with hashes": {
			sut: &NodeList{
				Nodes: []*Node{
					{Id: "nginx-amd64", Name: "nginx", Hashes: map[int32]string{
						int32(HashAlgorithm_SHA1):   "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1",
						int32(HashAlgorithm_SHA256): "e3fc9093ffd6eb531055f8f3bde275e7e9e8ab1884589c195d5f78d0a9b3d2b3",
					}},
					{Id: "nginx-arm64", Name: "nginx", Hashes: map[int32]string{
						int32(HashAlgorithm_SHA1):   "7df059597099bb7dcf25d2a9aedfaf4465f72d8d",
						int32(HashAlgorithm_SHA256): "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
					}},
				},
			},
			expected:       hashIndex{},
			expectedLength: 4,
			mustEqual:      true,
		},
		"2 nodes, shared hashes": {
			sut: &NodeList{
				Nodes: []*Node{
					{Id: "nginx-amd64", Name: "nginx", Hashes: map[int32]string{
						int32(HashAlgorithm_SHA1):   "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1",
						int32(HashAlgorithm_SHA256): "e3fc9093ffd6eb531055f8f3bde275e7e9e8ab1884589c195d5f78d0a9b3d2b3",
					}},
					{Id: "nginx-arm64", Name: "nginx", Hashes: map[int32]string{
						int32(HashAlgorithm_SHA1):   "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1",
						int32(HashAlgorithm_SHA256): "e3fc9093ffd6eb531055f8f3bde275e7e9e8ab1884589c195d5f78d0a9b3d2b3",
					}},
				},
			},
			expected:       hashIndex{},
			expectedLength: 2,
			mustEqual:      true,
		},
	} {
		res := tc.sut.indexNodesByHash()
		require.Equal(t, tc.expectedLength, len(res), label)
		// TODO(puerco): CHheck deeper into result
	}
}

func TestIndexByPurl(t *testing.T) {
	for label, tc := range map[string]struct {
		sut            *NodeList
		expected       purlIndex
		expectedLength int
		mustEqual      bool
	}{
		"1 node, no purl": {
			sut: &NodeList{
				Nodes: []*Node{{Id: "nginx-arm64", Name: "nginx"}},
			},
			expected:       purlIndex{},
			expectedLength: 0,
			mustEqual:      true,
		},
		"1 node, one purl": {
			sut: &NodeList{
				Nodes: []*Node{
					{
						Id:          "nginx-arm64",
						Name:        "nginx",
						Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:apk/wolfi/glibc@2.38-r1?arch=x86_64"},
					},
				},
			},
			expected:       purlIndex{},
			expectedLength: 1,
			mustEqual:      true,
		},
		"2 nodes, two purls": {
			sut: &NodeList{
				Nodes: []*Node{
					{
						Id: "nginx-arm64", Name: "nginx",
						Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:apk/wolfi/glibc@2.38-r1?arch=arm64"},
					},
					{
						Id: "nginx-amd64", Name: "nginx",
						Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:apk/wolfi/glibc@2.38-r1?arch=x86_64"},
					},
				},
			},
			expected:       purlIndex{},
			expectedLength: 2,
			mustEqual:      true,
		},
		"2 nodes, shared purl": {
			sut: &NodeList{
				Nodes: []*Node{
					{
						Id: "nginx-arm64", Name: "nginx",
						Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:apk/wolfi/glibc@2.38-r1"},
					},
					{
						Id: "nginx-amd64", Name: "nginx",
						Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:apk/wolfi/glibc@2.38-r1"},
					},
				},
			},
			expected:       purlIndex{},
			expectedLength: 1,
			mustEqual:      true,
		},
	} {
		res := tc.sut.indexNodesByPurl()
		require.Equal(t, tc.expectedLength, len(res), label)
		// TODO(puerco): CHheck deeper into result
	}
}

func TestGetMatchingNode(t *testing.T) {
	for label, tc := range map[string]struct {
		sut         *NodeList
		node        *Node
		exptectedId string
		shouldNil   bool
		shouldError bool
	}{
		"single hash": {
			sut: &NodeList{
				Nodes: []*Node{
					{Id: "node1", Hashes: map[int32]string{int32(HashAlgorithm_SHA1): "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1"}},
					{Id: "node2", Hashes: map[int32]string{int32(HashAlgorithm_SHA1): "4c219efaf4d39295971409f796301a89a304cee6"}},
				},
			},
			node:        &Node{Hashes: map[int32]string{int32(HashAlgorithm_SHA1): "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1"}},
			exptectedId: "node1",
		},
		"two matches": {
			sut: &NodeList{
				Nodes: []*Node{
					{Id: "node1", Hashes: map[int32]string{int32(HashAlgorithm_SHA1): "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1"}},
					{Id: "node2", Hashes: map[int32]string{int32(HashAlgorithm_SHA1): "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1"}},
				},
			},
			node:        &Node{Hashes: map[int32]string{int32(HashAlgorithm_SHA1): "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1"}},
			shouldError: true,
		},
		"two hashes, one matches, one doesnt": {
			sut: &NodeList{
				Nodes: []*Node{
					{
						Id: "node1", Hashes: map[int32]string{
							int32(HashAlgorithm_SHA1):   "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1",
							int32(HashAlgorithm_SHA256): "e63a4879428aad2c768954d7be753fde3997771b2ce45bc7f99c35ff00d2a98b",
						},
					},
				},
			},
			node: &Node{
				Hashes: map[int32]string{
					int32(HashAlgorithm_SHA1):   "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1",
					int32(HashAlgorithm_SHA256): "no-match-here",
				},
			},
			shouldError: false,
			shouldNil:   true,
		},
		"two hashes, three on the nodelist": {
			sut: &NodeList{
				Nodes: []*Node{
					{
						Id: "node1", Hashes: map[int32]string{
							int32(HashAlgorithm_SHA1):   "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1",
							int32(HashAlgorithm_SHA256): "e63a4879428aad2c768954d7be753fde3997771b2ce45bc7f99c35ff00d2a98b",
							int32(HashAlgorithm_SHA512): "012d52b1ab7abc4b8e98d6767ef6465f63259116f23f954b404ac356425d8488086e1483846fc755750f8bceae54d8c838f843753353d6709c3eaf85c1377cce",
						},
					},
				},
			},
			node: &Node{
				Hashes: map[int32]string{
					int32(HashAlgorithm_SHA1):   "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1",
					int32(HashAlgorithm_SHA256): "e63a4879428aad2c768954d7be753fde3997771b2ce45bc7f99c35ff00d2a98b",
				},
			},
			exptectedId: "node1",
		},
		"two hashes, both match": {
			sut: &NodeList{
				Nodes: []*Node{
					{
						Id: "node1", Hashes: map[int32]string{
							int32(HashAlgorithm_SHA1):   "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1",
							int32(HashAlgorithm_SHA256): "e63a4879428aad2c768954d7be753fde3997771b2ce45bc7f99c35ff00d2a98b",
						},
					},
				},
			},
			node: &Node{
				Hashes: map[int32]string{
					int32(HashAlgorithm_SHA1):   "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1",
					int32(HashAlgorithm_SHA256): "e63a4879428aad2c768954d7be753fde3997771b2ce45bc7f99c35ff00d2a98b",
				},
			},
			exptectedId: "node1",
		},
		"two shared matches, match on purl": {
			sut: &NodeList{
				Nodes: []*Node{
					{
						Id:          "node1",
						Hashes:      map[int32]string{int32(HashAlgorithm_SHA1): "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1"},
						Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:/apk/alpine/bash@4.0.1"},
					},
					{
						Id:          "node2",
						Hashes:      map[int32]string{int32(HashAlgorithm_SHA1): "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1"},
						Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:/apk/wolfi/bash@4.0.1"},
					},
				},
			},
			node: &Node{
				Hashes:      map[int32]string{int32(HashAlgorithm_SHA1): "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1"},
				Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:/apk/wolfi/bash@4.0.1"},
			},
			exptectedId: "node2",
			shouldError: false,
		},
		"purls. no hashes": {
			sut: &NodeList{
				Nodes: []*Node{
					{
						Id:          "node1",
						Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:/apk/alpine/bash@4.0.1"},
					},
					{
						Id:          "node2",
						Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:/apk/wolfi/bash@4.0.1"},
					},
				},
			},
			node: &Node{
				Hashes:      map[int32]string{int32(HashAlgorithm_SHA1): "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1"},
				Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:/apk/wolfi/bash@4.0.1"},
			},
			exptectedId: "node2",
		},
		/* this one needs to be implemented
		"rearranged purls should match": {
			sut: &NodeList{
				Nodes: []*Node{
					{
						Id: "node1",
						Identifiers: []*Identifier{
							{
								Type:  "purl",
								Value: "pkg:deb/libzstd1@1.3.8+dfsg-3+deb10u2?arch=amd64&upstream=libzstd",
							},
						},
					},
				},
			},
			node: &Node{
				Hashes: map[string]string{"sha1": "0b13c24e584ef7075f3d4fd3a9f8872c9fffa1b1"},
				Identifiers: []*Identifier{
					{
						Type:  "purl",
						Value: "pkg:deb/libzstd1@1.3.8+dfsg-3+deb10u2?upstream=libzstd&arch=amd64",
					},
				},
			},
			exptectedId: "node1",
		},
		*/
	} {
		res, err := tc.sut.GetMatchingNode(tc.node)
		if tc.shouldError {
			require.Error(t, err, label)
			continue
		}

		if tc.shouldNil {
			require.Nil(t, res, label)
			continue
		} else {
			require.NotNil(t, res, label)
		}
		require.Equal(t, tc.exptectedId, res.Id, label)
	}
}

func TestNodeSiblings(t *testing.T) {
	rootNode := "testRootNode"
	for _, tc := range []struct {
		testName string
		sut      *NodeList
		expected *NodeList
	}{
		{
			testName: "simple_root",
			sut: &NodeList{
				Nodes: []*Node{
					{Id: rootNode}, {Id: "a-a"}, {Id: "a-b"},
				},
				Edges: []*Edge{
					{From: rootNode, To: []string{"a-a", "a-b"}},
				},
				RootElements: []string{rootNode},
			},
			expected: &NodeList{
				Nodes: []*Node{
					{Id: rootNode}, {Id: "a-a"}, {Id: "a-b"},
				},
				Edges: []*Edge{
					{From: rootNode, To: []string{"a-a", "a-b"}},
				},
				RootElements: []string{rootNode},
			},
		},
		{
			testName: "two_roots",
			sut: &NodeList{
				Nodes: []*Node{
					{Id: rootNode}, {Id: "b"}, {Id: "a-a"}, {Id: "a-b"}, {Id: "b-c"},
				},
				Edges: []*Edge{
					{From: rootNode, To: []string{"a-a", "a-b"}},
					{From: "b", To: []string{"b-c"}},
				},
				RootElements: []string{rootNode, "b"},
			},
			expected: &NodeList{
				Nodes: []*Node{
					{Id: rootNode}, {Id: "a-a"}, {Id: "a-b"},
				},
				Edges: []*Edge{
					{From: rootNode, To: []string{"a-a", "a-b"}},
				},
				RootElements: []string{rootNode},
			},
		},
		{
			testName: "two_roots_linked",
			sut: &NodeList{
				Nodes: []*Node{
					{Id: rootNode}, {Id: "b"}, {Id: "a-a"}, {Id: "a-b"},
				},
				Edges: []*Edge{
					{From: rootNode, To: []string{"b", "a-a", "a-b"}},
				},
				RootElements: []string{rootNode, "b"},
			},
			expected: &NodeList{
				Nodes: []*Node{
					{Id: rootNode}, {Id: "b"}, {Id: "a-a"}, {Id: "a-b"},
				},
				Edges: []*Edge{
					{From: rootNode, To: []string{"b", "a-a", "a-b"}},
				},
				RootElements: []string{rootNode},
			},
		},
		{
			testName: "two_roots_more_descendants",
			sut: &NodeList{
				Nodes: []*Node{
					{Id: rootNode}, {Id: "b"}, {Id: "a-a"}, {Id: "a-b"}, {Id: "a-b-c"},
				},
				Edges: []*Edge{
					{From: rootNode, To: []string{"a-a", "a-b"}},
					{From: "a-b", To: []string{"a-b-c"}},
				},
				RootElements: []string{rootNode, "b"},
			},
			expected: &NodeList{
				Nodes: []*Node{
					{Id: rootNode}, {Id: "a-a"}, {Id: "a-b"},
				},
				Edges: []*Edge{
					{From: rootNode, To: []string{"a-a", "a-b"}},
				},
				RootElements: []string{rootNode},
			},
		},
	} {
		t.Run(tc.testName, func(t *testing.T) {
			result := tc.sut.NodeSiblings(rootNode)
			require.Truef(t, result.Equal(tc.expected), "%s:\n\n%s\n\n%s", tc.testName, result, tc.expected)
		})
	}
}

func TestNodeGraph(t *testing.T) {
	root := "testRootNode"
	for _, tc := range []struct {
		testName string
		id       string
		sut      *NodeList
		expected *NodeList
	}{
		{
			// One root. Returns same
			// root
			//   |- a-a
			//   \- a-b
			//
			testName: "simple",
			id:       root,
			sut: &NodeList{
				Nodes: []*Node{
					{Id: root}, {Id: "a-a"}, {Id: "a-b"},
				},
				Edges: []*Edge{
					{From: root, To: []string{"a-a", "a-b"}},
				},
				RootElements: []string{root},
			},
			expected: &NodeList{
				Nodes: []*Node{
					{Id: root}, {Id: "a-a"}, {Id: "a-b"},
				},
				Edges: []*Edge{
					{From: root, To: []string{"a-a", "a-b"}},
				},
				RootElements: []string{root},
			},
		},
		{
			// One root. Index the end of the leaf
			// root
			//   |- a-a
			//   \- a-b
			//
			testName: "simple_idx_finish",
			id:       "a-a",
			sut: &NodeList{
				Nodes: []*Node{
					{Id: root}, {Id: "a-a"}, {Id: "a-b"},
				},
				Edges: []*Edge{
					{From: root, To: []string{"a-a", "a-b"}},
				},
				RootElements: []string{root},
			},
			expected: &NodeList{
				Nodes:        []*Node{{Id: "a-a"}},
				Edges:        []*Edge{},
				RootElements: []string{"a-a"},
			},
		},
		{
			// One root. Ancestor descendant, index at middle
			// root
			//   \- middle
			//       \- end
			//
			testName: "mid-tree",
			id:       "middle",
			sut: &NodeList{
				Nodes: []*Node{
					{Id: root}, {Id: "middle"}, {Id: "end"},
				},
				Edges: []*Edge{
					{From: root, To: []string{"middle"}},
					{From: "middle", To: []string{"end"}},
				},
				RootElements: []string{root},
			},
			expected: &NodeList{
				Nodes: []*Node{
					{Id: "middle"}, {Id: "end"},
				},
				Edges: []*Edge{
					{From: "middle", To: []string{"end"}},
				},
				RootElements: []string{"middle"},
			},
		},
		{
			// Two roots. Single descendant, index root1
			// root1
			//   \- descendant
			// root2
			testName: "two roots index root1",
			id:       "root1",
			sut: &NodeList{
				Nodes: []*Node{
					{Id: "root1"}, {Id: "root2"}, {Id: "descendant"},
				},
				Edges: []*Edge{
					{From: "root1", To: []string{"descendant"}},
				},
				RootElements: []string{"root1", "root2"},
			},
			expected: &NodeList{
				Nodes: []*Node{
					{Id: "root1"}, {Id: "descendant"},
				},
				Edges: []*Edge{
					{From: "root1", To: []string{"descendant"}},
				},
				RootElements: []string{"root1"},
			},
		},
		{
			// Two roots. Common descendant, index root2
			// root1
			//   \
			//    >= descendant
			//   /
			// root2
			testName: "two roots index root1",
			id:       "root2",
			sut: &NodeList{
				Nodes: []*Node{
					{Id: "root1"}, {Id: "root2"}, {Id: "descendant"},
				},
				Edges: []*Edge{
					{From: "root2", To: []string{"descendant"}},
					{From: "descendant", To: []string{"root1"}},
				},
				RootElements: []string{"root1", "root2"},
			},
			expected: &NodeList{
				Nodes: []*Node{
					{Id: "root2"}, {Id: "descendant"},
				},
				Edges: []*Edge{
					{From: "root2", To: []string{"descendant"}},
				},
				RootElements: []string{"root2"},
			},
		},
	} {
		t.Run(tc.testName, func(t *testing.T) {
			graph := tc.sut.NodeGraph(tc.id)
			if tc.expected != nil {
				require.NotNil(t, graph)
			}
			logrus.Infof("%T %+v", graph, graph)
			require.True(
				t, tc.expected.Equal(graph), "%s:\n\nResult: %s\n\nExpected: %s",
				tc.testName, graph, tc.expected,
			)
		})
	}
}

func TestRelateNodeAtId(t *testing.T) {
	sutId := "nodeA"
	nodeId := "nodeB"
	testNode := &Node{Id: nodeId}
	for _, tc := range []struct {
		name        string
		sut         *NodeList
		node        *Node
		expected    *NodeList
		shouldError bool
	}{
		{
			name: "relate to node",
			sut: &NodeList{
				Nodes: []*Node{{Id: sutId}},
			},
			node: testNode,
			expected: &NodeList{
				Nodes: []*Node{{Id: sutId}, {Id: nodeId}},
				Edges: []*Edge{{From: sutId, To: []string{nodeId}, Type: Edge_UNKNOWN}},
			},
		},
		{
			name: "non existent node",
			sut: &NodeList{
				Nodes: []*Node{{Id: sutId + "other"}},
			},
			node:        testNode,
			shouldError: true,
		},
		{
			name: "relate to existing edge",
			sut: &NodeList{
				Nodes: []*Node{{Id: sutId}, {Id: "node2"}},
				Edges: []*Edge{{From: sutId, To: []string{"node2"}, Type: Edge_UNKNOWN}},
			},
			node: testNode,
			expected: &NodeList{
				Nodes: []*Node{{Id: sutId}, {Id: "node2"}, {Id: nodeId}},
				Edges: []*Edge{{From: sutId, To: []string{"node2", nodeId}, Type: Edge_UNKNOWN}},
			},
		},
		{
			name: "relate existing node",
			sut: &NodeList{
				Nodes: []*Node{{Id: sutId}, {Id: nodeId}},
			},
			node: testNode,
			expected: &NodeList{
				Nodes: []*Node{{Id: sutId}, {Id: nodeId}},
				Edges: []*Edge{{From: sutId, To: []string{nodeId}, Type: Edge_UNKNOWN}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.sut.RelateNodeAtID(tc.node, sutId, Edge_UNKNOWN)
			if tc.shouldError {
				require.Error(t, err)
				return
			}
			require.True(t, tc.sut.Equal(tc.expected))
		})
	}
}

func TestNodeListCopy(t *testing.T) {
	for _, tc := range []struct {
		original *NodeList
	}{
		{
			original: &NodeList{
				Nodes: []*Node{
					{Id: "test1"},
					{Id: "test2"},
				},
				Edges: []*Edge{
					{From: "test1", Type: Edge_contains, To: []string{"test2"}},
				},
			},
		},
		{
			original: &NodeList{
				Nodes: []*Node{
					{Id: "root1"}, {Id: "root2"}, {Id: "descendant"},
				},
				Edges: []*Edge{
					{From: "root2", To: []string{"descendant"}},
					{From: "descendant", To: []string{"root1"}},
				},
				RootElements: []string{"root1", "root2"},
			},
		},
		{
			original: &NodeList{
				Nodes:        []*Node{},
				Edges:        []*Edge{},
				RootElements: []string{"root1", "root2"},
			},
		},
	} {
		copied := tc.original.Copy()
		require.True(t, tc.original.Equal(copied), "equal copied nodelist %s %s", tc.original, copied)
	}
}

func TestRelateNodeListAtId(t *testing.T) {
	sutId := "nodeA"
	nodeId := "nodeB"
	testNodeList := &NodeList{
		RootElements: []string{sutId},
		Nodes:        []*Node{{Id: sutId}},
		Edges:        []*Edge{},
	}

	for _, tc := range []struct {
		name        string
		sut         *NodeList
		nodeList    *NodeList
		expected    *NodeList
		shouldError bool
	}{
		{
			// This merges these nodelists:
			//   root        root
			//     \           \
			//    NodeA       NodeB
			name: "relate to node",
			sut:  testNodeList,
			nodeList: &NodeList{
				RootElements: []string{nodeId},
				Nodes:        []*Node{{Id: nodeId}},
				Edges:        []*Edge{},
			},
			expected: &NodeList{
				RootElements: []string{sutId},
				Nodes:        []*Node{{Id: sutId}, {Id: nodeId}},
				Edges:        []*Edge{{From: sutId, To: []string{nodeId}, Type: Edge_ancestor}},
			},
		},
		{
			// This merges two nodelists:
			// root         root
			//   \            \
			//  NodeA        NodeB
			//                 \ (contains)
			//                NodeC
			name: "relate with descendants",
			sut:  testNodeList,
			nodeList: &NodeList{
				RootElements: []string{nodeId},
				Nodes:        []*Node{{Id: nodeId}, {Id: "nodeC"}},
				Edges:        []*Edge{{From: nodeId, To: []string{"nodeC"}, Type: Edge_contains}},
			},
			expected: &NodeList{
				RootElements: []string{sutId},
				Nodes:        []*Node{{Id: sutId}, {Id: nodeId}, {Id: "nodeC"}},
				Edges: []*Edge{
					{From: sutId, To: []string{nodeId}, Type: Edge_ancestor},
					{From: nodeId, To: []string{"nodeC"}, Type: Edge_contains},
				},
			},
		},
		{
			// Error when the specified ID is not there
			name: "merge point not available",
			sut: &NodeList{
				RootElements: []string{"nodeC"},
				Nodes:        []*Node{{Id: "nodeC"}},
			},
			nodeList:    testNodeList,
			shouldError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.sut.RelateNodeListAtID(tc.nodeList, sutId, Edge_ancestor)
			if tc.shouldError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Truef(t, tc.sut.Equal(tc.expected), "Result: %+v", tc.sut)
		})
	}
}
