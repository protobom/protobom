package sbom

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNodeDiff(t *testing.T) {
	mytime := timestamppb.New(time.Date(2023, 10, 16, 11, 41, 0, 0, time.UTC))
	testNode := &Node{
		Id:               "test-node",
		Type:             Node_PACKAGE,
		Name:             "test",
		Version:          "1.0.0",
		FileName:         "test.zip",
		UrlHome:          "http://example.com/",
		UrlDownload:      "http://example.com/test-node.zip",
		Licenses:         []string{"Apache-2.0"},
		LicenseConcluded: "Apache-2.0",
		LicenseComments:  "License inferred by an automated classifer",
		Copyright:        "Copyright (c) 2023 The Protobom Authors",
		SourceInfo:       "",
		PrimaryPurpose:   []Purpose{Purpose_APPLICATION},
		Comment:          "This a node to test node diffing",
		Summary:          "A non existent node that serves as an example to diff",
		Description:      "A non existent software package that can be used to test data",
		Attribution:      []string{},
		Suppliers: []*Person{
			{
				Name:  "The protobom Authors",
				IsOrg: true,
				Email: "protobom@example.dev",
				Url:   "http://github.com/protobom",
			},
		},
		Originators:    []*Person{},
		ReleaseDate:    mytime,
		BuildDate:      nil,
		ValidUntilDate: nil,
		ExternalReferences: []*ExternalReference{
			{
				Url:     "http://github.com/protobom",
				Type:    ExternalReference_VCS,
				Comment: "Organization Repo",
			},
		},
		Identifiers: map[int32]string{
			int32(SoftwareIdentifierType_PURL): "pkg:github/protobom@1.0.0",
		},
		Hashes: map[int32]string{
			int32(HashAlgorithm_SHA1): "781721ca4eccbf8fe65c44dcdf141ca1b4e44adf",
		},
		Properties: []*Property{
			{Name: "test", Data: "testing123"},
			{Name: "otherProperty", Data: "somethin else"},
		},
	}

	for _, tc := range []struct {
		name     string
		prepare  func(*Node, *Node)
		options  []DiffOption
		sut      *Node
		node     *Node
		expected *NodeDiff
	}{
		{
			name:     "nochange",
			prepare:  func(sutNode, newNode *Node) {},
			expected: nil,
		},
		{
			name: "alter node id ignored by default",
			prepare: func(sutNode, newNode *Node) {
				newNode.Id = "modified"
			},
			expected: nil,
		},
		{
			name: "alter node id with WithIDs",
			prepare: func(sutNode, newNode *Node) {
				newNode.Id = "modified"
			},
			options: []DiffOption{WithIDs()},
			expected: &NodeDiff{
				Added: &Node{
					Id: "modified",
				},
				Removed:   &Node{},
				DiffCount: 1,
			},
		},
		{
			name: "alter node name",
			prepare: func(sutNode, newNode *Node) {
				newNode.Name = "newname"
			},
			expected: &NodeDiff{
				Added: &Node{
					Name: "newname",
				},
				Removed:   &Node{},
				DiffCount: 1,
			},
		},
		{
			name: "alter node name and id",
			prepare: func(sutNode, newNode *Node) {
				newNode.Id = "modified"
				newNode.Name = "newname"
			},
			expected: &NodeDiff{
				Added: &Node{
					Name: "newname",
				},
				Removed:   &Node{},
				DiffCount: 1,
			},
		},
		{
			name: "alter node name and id with WithIDs",
			prepare: func(sutNode, newNode *Node) {
				newNode.Id = "modified"
				newNode.Name = "newname"
			},
			options: []DiffOption{WithIDs()},
			expected: &NodeDiff{
				Added: &Node{
					Id:   "modified",
					Name: "newname",
				},
				Removed:   &Node{},
				DiffCount: 2,
			},
		},
		{
			name: "blank DownloadURL",
			prepare: func(sutNode, newNode *Node) {
				newNode.UrlDownload = ""
			},
			expected: &NodeDiff{
				Added: &Node{},
				Removed: &Node{
					UrlDownload: "http://example.com/test-node.zip",
				},
				DiffCount: 1,
			},
		},
		{
			name: "add a license",
			prepare: func(sutNode, newNode *Node) {
				newNode.Licenses = append(newNode.Licenses, "GPL3")
			},
			expected: &NodeDiff{
				Added: &Node{
					Licenses: []string{"GPL3"},
				},
				Removed:   &Node{},
				DiffCount: 1,
			},
		},
		{
			name: "remove a license",
			prepare: func(sutNode, newNode *Node) {
				sutNode.Licenses = newNode.Licenses
				sutNode.Licenses = append(sutNode.Licenses, "GPL3")
			},
			expected: &NodeDiff{
				Added: &Node{},
				Removed: &Node{
					Licenses: []string{"GPL3"},
				},
				DiffCount: 1,
			},
		},
		{
			name: "add a hash",
			prepare: func(sutNode, newNode *Node) {
				newNode.Hashes[int32(HashAlgorithm_SHA256)] = "2f2ed83cb80d77c14b7a23284fa73fbe3150a571fdb9388dcce9a7209bb11055"
			},
			expected: &NodeDiff{
				Added: &Node{
					Hashes: map[int32]string{
						int32(HashAlgorithm_SHA256): "2f2ed83cb80d77c14b7a23284fa73fbe3150a571fdb9388dcce9a7209bb11055",
					},
				},
				Removed:   &Node{},
				DiffCount: 1,
			},
		},
		{
			name: "remove a hash",
			prepare: func(sutNode, newNode *Node) {
				sutNode.Hashes[int32(HashAlgorithm_SHA256)] = "2f2ed83cb80d77c14b7a23284fa73fbe3150a571fdb9388dcce9a7209bb11055"
			},
			expected: &NodeDiff{
				Added: &Node{},
				Removed: &Node{
					Hashes: map[int32]string{
						int32(HashAlgorithm_SHA256): "2f2ed83cb80d77c14b7a23284fa73fbe3150a571fdb9388dcce9a7209bb11055",
					},
				},
				DiffCount: 1,
			},
		},
		{
			name: "change external reference",
			prepare: func(sutNode, newNode *Node) {
				newNode.ExternalReferences[0].Type = ExternalReference_WEBSITE
			},
			expected: &NodeDiff{
				Added: &Node{
					ExternalReferences: []*ExternalReference{
						{
							Url:     "http://github.com/protobom",
							Type:    ExternalReference_WEBSITE,
							Comment: "Organization Repo",
						},
					},
				},
				Removed: &Node{
					ExternalReferences: []*ExternalReference{
						{
							Url:     "http://github.com/protobom",
							Type:    ExternalReference_VCS,
							Comment: "Organization Repo",
						},
					},
				},
				DiffCount: 1,
			},
		},
		{
			name: "add-property",
			prepare: func(sutNode, newNode *Node) {
				newNode.Properties = append(newNode.Properties, &Property{Name: "secondTest", Data: "321"})
			},
			expected: &NodeDiff{
				Added: &Node{
					Properties: []*Property{
						{Name: "secondTest", Data: "321"},
					},
				},
				Removed:   &Node{},
				DiffCount: 1,
			},
		},
		{
			name: "remove-property",
			prepare: func(sutNode, newNode *Node) {
				newNode.Properties = []*Property{newNode.Properties[0]}
			},
			expected: &NodeDiff{
				Added: &Node{},
				Removed: &Node{
					Properties: []*Property{
						{Name: "otherProperty", Data: "somethin else"},
					},
				},
				DiffCount: 1,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Tests start with a copy of the test node
			tc.sut = testNode.Copy()
			tc.node = testNode.Copy()
			// The prepare function modifies them for the test
			tc.prepare(tc.sut, tc.node)
			result := tc.sut.Diff(tc.node, tc.options...)
			if tc.expected == nil {
				require.Nil(t, result)
				return
			}
			// Compare the nodes in the diff report
			require.NotNil(t, result)
			require.Truef(t, tc.expected.Added.Equal(result.Added), "comparing added: %s %s", result.Added.flatString(), tc.expected.Added.flatString())
			require.Truef(t, tc.expected.Removed.Equal(result.Removed), "comparing removed: %s %s", result.Removed.flatString(), tc.expected.Removed.flatString())
			require.Equal(t, tc.expected.DiffCount, result.DiffCount)
		})
	}
}

// testDiffNodeList builds the NodeList the NodeList.Diff tests start from:
// an application depending on two libraries.
func testDiffNodeList() *NodeList {
	return &NodeList{
		Nodes: []*Node{
			{
				Id:      "node-1",
				Type:    Node_PACKAGE,
				Name:    "app",
				Version: "1.0.0",
				Identifiers: map[int32]string{
					int32(SoftwareIdentifierType_PURL): "pkg:generic/app@1.0.0",
				},
				Hashes: map[int32]string{
					int32(HashAlgorithm_SHA256): "6a19a4bb32f4bd925e26f4a5932affe8757dfa1a90c1d1d32a3f0b6f42c2bcf0",
				},
			},
			{
				Id:      "node-2",
				Type:    Node_PACKAGE,
				Name:    "libone",
				Version: "2.1.0",
				Identifiers: map[int32]string{
					int32(SoftwareIdentifierType_PURL): "pkg:generic/libone@2.1.0",
				},
				Hashes: map[int32]string{
					int32(HashAlgorithm_SHA256): "0f9f5c1c3b6a9d5f6f1f4b1a9a4b1b0a3a2c1d1e2f30415263748596a7b8c9d0",
				},
			},
			{
				Id:      "node-3",
				Type:    Node_PACKAGE,
				Name:    "libtwo",
				Version: "0.9.0",
				Identifiers: map[int32]string{
					int32(SoftwareIdentifierType_PURL): "pkg:generic/libtwo@0.9.0",
				},
				Hashes: map[int32]string{
					int32(HashAlgorithm_SHA256): "d6f2b1a0c9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2",
				},
			},
		},
		Edges: []*Edge{
			{From: "node-1", Type: Edge_dependsOn, To: []string{"node-2", "node-3"}},
		},
		RootElements: []string{"node-1"},
	}
}

func TestNodeListDiff(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(sut, other *NodeList)
		options []DiffOption
		// check verifies the resulting diff. A nil check expects a nil diff.
		check func(t *testing.T, d *NodeListDiff)
	}{
		{
			name:    "no change",
			prepare: func(sut, other *NodeList) {},
			check:   nil,
		},
		{
			name: "node added",
			prepare: func(sut, other *NodeList) {
				other.Nodes = append(other.Nodes, &Node{Id: "node-4", Name: "libthree"})
			},
			check: func(t *testing.T, d *NodeListDiff) {
				require.Len(t, d.Added, 1)
				require.Equal(t, "node-4", d.Added[0].Id)
				require.Empty(t, d.Removed)
				require.Empty(t, d.Modified)
				require.Equal(t, 1, d.DiffCount)
			},
		},
		{
			name: "node removed",
			prepare: func(sut, other *NodeList) {
				other.Nodes = other.Nodes[0:2]
			},
			check: func(t *testing.T, d *NodeListDiff) {
				require.Empty(t, d.Added)
				require.Len(t, d.Removed, 1)
				require.Equal(t, "node-3", d.Removed[0].Id)
				require.Empty(t, d.Modified)
				require.Equal(t, 1, d.DiffCount)
			},
		},
		{
			name: "node modified",
			prepare: func(sut, other *NodeList) {
				other.Nodes[1].Version = "2.2.0"
			},
			check: func(t *testing.T, d *NodeListDiff) {
				require.Empty(t, d.Added)
				require.Empty(t, d.Removed)
				require.Len(t, d.Modified, 1)
				require.Equal(t, "node-2", d.Modified[0].Node1.Id)
				require.Equal(t, "node-2", d.Modified[0].Node2.Id)
				require.Equal(t, "2.2.0", d.Modified[0].Added.Version)
				require.Equal(t, 1, d.Modified[0].DiffCount)
				require.Equal(t, 1, d.DiffCount)
			},
		},
		{
			name: "node rename alone is no change",
			prepare: func(sut, other *NodeList) {
				other.Nodes[2].Id = "node-3-renamed"
				other.Edges[0].To = []string{"node-2", "node-3-renamed"}
			},
			check: nil,
		},
		{
			name: "node rename reported with WithIDs",
			prepare: func(sut, other *NodeList) {
				other.Nodes[2].Id = "node-3-renamed"
				other.Edges[0].To = []string{"node-2", "node-3-renamed"}
			},
			options: []DiffOption{WithIDs()},
			check: func(t *testing.T, d *NodeListDiff) {
				require.Empty(t, d.Added)
				require.Empty(t, d.Removed)
				require.Len(t, d.Modified, 1)
				require.Equal(t, "node-3-renamed", d.Modified[0].Added.Id)
				require.Equal(t, 1, d.DiffCount)
			},
		},
		{
			name: "node matched by identity across IDs",
			prepare: func(sut, other *NodeList) {
				other.Nodes[2].Id = "node-3-renamed"
				other.Nodes[2].Version = "0.9.1"
				other.Edges[0].To = []string{"node-2", "node-3-renamed"}
			},
			check: func(t *testing.T, d *NodeListDiff) {
				require.Empty(t, d.Added)
				require.Empty(t, d.Removed)
				require.Len(t, d.Modified, 1)
				require.Equal(t, "node-3", d.Modified[0].Node1.Id)
				require.Equal(t, "node-3-renamed", d.Modified[0].Node2.Id)
				require.Equal(t, "0.9.1", d.Modified[0].Added.Version)
				require.Empty(t, d.Modified[0].Added.Id)
				// The edges must not report changes as the renamed node's
				// ID translates back to its match in the receiver
				require.Empty(t, d.EdgesAdded)
				require.Empty(t, d.EdgesRemoved)
				require.Equal(t, 1, d.DiffCount)
			},
		},
		{
			name: "ambiguous identity match reports add and remove",
			prepare: func(sut, other *NodeList) {
				sut.Nodes = append(sut.Nodes, &Node{
					Id: "amb-1",
					Identifiers: map[int32]string{
						int32(SoftwareIdentifierType_PURL): "pkg:generic/dupe@1.0.0",
					},
				})
				for _, id := range []string{"amb-2", "amb-3"} {
					other.Nodes = append(other.Nodes, &Node{
						Id: id,
						Identifiers: map[int32]string{
							int32(SoftwareIdentifierType_PURL): "pkg:generic/dupe@1.0.0",
						},
					})
				}
			},
			check: func(t *testing.T, d *NodeListDiff) {
				require.Len(t, d.Added, 2)
				require.Equal(t, "amb-2", d.Added[0].Id)
				require.Equal(t, "amb-3", d.Added[1].Id)
				require.Len(t, d.Removed, 1)
				require.Equal(t, "amb-1", d.Removed[0].Id)
				require.Empty(t, d.Modified)
				require.Equal(t, 3, d.DiffCount)
			},
		},
		{
			name: "edge destination added",
			prepare: func(sut, other *NodeList) {
				other.Nodes = append(other.Nodes, &Node{Id: "node-4", Name: "libthree"})
				other.Edges[0].To = append(other.Edges[0].To, "node-4")
			},
			check: func(t *testing.T, d *NodeListDiff) {
				require.Len(t, d.Added, 1)
				require.Len(t, d.EdgesAdded, 1)
				require.True(t, d.EdgesAdded[0].Equal(
					&Edge{From: "node-1", Type: Edge_dependsOn, To: []string{"node-4"}},
				), d.EdgesAdded[0].flatString())
				require.Empty(t, d.EdgesRemoved)
				require.Equal(t, 2, d.DiffCount)
			},
		},
		{
			name: "edge destination removed",
			prepare: func(sut, other *NodeList) {
				other.Nodes = other.Nodes[0:2]
				other.Edges[0].To = []string{"node-2"}
			},
			check: func(t *testing.T, d *NodeListDiff) {
				require.Len(t, d.Removed, 1)
				require.Empty(t, d.EdgesAdded)
				require.Len(t, d.EdgesRemoved, 1)
				require.True(t, d.EdgesRemoved[0].Equal(
					&Edge{From: "node-1", Type: Edge_dependsOn, To: []string{"node-3"}},
				), d.EdgesRemoved[0].flatString())
				require.Equal(t, 2, d.DiffCount)
			},
		},
		{
			name: "edge of new type added",
			prepare: func(sut, other *NodeList) {
				other.Edges = append(other.Edges, &Edge{
					From: "node-2", Type: Edge_contains, To: []string{"node-3"},
				})
			},
			check: func(t *testing.T, d *NodeListDiff) {
				require.Len(t, d.EdgesAdded, 1)
				require.True(t, d.EdgesAdded[0].Equal(
					&Edge{From: "node-2", Type: Edge_contains, To: []string{"node-3"}},
				), d.EdgesAdded[0].flatString())
				require.Equal(t, 1, d.DiffCount)
			},
		},
		{
			name: "root element added",
			prepare: func(sut, other *NodeList) {
				other.RootElements = append(other.RootElements, "node-2")
			},
			check: func(t *testing.T, d *NodeListDiff) {
				require.Equal(t, []string{"node-2"}, d.RootElementsAdded)
				require.Empty(t, d.RootElementsRemoved)
				require.Equal(t, 1, d.DiffCount)
			},
		},
		{
			name: "root element replaced",
			prepare: func(sut, other *NodeList) {
				other.RootElements = []string{"node-2"}
			},
			check: func(t *testing.T, d *NodeListDiff) {
				require.Equal(t, []string{"node-2"}, d.RootElementsAdded)
				require.Equal(t, []string{"node-1"}, d.RootElementsRemoved)
				require.Equal(t, 2, d.DiffCount)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sut := testDiffNodeList()
			other := testDiffNodeList()
			tc.prepare(sut, other)
			result := sut.Diff(other, tc.options...)
			if tc.check == nil {
				require.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			tc.check(t, result)
		})
	}
}

func TestNodeListDiffNil(t *testing.T) {
	sut := testDiffNodeList()
	d := sut.Diff(nil)
	require.NotNil(t, d)
	require.Empty(t, d.Added)
	require.Len(t, d.Removed, 3)
	require.Len(t, d.EdgesRemoved, 1)
	require.Equal(t, []string{"node-1"}, d.RootElementsRemoved)
	require.Equal(t, 5, d.DiffCount)
}

func TestDiffString(t *testing.T) {
	for _, tc := range []struct {
		name            string
		sut1            string
		sut2            string
		expectedAdded   string
		expectedRemoved string
		expectedCount   int
	}{
		{
			name:            "no change",
			sut1:            "a",
			sut2:            "a",
			expectedAdded:   "",
			expectedRemoved: "",
			expectedCount:   0,
		},
		{
			name:            "change",
			sut1:            "",
			sut2:            "a",
			expectedAdded:   "a",
			expectedRemoved: "",
			expectedCount:   1,
		},
		{
			name:            "remove",
			sut1:            "a",
			sut2:            "",
			expectedAdded:   "",
			expectedRemoved: "a",
			expectedCount:   1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, r, c := diff(tc.sut1, tc.sut2)
			require.Equal(t, tc.expectedAdded, a)
			require.Equal(t, tc.expectedRemoved, r)
			require.Equal(t, tc.expectedCount, c)
		})
	}
}

func TestDiffStrSlice(t *testing.T) {
	for _, tc := range []struct {
		name            string
		sut1            []string
		sut2            []string
		expectedAdded   []string
		expectedRemoved []string
		expectedCount   int
	}{
		{
			name:            "no change",
			sut1:            []string{"a", "b"},
			sut2:            []string{"a", "b"},
			expectedAdded:   []string{},
			expectedRemoved: []string{},
			expectedCount:   0,
		},
		{
			name:            "add to blank",
			sut1:            []string{},
			sut2:            []string{"a"},
			expectedAdded:   []string{"a"},
			expectedRemoved: []string{},
			expectedCount:   1,
		},
		{
			name:            "add to existing",
			sut1:            []string{"a"},
			sut2:            []string{"a", "b"},
			expectedAdded:   []string{"b"},
			expectedRemoved: []string{},
			expectedCount:   1,
		},
		{
			name:            "remove all",
			sut1:            []string{"a", "b"},
			sut2:            []string{},
			expectedAdded:   []string{},
			expectedRemoved: []string{"a", "b"},
			expectedCount:   1,
		},
		{
			name:            "remove one",
			sut1:            []string{"a", "b"},
			sut2:            []string{"b"},
			expectedAdded:   []string{},
			expectedRemoved: []string{"a"},
			expectedCount:   1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, r, c := diffSlice(tc.sut1, tc.sut2)
			require.Equal(t, tc.expectedAdded, a)
			require.Equal(t, tc.expectedRemoved, r)
			require.Equal(t, tc.expectedCount, c)
		})
	}
}

func TestDiffDates(t *testing.T) {
	t1 := timestamppb.New(time.Date(2023, 11, 15, 13, 30, 0, 0, time.UTC))
	t2 := timestamppb.New(time.Date(2000, 1, 1, 13, 0, 0, 0, time.UTC))
	for _, tc := range []struct {
		name            string
		sut1            *timestamppb.Timestamp
		sut2            *timestamppb.Timestamp
		expectedAdded   *timestamppb.Timestamp
		expectedRemoved *timestamppb.Timestamp
		expectedCount   int
	}{
		{
			name:            "nochange",
			sut1:            t1,
			sut2:            t1,
			expectedAdded:   nil,
			expectedRemoved: nil,
			expectedCount:   0,
		},
		{
			name:            "nochange blank",
			sut1:            nil,
			sut2:            nil,
			expectedAdded:   nil,
			expectedRemoved: nil,
			expectedCount:   0,
		},
		{
			name:            "change",
			sut1:            t1,
			sut2:            t2,
			expectedAdded:   t2,
			expectedRemoved: nil,
			expectedCount:   1,
		},
		{
			name:            "remove",
			sut1:            t2,
			sut2:            nil,
			expectedAdded:   nil,
			expectedRemoved: t2,
			expectedCount:   1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, r, c := diffDates(tc.sut1, tc.sut2)
			require.Equal(t, tc.expectedAdded, a)
			require.Equal(t, tc.expectedRemoved, r)
			require.Equal(t, tc.expectedCount, c)
		})
	}
}

func TestDiffPersonList(t *testing.T) {
	p1 := &Person{
		Name:  "Corelia Enterprises",
		IsOrg: true,
	}
	p2 := &Person{
		Name:  "Turbowind Enterprises",
		IsOrg: true,
	}
	p3 := &Person{
		Name: "Inky",
	}
	//nolint:dupl
	for _, tc := range []struct {
		name            string
		sut1            []*Person
		sut2            []*Person
		expectedAdded   []*Person
		expectedRemoved []*Person
		expectedCount   int
	}{
		{
			name:            "no change",
			sut1:            []*Person{p1, p2},
			sut2:            []*Person{p1, p2},
			expectedAdded:   []*Person{},
			expectedRemoved: []*Person{},
			expectedCount:   0,
		},
		{
			name:            "add",
			sut1:            []*Person{p1},
			sut2:            []*Person{p1, p2},
			expectedAdded:   []*Person{p2},
			expectedRemoved: []*Person{},
			expectedCount:   1,
		},
		{
			name:            "remove",
			sut1:            []*Person{p1, p2},
			sut2:            []*Person{p1},
			expectedAdded:   []*Person{},
			expectedRemoved: []*Person{p2},
			expectedCount:   1,
		},
		{
			name:            "add and remove",
			sut1:            []*Person{p1, p2},
			sut2:            []*Person{p1, p3},
			expectedAdded:   []*Person{p3},
			expectedRemoved: []*Person{p2},
			expectedCount:   1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, r, c := diffList(tc.sut1, tc.sut2)
			require.Equal(t, tc.expectedAdded, a)
			require.Equal(t, tc.expectedRemoved, r)
			require.Equal(t, tc.expectedCount, c)
		})
	}
}

func TestDiffExtRefList(t *testing.T) {
	er1 := &ExternalReference{
		Url:  "https://example.com/",
		Type: ExternalReference_VCS,
	}
	er2 := &ExternalReference{
		Url:  "https://example.net/",
		Type: ExternalReference_VCS,
	}
	er3 := &ExternalReference{
		Url:  "https://example.org/",
		Type: ExternalReference_VCS,
	}
	//nolint:dupl
	for _, tc := range []struct {
		name            string
		sut1            []*ExternalReference
		sut2            []*ExternalReference
		expectedAdded   []*ExternalReference
		expectedRemoved []*ExternalReference
		expectedCount   int
	}{
		{
			name:            "no change",
			sut1:            []*ExternalReference{er1, er2},
			sut2:            []*ExternalReference{er1, er2},
			expectedAdded:   []*ExternalReference{},
			expectedRemoved: []*ExternalReference{},
			expectedCount:   0,
		},
		{
			name:            "add",
			sut1:            []*ExternalReference{er1},
			sut2:            []*ExternalReference{er1, er2},
			expectedAdded:   []*ExternalReference{er2},
			expectedRemoved: []*ExternalReference{},
			expectedCount:   1,
		},
		{
			name:            "remove",
			sut1:            []*ExternalReference{er1, er2},
			sut2:            []*ExternalReference{er1},
			expectedAdded:   []*ExternalReference{},
			expectedRemoved: []*ExternalReference{er2},
			expectedCount:   1,
		},
		{
			name:            "add and remove",
			sut1:            []*ExternalReference{er1, er2},
			sut2:            []*ExternalReference{er1, er3},
			expectedAdded:   []*ExternalReference{er3},
			expectedRemoved: []*ExternalReference{er2},
			expectedCount:   1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, r, c := diffList(tc.sut1, tc.sut2)
			require.Equal(t, tc.expectedAdded, a)
			require.Equal(t, tc.expectedRemoved, r)
			require.Equal(t, tc.expectedCount, c)
		})
	}
}

func TestDiffIntStrMap(t *testing.T) {
	m1 := map[int32]string{
		int32(HashAlgorithm_SHA1):   "68e6e3665b3010f0979089079d7f554c940e3aa8",
		int32(HashAlgorithm_SHA256): "d02b22ab7fc76fe2a17e768b180bf5048889dbcae3a6d7e4a889a916848e5d11",
	}
	m2 := map[int32]string{
		int32(HashAlgorithm_SHA1):   "68e6e3665b3010f0979089079d7f554c940e3aa8",
		int32(HashAlgorithm_SHA256): "a8a20fe2e556080457d718930bfe1f423100952fdb3cffe9b1f0831be96fd85e",
	}

	for _, tc := range []struct {
		name            string
		sut1            map[int32]string
		sut2            map[int32]string
		expectedAdded   map[int32]string
		expectedRemoved map[int32]string
		expectedCount   int
	}{
		{
			name:            "no change",
			sut1:            m1,
			sut2:            m1,
			expectedAdded:   map[int32]string{},
			expectedRemoved: map[int32]string{},
			expectedCount:   0,
		},
		{
			name: "change",
			sut1: m1,
			sut2: m2,
			expectedAdded: map[int32]string{
				int32(HashAlgorithm_SHA256): "a8a20fe2e556080457d718930bfe1f423100952fdb3cffe9b1f0831be96fd85e",
			},
			expectedRemoved: map[int32]string{},
			expectedCount:   1,
		},
		{
			name: "remove",
			sut1: m1,
			sut2: map[int32]string{
				int32(HashAlgorithm_SHA256): "d02b22ab7fc76fe2a17e768b180bf5048889dbcae3a6d7e4a889a916848e5d11",
			},
			expectedAdded: map[int32]string{},
			expectedRemoved: map[int32]string{
				int32(HashAlgorithm_SHA1): "68e6e3665b3010f0979089079d7f554c940e3aa8",
			},
			expectedCount: 1,
		},
		{
			name: "add and remove",
			sut1: m1,
			sut2: map[int32]string{
				int32(HashAlgorithm_SHA256): "a8a20fe2e556080457d718930bfe1f423100952fdb3cffe9b1f0831be96fd85e",
			},
			expectedAdded: map[int32]string{
				int32(HashAlgorithm_SHA256): "a8a20fe2e556080457d718930bfe1f423100952fdb3cffe9b1f0831be96fd85e",
			},
			expectedRemoved: map[int32]string{
				int32(HashAlgorithm_SHA1): "68e6e3665b3010f0979089079d7f554c940e3aa8",
			},
			expectedCount: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, r, c := diffMap(tc.sut1, tc.sut2)
			require.Equal(t, tc.expectedAdded, a)
			require.Equal(t, tc.expectedRemoved, r)
			require.Equal(t, tc.expectedCount, c)
		})
	}
}
