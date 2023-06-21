package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

func TestAugment(t *testing.T) {
	fullnode := &Node{
		Name:             "test1",
		Version:          "1.0.0",
		FileName:         "file.txt",
		UrlHome:          "http://home.com/",
		UrlDownload:      "http://home.com/file.tgz",
		Licenses:         []string{"Apache-2.0"},
		LicenseConcluded: "Apache-2.0",
		LicenseComments:  "A license",
		Copyright:        "Copyright 2023 The BOM Squad",
		Hashes:           map[string]string{"sha1": "9283475928734987"},
		SourceInfo:       "Source info here",
		PrimaryPurpose:   "FILE",
		Comment:          "Hello world",
		Summary:          "This is a test package",
		Description:      "This is a test package, it is red",
		Attribution:      []string{"The BOM Squad"},
		Suppliers: []*Person{
			{
				Name:  "John Doe",
				Email: "john@doe.com",
			},
		},
		Originators: []*Person{
			{
				Name:  "John Doe",
				Email: "john@doe.com",
			},
		},
		ReleaseDate:    timestamppb.Now(),
		BuildDate:      timestamppb.Now(),
		ValidUntilDate: timestamppb.Now(),
		ExternalReferences: []*ExternalReference{
			{
				Url:  "git+https://github.com/example/example",
				Type: "VCS",
			},
		},
		Identifiers: []*Identifier{
			{
				Type:  "pkg:/apk/wolfi/glibc@12.0.0",
				Value: "purl",
			},
		},
		FileTypes: []string{"TEXT"},
	}

	for _, tc := range []struct {
		sut      *Node
		n2       *Node
		expected *Node
	}{
		// ID and node type should never change
		{
			sut: &Node{
				Id:   "test1",
				Type: 0,
			},
			n2: &Node{
				Id:   "test2",
				Type: 1,
			},
			expected: &Node{
				Id:   "test1",
				Type: 0,
			},
		},
		{
			sut: fullnode,
			n2: &Node{
				Name:        "other name",
				Version:     "2.0.0",
				Attribution: []string{"Other attribution"},
			},
			expected: fullnode,
		},
	} {
		tc.sut.Augment(tc.n2)
		require.Equal(t, tc.sut, tc.expected)
	}
}

func TestUpdate(t *testing.T) {
	now := timestamppb.Now()
	for _, tc := range []struct {
		sut      *Node
		n2       *Node
		expected *Node
	}{
		// ID and node type should never change
		{
			sut: &Node{
				Id:   "test1",
				Type: 0,
			},
			n2: &Node{
				Id:   "test2",
				Type: 1,
			},
			expected: &Node{
				Id:   "test1",
				Type: 0,
			},
		},
		{
			sut: &Node{
				Name:    "My Awesome Software",
				Version: "1.0.0",
				Hashes: map[string]string{
					"SHA1": "9782347892345789234578",
				},
				ReleaseDate: now,
			},
			n2: &Node{
				Identifiers: []*Identifier{
					{
						Type:  "purl",
						Value: "pkg:generic/mysoftware@1.0.0",
					},
				},
				BuildDate: now,
			},
			expected: &Node{
				Name:    "My Awesome Software",
				Version: "1.0.0",
				Hashes: map[string]string{
					"SHA1": "9782347892345789234578",
				},
				ReleaseDate: now,
				Identifiers: []*Identifier{
					{
						Type:  "purl",
						Value: "pkg:generic/mysoftware@1.0.0",
					},
				},
				BuildDate: now,
			},
		},
	} {
		tc.sut.Update(tc.n2)
		require.Equal(t, tc.sut, tc.expected)
	}
}

func TestGetRootNodes(t *testing.T) {
	for _, tc := range []struct {
		sut      *NodeList
		expected []*Node
	}{
		// ID and node type should never change
		{
			sut: &NodeList{
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
			sut: &NodeList{
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
