package sbom

import (
	"testing"
	"time"

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
		Hashes:           map[int32]string{int32(HashAlgorithm_SHA1): "9283475928734987"},
		SourceInfo:       "Source info here",
		PrimaryPurpose:   []Purpose{Purpose_FILE},
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
				Type: ExternalReference_VCS,
			},
		},
		Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:/apk/wolfi/glibc@12.0.0"},
		FileTypes:   []string{"TEXT"},
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
				Hashes: map[int32]string{
					int32(HashAlgorithm_SHA1): "9782347892345789234578",
				},
				ReleaseDate: now,
			},
			n2: &Node{
				Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:generic/mysoftware@1.0.0"},
				BuildDate:   now,
			},
			expected: &Node{
				Name:    "My Awesome Software",
				Version: "1.0.0",
				Hashes: map[int32]string{
					int32(HashAlgorithm_SHA1): "9782347892345789234578",
				},
				ReleaseDate: now,
				Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:generic/mysoftware@1.0.0"},
				BuildDate:   now,
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

func TestNodeFlatString(t *testing.T) {
	t1 := time.Date(2023, 11, 15, 20, 34, 58, 651387237, time.UTC)
	t2 := time.Date(2023, 11, 16, 20, 34, 58, 651387237, time.UTC)
	t3 := time.Date(2023, 11, 17, 20, 34, 58, 651387237, time.UTC)
	for _, tc := range []struct {
		name           string
		sut            *Node
		expectedString string
	}{
		{
			"simple",
			&Node{
				Id:               "node-id",
				Type:             0,
				Name:             "test node",
				Version:          "1.0.0",
				FileName:         "test.tar.gz",
				UrlHome:          "http://example.com/",
				UrlDownload:      "http://example.com/file.tar.gz",
				LicenseConcluded: "Apache-2.0",
				LicenseComments:  "Comment on the license",
				Copyright:        "Copyright (c) 2023 The Protobom Authors",
				Hashes:           map[int32]string{int32(HashAlgorithm_SHA256): "b51261db1ecadecf85274e811e537c5811a0ad1ab2a0121aeac4e3d031e1bf83"},
				SourceInfo:       "",
				PrimaryPurpose:   []Purpose{Purpose_CONTAINER},
				Comment:          "",
				Summary:          "",
				Description:      "",
				Suppliers: []*Person{
					{
						Name:  "ACME, Inc",
						IsOrg: true,
						Email: "acme@example.com",
						Url:   "http://acme-fixtures.com",
						Phone: "123-3456",
					},
				},
				Originators: []*Person{
					{
						Name:  "The Open Source Authors",
						IsOrg: false,
						Email: "noone@example.com",
						Url:   "http://github.com/example",
						Phone: "987-5432",
					},
				},
				ReleaseDate:    timestamppb.New(t1),
				BuildDate:      timestamppb.New(t2),
				ValidUntilDate: timestamppb.New(t3),
				Identifiers:    map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:/apk/wolfi/bash@4.1.11"},
				FileTypes:      []string{},
				ExternalReferences: []*ExternalReference{
					{
						Url:       "http://github.com/external",
						Type:      ExternalReference_VCS,
						Comment:   "GitHub Link",
						Authority: "",
						Hashes:    map[int32]string{},
					},
				},
			},
			"extref:(t)56(u)http://github.com/external(c)GitHub Link:identifiers[1]:pkg:/apk/wolfi/bash@4.1.11:originator:n(The Open Source Authors)o(false)email(noone@example.com)url(http://github.com/example)p(987-5432):protobom.protobom.Node.build_date:1700166898:protobom.protobom.Node.copyright:Copyright (c) 2023 The Protobom Authors:protobom.protobom.Node.file_name:test.tar.gz:protobom.protobom.Node.hashes:3:b51261db1ecadecf85274e811e537c5811a0ad1ab2a0121aeac4e3d031e1bf83:protobom.protobom.Node.id:node-id:protobom.protobom.Node.license_comments:Comment on the license:protobom.protobom.Node.license_concluded:Apache-2.0:protobom.protobom.Node.name:test node:protobom.protobom.Node.primary_purpose[0]:5:protobom.protobom.Node.release_date:1700080498:protobom.protobom.Node.url_download:http://example.com/file.tar.gz:protobom.protobom.Node.url_home:http://example.com/:protobom.protobom.Node.valid_until_date:1700253298:protobom.protobom.Node.version:1.0.0:supplier:n(ACME, Inc)o(true)email(acme@example.com)url(http://acme-fixtures.com)p(123-3456)",
		},
		{
			"with-extref",
			&Node{
				Id:                 "node-2",
				Type:               1,
				Name:               "textfile.txt",
				Version:            "",
				FileName:           "textfile.txt",
				UrlHome:            "http://example.com/",
				UrlDownload:        "http://example.com/file.tar.gz",
				Licenses:           []string{},
				LicenseConcluded:   "Apache-2.0",
				LicenseComments:    "Test license, ignore",
				Copyright:          "Copyright (c) 2023 The Protobom Authors",
				Hashes:             map[int32]string{int32(HashAlgorithm_SHA1): "7df059597099bb7dcf25d2a9aedfaf4465f72d8d", int32(HashAlgorithm_SHA256): "b51261db1ecadecf85274e811e537c5811a0ad1ab2a0121aeac4e3d031e1bf83", int32(HashAlgorithm_SHA512): "dc6b68d13b8cf959644b935f1192b02c71aa7a5cf653bd43b4480fa89eec8d4d3f16a2278ec8c3b40ab1fdb233b3173a78fd83590d6f739e0c9e8ff56c282557"},
				SourceInfo:         "",
				PrimaryPurpose:     []Purpose{Purpose_FILE},
				Comment:            "This a test file to check serialization",
				Summary:            "Test",
				Description:        "Descr",
				Attribution:        []string{"Copyright 2003 The Protobom Authors"},
				Suppliers:          []*Person{},
				Originators:        []*Person{},
				ExternalReferences: []*ExternalReference{},
				FileTypes:          []string{},
			},
			"protobom.protobom.Node.attribution[0]:Copyright 2003 The Protobom Authors:protobom.protobom.Node.comment:This a test file to check serialization:protobom.protobom.Node.copyright:Copyright (c) 2023 The Protobom Authors:protobom.protobom.Node.description:Descr:protobom.protobom.Node.file_name:textfile.txt:protobom.protobom.Node.hashes:2:7df059597099bb7dcf25d2a9aedfaf4465f72d8d3:b51261db1ecadecf85274e811e537c5811a0ad1ab2a0121aeac4e3d031e1bf835:dc6b68d13b8cf959644b935f1192b02c71aa7a5cf653bd43b4480fa89eec8d4d3f16a2278ec8c3b40ab1fdb233b3173a78fd83590d6f739e0c9e8ff56c282557:protobom.protobom.Node.id:node-2:protobom.protobom.Node.license_comments:Test license, ignore:protobom.protobom.Node.license_concluded:Apache-2.0:protobom.protobom.Node.name:textfile.txt:protobom.protobom.Node.primary_purpose[0]:12:protobom.protobom.Node.summary:Test:protobom.protobom.Node.type:1:protobom.protobom.Node.url_download:http://example.com/file.tar.gz:protobom.protobom.Node.url_home:http://example.com/",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s := tc.sut.flatString()
			require.Equal(t, tc.expectedString, s)
		})
	}
}

func TestNodeCopy(t *testing.T) {
	original := &Node{
		Licenses: []string{"Apache-2.0"},
		Hashes: map[int32]string{
			int32(HashAlgorithm_SHA1):   "f3ae11065cafc14e27a1410ae8be28e600bb8336",
			int32(HashAlgorithm_SHA256): "4f232eeb99e1663d07f0af1af6ea262bf594934b694228e71fd8f159f9a19f32",
			int32(HashAlgorithm_SHA512): "8044d0df34242699ad73bfe99b9ac3d6bbdaa4f8ebce1e23ee5c7f9fe59db8ad7b01fe94e886941793aee802008a35b05a30bc51426db796aa21e5e91b7ed9be",
		},
		FileTypes: []string{"TEXT"},
		Suppliers: []*Person{
			{
				Name:  "John Doe",
				Email: "john@doe.com",
			},
		},
		Originators: []*Person{
			{
				Name:  "Jane Doe",
				Email: "jane@doe.com",
			},
		},
	}

	copied := original.Copy()

	// modifying the original to ensure the deep copy worked
	original.Suppliers[0].Name = "Suppliers Copy Failed"
	original.Originators[0].Email = "Originators Copy Failed"
	original.Licenses[0] = "Licenses Copy Failed"
	original.Hashes[int32(HashAlgorithm_SHA1)] = "Hashes Copy Failed"
	original.FileTypes[0] = "FileTypes Copy Failed"

	// The copied Node should reflect the original values, not the subsequent changes.
	require.Equal(t, "John Doe", copied.Suppliers[0].Name)
	require.Equal(t, "jane@doe.com", copied.Originators[0].Email)
	require.Equal(t, "Apache-2.0", copied.Licenses[0])
	require.Equal(t, "f3ae11065cafc14e27a1410ae8be28e600bb8336", copied.Hashes[int32(HashAlgorithm_SHA1)])
	require.Equal(t, "TEXT", copied.FileTypes[0])
}

func TestNodeDescendants(t *testing.T) {
	sutId := "mynode"
	for _, tc := range []struct {
		name                string
		sut                 *NodeList
		expectedNodesLength int
		depth               int
	}{
		{
			// SA graph with a single node. We should get a one node result but
			// we use a max distance of 10 to catch any possible errors traversing
			// the graph that could lead to duplications.
			//
			//     mynode
			//       |
			name: "single node",
			sut: &NodeList{
				Nodes:        []*Node{{Id: sutId}},
				Edges:        []*Edge{},
				RootElements: []string{sutId},
			},
			expectedNodesLength: 1,
			depth:               10,
		},
		{
			//     mynode
			//     /    \
			// child1  child2
			name: "two descendants one level",
			sut: &NodeList{
				Nodes: []*Node{{Id: sutId}, {Id: "child1"}, {Id: "child2"}},
				Edges: []*Edge{{
					From: sutId, To: []string{"child1", "child2"},
				}},
				RootElements: []string{sutId},
			},
			expectedNodesLength: 3,
			depth:               10,
		},
		{
			//      mynode
			//      /   \
			//  child1  child2
			//     |      |
			// child1-1 child2-1
			name: "four descendants two levels",
			sut: &NodeList{
				Nodes: []*Node{{Id: sutId}, {Id: "child1"}, {Id: "child2"}, {Id: "child1-1"}, {Id: "child2-1"}},
				Edges: []*Edge{
					{From: sutId, To: []string{"child1", "child2"}},
					{From: "child1", To: []string{"child1-1"}},
					{From: "child2", To: []string{"child2-1"}},
				},
				RootElements: []string{sutId},
			},
			expectedNodesLength: 5,
			depth:               10,
		},
		{
			//      mynode        <-- Depth 1
			//      /   \
			//  child1  child2    <-- Depth 2
			//     |      |
			// child1-1 child2-1  <-- Depth 3
			name: "four descendants two levels, depth 2",
			sut: &NodeList{
				Nodes: []*Node{{Id: sutId}, {Id: "child1"}, {Id: "child2"}, {Id: "child1-1"}, {Id: "child2-1"}},
				Edges: []*Edge{
					{From: sutId, To: []string{"child1", "child2"}},
					{From: "child1", To: []string{"child1-1"}},
					{From: "child2", To: []string{"child2-1"}},
				},
				RootElements: []string{sutId},
			},
			expectedNodesLength: 3,
			depth:               2,
		},
		{
			//       root1    /-> root2
			//          \    /       \
			//       =mynode=      child3
			//            |
			//        child2-1
			name: "mid node check we stop at root",
			sut: &NodeList{
				Nodes: []*Node{{Id: sutId}, {Id: "root1"}, {Id: "root2"}, {Id: "child2-1"}, {Id: "child3"}},
				Edges: []*Edge{
					{From: "root1", To: []string{sutId}},
					{From: sutId, To: []string{"child2-1", "root2"}},
					{From: "root2", To: []string{"child3"}},
				},
				RootElements: []string{"root1", "root2"},
			},
			expectedNodesLength: 3, // Must not contain root1 or child3
			depth:               10,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.sut.NodeDescendants(sutId, tc.depth)
			require.NotNil(t, res)
			require.Len(t, res.RootElements, 1)
			require.Len(t, res.Nodes, tc.expectedNodesLength)
		})
	}
}

func TestNodeAddHash(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sut      *Node
		algo     HashAlgorithm
		val      string
		expected map[int32]string
	}{
		{
			name: "regular add",
			sut:  &Node{Hashes: map[int32]string{}},
			algo: HashAlgorithm_SHA256,
			val:  "a127ceedc934ccbe6e5fc2fac4c1afa2bf59271d2df288dd0cba01fbf93ce694",
			expected: map[int32]string{
				int32(HashAlgorithm_SHA256): "a127ceedc934ccbe6e5fc2fac4c1afa2bf59271d2df288dd0cba01fbf93ce694",
			},
		},
		{
			name: "replace existing",
			sut: &Node{Hashes: map[int32]string{
				int32(HashAlgorithm_SHA256): "a127ceedc934ccbe6e5fc2fac4c1afa2bf59271d2df288dd0cba01fbf93ce694",
			}},
			algo: HashAlgorithm_SHA256,
			val:  "c2c306cf6281251126b8bff2e747d89019de78de51324f3a48f9c83b794be46c",
			expected: map[int32]string{
				int32(HashAlgorithm_SHA256): "c2c306cf6281251126b8bff2e747d89019de78de51324f3a48f9c83b794be46c",
			},
		},
		{
			name: "empty hash does not replace value",
			sut: &Node{Hashes: map[int32]string{
				int32(HashAlgorithm_SHA256): "a127ceedc934ccbe6e5fc2fac4c1afa2bf59271d2df288dd0cba01fbf93ce694",
			}},
			algo: HashAlgorithm_SHA256,
			val:  "",
			expected: map[int32]string{
				int32(HashAlgorithm_SHA256): "a127ceedc934ccbe6e5fc2fac4c1afa2bf59271d2df288dd0cba01fbf93ce694",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.sut.AddHash(tc.algo, tc.val)
			require.True(t, tc.sut.Equal(&Node{Hashes: tc.expected}))
		})
	}
}
