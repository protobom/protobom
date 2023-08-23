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
				Hashes: map[string]string{
					"SHA1": "9782347892345789234578",
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
				Hashes: map[string]string{
					"SHA1": "9782347892345789234578",
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
		sut            *Node
		expectedString string
	}{
		{
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
				Hashes:           map[string]string{"sha-256": "b51261db1ecadecf85274e811e537c5811a0ad1ab2a0121aeac4e3d031e1bf83"},
				SourceInfo:       "",
				PrimaryPurpose:   "CONTAINER",
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
						Type:      "VCS",
						Comment:   "GitHub Link",
						Authority: "",
						Hashes:    map[string]string{},
					},
				},
			},
			"bomsquad.protobom.Node.build_date:1700166898:bomsquad.protobom.Node.copyright:Copyright (c) 2023 The Protobom Authors:bomsquad.protobom.Node.file_name:test.tar.gz:bomsquad.protobom.Node.hashes:sha-256:b51261db1ecadecf85274e811e537c5811a0ad1ab2a0121aeac4e3d031e1bf83:bomsquad.protobom.Node.id:node-id:bomsquad.protobom.Node.license_comments:Comment on the license:bomsquad.protobom.Node.license_concluded:Apache-2.0:bomsquad.protobom.Node.name:test node:bomsquad.protobom.Node.primary_purpose:CONTAINER:bomsquad.protobom.Node.release_date:1700080498:bomsquad.protobom.Node.url_download:http://example.com/file.tar.gz:bomsquad.protobom.Node.url_home:http://example.com/:bomsquad.protobom.Node.valid_until_date:1700253298:bomsquad.protobom.Node.version:1.0.0:extref:(t)VCS(u)http://github.com/external(c)GitHub Link:identifiers[1]:pkg:/apk/wolfi/bash@4.1.11:originator:n(The Open Source Authors)o(false)email(noone@example.com)url(http://github.com/example)p(987-5432):supplier:n(ACME, Inc)o(true)email(acme@example.com)url(http://acme-fixtures.com)p(123-3456)",
		},
		{
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
				Hashes:             map[string]string{"sha-1": "7df059597099bb7dcf25d2a9aedfaf4465f72d8d", "sha-256": "b51261db1ecadecf85274e811e537c5811a0ad1ab2a0121aeac4e3d031e1bf83", "sha-512": "dc6b68d13b8cf959644b935f1192b02c71aa7a5cf653bd43b4480fa89eec8d4d3f16a2278ec8c3b40ab1fdb233b3173a78fd83590d6f739e0c9e8ff56c282557"},
				SourceInfo:         "",
				PrimaryPurpose:     "FILE",
				Comment:            "This a test file to check serialization",
				Summary:            "Test",
				Description:        "Descr",
				Attribution:        []string{"Copyright 2003 The Protobom Authors"},
				Suppliers:          []*Person{},
				Originators:        []*Person{},
				ExternalReferences: []*ExternalReference{},
				FileTypes:          []string{},
			},
			"bomsquad.protobom.Node.attribution[0]:Copyright 2003 The Protobom Authors:bomsquad.protobom.Node.comment:This a test file to check serialization:bomsquad.protobom.Node.copyright:Copyright (c) 2023 The Protobom Authors:bomsquad.protobom.Node.description:Descr:bomsquad.protobom.Node.file_name:textfile.txt:bomsquad.protobom.Node.hashes:sha-1:7df059597099bb7dcf25d2a9aedfaf4465f72d8dsha-256:b51261db1ecadecf85274e811e537c5811a0ad1ab2a0121aeac4e3d031e1bf83sha-512:dc6b68d13b8cf959644b935f1192b02c71aa7a5cf653bd43b4480fa89eec8d4d3f16a2278ec8c3b40ab1fdb233b3173a78fd83590d6f739e0c9e8ff56c282557:bomsquad.protobom.Node.id:node-2:bomsquad.protobom.Node.license_comments:Test license, ignore:bomsquad.protobom.Node.license_concluded:Apache-2.0:bomsquad.protobom.Node.name:textfile.txt:bomsquad.protobom.Node.primary_purpose:FILE:bomsquad.protobom.Node.summary:Test:bomsquad.protobom.Node.type:1:bomsquad.protobom.Node.url_download:http://example.com/file.tar.gz:bomsquad.protobom.Node.url_home:http://example.com/",
		},
	} {
		s := tc.sut.flatString()
		require.Equal(t, tc.expectedString, s)
	}
}
