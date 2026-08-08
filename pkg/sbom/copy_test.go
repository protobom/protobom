// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The copies in this package have had two kinds of bug: a field left out, so
// the copy silently lost data, and a slice or map assigned rather than
// cloned, so writing to the copy reached back into the original. Both are
// invisible until something far away misbehaves, so each type is checked for
// both here rather than relying on whoever adds a field to remember.

// fullNode is a node with every field set, so a copy that drops one is
// caught. Anything added to the proto should be added here.
func fullNode() *Node {
	return &Node{
		Id: "node-1", Type: Node_FILE, Name: "name", Version: "1.0",
		FileName: "file.txt", UrlHome: "https://home", UrlDownload: "https://dl",
		Licenses: []string{"MIT", "Apache-2.0"}, LicenseConcluded: "MIT",
		LicenseComments: "comments", Copyright: "copyright", SourceInfo: "source",
		Comment: "comment", Summary: "summary", Description: "description",
		Attribution: []string{"attribution"}, FileTypes: []string{"SOURCE"},
		ContentType: "text/plain", FileKind: Node_FILE_KIND_DIRECTORY,
		Hashes:         map[int32]string{int32(HashAlgorithm_SHA1): "abc"},
		Identifiers:    map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:generic/a"},
		PrimaryPurpose: []Purpose{Purpose_LIBRARY, Purpose_SOURCE},
		Suppliers:      []*Person{{Name: "supplier", Contacts: []*Person{{Name: "contact"}}}},
		Originators:    []*Person{{Name: "originator"}},
		ExternalReferences: []*ExternalReference{{
			Url: "https://ref", Comment: "c", Authority: "auth",
			Type: ExternalReference_BOWER, Hashes: map[int32]string{1: "h"},
		}},
		Properties:     []*Property{{Name: "prop", Data: "data"}},
		ReleaseDate:    timestamppb.Now(),
		BuildDate:      timestamppb.Now(),
		ValidUntilDate: timestamppb.Now(),
	}
}

func fullPerson() *Person {
	return &Person{
		Name: "name", IsOrg: true, Email: "e@example.com", Url: "https://u",
		Phone: "555", Contacts: []*Person{{Name: "contact", Email: "c@example.com"}},
	}
}

// requireCarriesEveryField fails when the copy has fewer fields set than the
// original, which is what a forgotten field looks like.
func requireCarriesEveryField(t *testing.T, original, copied proto.Message) {
	t.Helper()
	original.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		require.True(t, copied.ProtoReflect().Has(fd),
			"the copy does not carry %s", fd.Name())
		return true
	})
}

// requireIndependent fails when writing to the copy reaches the original,
// which is what an assigned slice or map looks like.
func requireIndependent(t *testing.T, original, copied proto.Message, write func()) {
	t.Helper()
	before := proto.Clone(original)
	write()
	require.True(t, proto.Equal(before, original),
		"writing to the copy changed the original")
	require.False(t, proto.Equal(original, copied),
		"the write did not take, so this proves nothing")
}

func TestNodeCopyIsCompleteAndIndependent(t *testing.T) {
	original := fullNode()
	copied := original.Copy()

	requireCarriesEveryField(t, original, copied)
	require.True(t, proto.Equal(original, copied), "a copy says the same as the original")

	for name, write := range map[string]func(*Node){
		"licenses":            func(c *Node) { c.Licenses[0] = "changed" },
		"attribution":         func(c *Node) { c.Attribution[0] = "changed" },
		"file types":          func(c *Node) { c.FileTypes[0] = "changed" },
		"primary purpose":     func(c *Node) { c.PrimaryPurpose[0] = Purpose_CONTAINER },
		"hashes":              func(c *Node) { c.Hashes[int32(HashAlgorithm_SHA1)] = "changed" },
		"identifiers":         func(c *Node) { c.Identifiers[int32(SoftwareIdentifierType_PURL)] = "changed" },
		"suppliers":           func(c *Node) { c.Suppliers[0].Name = "changed" },
		"supplier contacts":   func(c *Node) { c.Suppliers[0].Contacts[0].Name = "changed" },
		"originators":         func(c *Node) { c.Originators[0].Name = "changed" },
		"external references": func(c *Node) { c.ExternalReferences[0].Url = "changed" },
		"external ref hashes": func(c *Node) { c.ExternalReferences[0].Hashes[1] = "changed" },
		"properties":          func(c *Node) { c.Properties[0].Data = "changed" },
		"release date":        func(c *Node) { c.ReleaseDate = timestamppb.New(c.ReleaseDate.AsTime().Add(1)) },
	} {
		t.Run(name, func(t *testing.T) {
			fresh := fullNode()
			c := fresh.Copy()
			requireIndependent(t, fresh, c, func() { write(c) })
		})
	}
}

func TestPersonCopyIsCompleteAndIndependent(t *testing.T) {
	original := fullPerson()
	copied := original.Copy()

	requireCarriesEveryField(t, original, copied)
	require.True(t, proto.Equal(original, copied))

	fresh := fullPerson()
	c := fresh.Copy()
	requireIndependent(t, fresh, c, func() { c.Contacts[0].Name = "changed" })
}

func TestEdgeCopyIsCompleteAndIndependent(t *testing.T) {
	original := &Edge{Type: Edge_contains, From: "a", To: []string{"b", "c"}}
	copied := original.Copy()

	requireCarriesEveryField(t, original, copied)
	require.True(t, proto.Equal(original, copied))

	fresh := &Edge{Type: Edge_contains, From: "a", To: []string{"b", "c"}}
	c := fresh.Copy()
	requireIndependent(t, fresh, c, func() { c.To[0] = "changed" })
}

func TestExternalReferenceCopyIsCompleteAndIndependent(t *testing.T) {
	build := func() *ExternalReference {
		return &ExternalReference{
			Url: "https://ref", Comment: "c", Authority: "auth",
			Type: ExternalReference_BOWER, Hashes: map[int32]string{1: "h"},
		}
	}
	original := build()
	copied := original.Copy()

	requireCarriesEveryField(t, original, copied)
	require.True(t, proto.Equal(original, copied))

	fresh := build()
	c := fresh.Copy()
	requireIndependent(t, fresh, c, func() { c.Hashes[1] = "changed" })
}

func TestPropertyCopyIsComplete(t *testing.T) {
	original := &Property{Name: "n", Data: "d"}
	copied := original.Copy()
	requireCarriesEveryField(t, original, copied)
	require.True(t, proto.Equal(original, copied))
}

func TestNodeListCopyIsCompleteAndIndependent(t *testing.T) {
	build := func() *NodeList {
		return &NodeList{
			Nodes:        []*Node{fullNode()},
			Edges:        []*Edge{{Type: Edge_contains, From: "node-1", To: []string{"b"}}},
			RootElements: []string{"node-1"},
		}
	}
	original := build()
	copied := original.Copy()

	requireCarriesEveryField(t, original, copied)
	require.True(t, proto.Equal(original, copied))

	for name, write := range map[string]func(*NodeList){
		"nodes":         func(c *NodeList) { c.Nodes[0].Id = "changed" },
		"node licenses": func(c *NodeList) { c.Nodes[0].Licenses[0] = "changed" },
		"edges":         func(c *NodeList) { c.Edges[0].From = "changed" },
		"edge targets":  func(c *NodeList) { c.Edges[0].To[0] = "changed" },
		"root elements": func(c *NodeList) { c.RootElements[0] = "changed" },
	} {
		t.Run(name, func(t *testing.T) {
			fresh := build()
			c := fresh.Copy()
			requireIndependent(t, fresh, c, func() { write(c) })
		})
	}
}

// Copying used to append each contact's copy to the contact itself rather
// than to the new person, so the copy came back with no contacts at all and
// the person being copied grew one every time it was copied.
func TestPersonCopyContacts(t *testing.T) {
	bob := &Person{Name: "bob", Email: "bob@example.com"}
	alice := &Person{Name: "alice", Contacts: []*Person{bob}}

	copied := alice.Copy()

	require.Len(t, copied.Contacts, 1, "the copy has the contacts")
	require.Equal(t, "bob", copied.Contacts[0].Name)
	require.Equal(t, "bob@example.com", copied.Contacts[0].Email)
	require.NotSame(t, bob, copied.Contacts[0], "the contact is copied, not shared")

	require.Len(t, alice.Contacts, 1, "copying leaves the original alone")
	require.Empty(t, bob.Contacts, "and does not give the contact a contact")

	// Copying twice must not grow anything.
	alice.Copy()
	require.Len(t, alice.Contacts, 1)
	require.Empty(t, bob.Contacts)
}

// Contacts nest, and so does copying them.
func TestPersonCopyNestedContacts(t *testing.T) {
	deep := &Person{Name: "a", Contacts: []*Person{
		{Name: "b", Contacts: []*Person{{Name: "c"}}},
	}}
	copied := deep.Copy()

	require.Len(t, copied.Contacts, 1)
	require.Len(t, copied.Contacts[0].Contacts, 1)
	require.Equal(t, "c", copied.Contacts[0].Contacts[0].Name)
	require.NotSame(t, deep.Contacts[0].Contacts[0], copied.Contacts[0].Contacts[0])
}
