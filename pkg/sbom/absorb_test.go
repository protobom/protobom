package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNodeListAbsorb(t *testing.T) {
	nl := &NodeList{
		Nodes: []*Node{
			{Id: "a", Name: "a", Licenses: []string{"MIT"}, Hashes: map[int32]string{int32(HashAlgorithm_SHA256): "h1"}},
			{Id: "b", Name: "b"},
		},
		Edges:        []*Edge{{Type: Edge_dependsOn, From: "a", To: []string{"b"}}},
		RootElements: []string{"a"},
	}
	nl2 := &NodeList{
		Nodes: []*Node{
			{Id: "a", Name: "other", Version: "2", Licenses: []string{"Apache-2.0"}, Hashes: map[int32]string{int32(HashAlgorithm_SHA1): "s1"}},
			{Id: "c", Name: "c"},
		},
		Edges:        []*Edge{{Type: Edge_dependsOn, From: "a", To: []string{"c"}}},
		RootElements: []string{"a", "c"},
	}

	nl.Absorb(nl2)

	require.Equal(t, []string{"a", "b", "c"}, dedupeIDs(nl.Nodes))
	a := nl.GetNodeByID("a")
	require.Equal(t, "a", a.Name, "what nl states is kept")
	require.Equal(t, "2", a.Version, "what it lacks is filled")
	require.Equal(t, []string{"MIT", "Apache-2.0"}, a.Licenses, "collections merge entry by entry")
	require.Len(t, a.Hashes, 2)
	require.Len(t, nl.Edges, 1, "edges from the same node merge")
	require.ElementsMatch(t, []string{"b", "c"}, nl.Edges[0].To)
	require.Equal(t, []string{"a", "c"}, nl.RootElements)

	// Add, on the same input, leaves the shared node's collections alone.
	nl3 := &NodeList{Nodes: []*Node{{Id: "a", Licenses: []string{"MIT"}}}}
	nl3.Add(&NodeList{Nodes: []*Node{{Id: "a", Licenses: []string{"Apache-2.0"}}}})
	require.Equal(t, []string{"MIT"}, nl3.Nodes[0].Licenses)

	// Absorbing nothing changes nothing.
	before := nl.Copy()
	nl.Absorb(nil)
	nl.Absorb(&NodeList{})
	require.True(t, before.Equal(nl))
}

func TestDocumentAbsorb(t *testing.T) {
	d := &Document{
		Metadata: &Metadata{
			Id:    "urn:doc1",
			Tools: []*Tool{{Name: "unpack", Version: "1"}},
		},
		NodeList: &NodeList{Nodes: []*Node{{Id: "a", Licenses: []string{"MIT"}}}, RootElements: []string{"a"}},
	}
	when := timestamppb.Now()
	d2 := &Document{
		Metadata: &Metadata{
			Id:      "urn:doc2",
			Name:    "second",
			Comment: "from the second",
			Date:    when,
			Tools:   []*Tool{{Name: "unpack", Version: "1"}, {Name: "other", Version: "9"}},
			Authors: []*Person{{Name: "Ann", Email: "ann@example.com"}},
			DocumentTypes: []*DocumentType{
				{Type: DocumentType_BUILD.Enum()},
			},
		},
		NodeList: &NodeList{Nodes: []*Node{{Id: "a", Licenses: []string{"Apache-2.0"}}, {Id: "b"}}, RootElements: []string{"b"}},
	}

	d.Absorb(d2)

	m := d.GetMetadata()
	require.Equal(t, "urn:doc1", m.GetId(), "the id d states is kept")
	require.Equal(t, "second", m.GetName())
	require.Equal(t, "from the second", m.GetComment())
	require.Equal(t, when, m.GetDate())
	require.Len(t, m.GetTools(), 2, "the shared tool is listed once")
	require.Len(t, m.GetAuthors(), 1)
	require.Len(t, m.GetDocumentTypes(), 1)
	require.Equal(t, []string{"MIT", "Apache-2.0"}, d.GetNodeList().GetNodeByID("a").GetLicenses())
	require.Equal(t, []string{"a", "b"}, d.GetNodeList().GetRootElements())

	// Absorbing the same document again adds nothing.
	d.Absorb(d2)
	require.Len(t, m.GetTools(), 2)
	require.Len(t, m.GetAuthors(), 1)
	require.Len(t, d.GetNodeList().GetNodes(), 2)

	// An empty document takes everything; nil is a no-op.
	e := &Document{}
	e.Absorb(d2)
	require.Equal(t, "urn:doc2", e.GetMetadata().GetId())
	require.Len(t, e.GetNodeList().GetNodes(), 2)
	e.Absorb(nil)
	require.Len(t, e.GetNodeList().GetNodes(), 2)
}
