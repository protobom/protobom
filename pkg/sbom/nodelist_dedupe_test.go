package sbom

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dedupePkg builds a package node with a purl and up to two hashes: the
// first a SHA-256, the second a SHA-1.
func dedupePkg(id, purl string, hashes ...string) *Node {
	n := &Node{Id: id, Type: Node_PACKAGE, Name: id}
	if purl != "" {
		n.Identifiers = map[int32]string{int32(SoftwareIdentifierType_PURL): purl}
	}
	if len(hashes) > 0 {
		n.Hashes = map[int32]string{int32(HashAlgorithm_SHA256): hashes[0]}
	}
	if len(hashes) > 1 {
		n.Hashes[int32(HashAlgorithm_SHA1)] = hashes[1]
	}
	return n
}

func dedupeFile(id, sha256 string) *Node {
	return &Node{
		Id: id, Type: Node_FILE, Name: id,
		Hashes: map[int32]string{int32(HashAlgorithm_SHA256): sha256},
	}
}

// dedupeEdges renders the edges as "from>to:type" by node id.
func dedupeEdges(nl *NodeList) []string {
	out := []string{}
	for _, e := range nl.GetEdges() {
		for _, to := range e.GetTo() {
			out = append(out, e.GetFrom()+">"+to+":"+e.GetType().String())
		}
	}
	return out
}

func dedupeIDs(nodes []*Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.GetId())
	}
	return out
}

func TestHashesConflict(t *testing.T) {
	for name, tc := range map[string]struct {
		a, b *Node
		want bool
	}{
		"same value":      {dedupePkg("a", "", "h1"), dedupePkg("b", "", "h1"), false},
		"different value": {dedupePkg("a", "", "h1"), dedupePkg("b", "", "h2"), true},
		"no shared algo": {
			dedupePkg("a", "", "h1"),
			&Node{Id: "b", Hashes: map[int32]string{int32(HashAlgorithm_SHA1): "s1"}},
			false,
		},
		"one agrees, one differs": {dedupePkg("a", "", "h1", "s1"), dedupePkg("b", "", "h1", "s2"), true},
		"no hashes":               {dedupePkg("a", ""), dedupePkg("b", ""), false},
		"empty value":             {&Node{Hashes: map[int32]string{1: ""}}, &Node{Hashes: map[int32]string{1: "x"}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.a.HashesConflict(tc.b))
			assert.Equal(t, tc.want, tc.b.HashesConflict(tc.a), "symmetric")
		})
	}
}

func TestAbsorb(t *testing.T) {
	n := &Node{
		Name:               "n",
		Licenses:           []string{"MIT"},
		Hashes:             map[int32]string{int32(HashAlgorithm_SHA256): "h1"},
		Identifiers:        map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:x/n@1"},
		ExternalReferences: []*ExternalReference{{Type: ExternalReference_VCS, Url: "https://vcs"}},
		Properties:         []*Property{{Name: "k", Data: "v"}},
	}
	n2 := &Node{
		Name:        "other",
		Version:     "2",
		Licenses:    []string{"MIT", "Apache-2.0"},
		Hashes:      map[int32]string{int32(HashAlgorithm_SHA256): "different", int32(HashAlgorithm_SHA1): "s1"},
		Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:x/other@2", int32(SoftwareIdentifierType_CPE23): "cpe:2.3:a:x:n:1"},
		ExternalReferences: []*ExternalReference{
			{Type: ExternalReference_VCS, Url: "https://vcs"},
			{Type: ExternalReference_WEBSITE, Url: "https://site"},
		},
		Properties: []*Property{{Name: "k", Data: "v"}, {Name: "k2", Data: "v2"}},
	}

	n.Absorb(n2)

	// Scalars: kept when set, filled when not.
	require.Equal(t, "n", n.Name)
	require.Equal(t, "2", n.Version)
	// Collections: merged entry by entry, n's entries first and kept.
	require.Equal(t, []string{"MIT", "Apache-2.0"}, n.Licenses)
	require.Equal(t, map[int32]string{int32(HashAlgorithm_SHA256): "h1", int32(HashAlgorithm_SHA1): "s1"}, n.Hashes)
	require.Equal(t, "pkg:x/n@1", n.Identifiers[int32(SoftwareIdentifierType_PURL)])
	require.Equal(t, "cpe:2.3:a:x:n:1", n.Identifiers[int32(SoftwareIdentifierType_CPE23)])
	require.Len(t, n.ExternalReferences, 2)
	require.Len(t, n.Properties, 2)

	// Augment would have left every collection as it was.
	m := &Node{Licenses: []string{"MIT"}, Hashes: map[int32]string{int32(HashAlgorithm_SHA256): "h1"}}
	m.Augment(n2)
	require.Equal(t, []string{"MIT"}, m.Licenses)
	require.Len(t, m.Hashes, 1)

	// Absorbing into an empty node fills everything.
	e := &Node{}
	e.Absorb(n2)
	require.Equal(t, n2.Hashes, e.Hashes)
	require.Equal(t, n2.Identifiers, e.Identifiers)
	require.Equal(t, n2.Licenses, e.Licenses)
}

func TestSameComponent(t *testing.T) {
	for name, tc := range map[string]struct {
		a, b *Node
		want bool
	}{
		"same sha256":                 {dedupePkg("a", "pkg:x/a@1", "h1"), dedupePkg("b", "pkg:x/b@2", "h1"), true},
		"different sha256, same purl": {dedupePkg("a", "pkg:x/a@1", "h1"), dedupePkg("b", "pkg:x/a@1", "h2"), false},
		"no shared algorithm, same purl": {
			dedupePkg("a", "pkg:x/a@1", "h1"),
			&Node{Id: "b", Type: Node_PACKAGE, Identifiers: map[int32]string{int32(SoftwareIdentifierType_PURL): "pkg:x/a@1"}, Hashes: map[int32]string{int32(HashAlgorithm_SHA1): "s1"}},
			true,
		},
		"sha256 agrees, sha1 disagrees": {dedupePkg("a", "", "h1", "s1"), dedupePkg("b", "", "h1", "s2"), false},
		"no hashes, same purl":          {dedupePkg("a", "pkg:x/a@1"), dedupePkg("b", "pkg:x/a@1"), true},
		"no hashes, different purl":     {dedupePkg("a", "pkg:x/a@1"), dedupePkg("b", "pkg:x/a@2"), false},
		"no hashes, no purl":            {dedupePkg("a", ""), dedupePkg("b", ""), false},
		"file and package, same hash":   {dedupeFile("f", "h1"), dedupePkg("p", "", "h1"), false},
		"two files, same hash":          {dedupeFile("f", "h1"), dedupeFile("g", "h1"), true},
		"two files, different hash":     {dedupeFile("f", "h1"), dedupeFile("g", "h2"), false},
		"nil":                           {nil, dedupePkg("a", ""), false},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, SameComponent(tc.a, tc.b))
			assert.Equal(t, tc.want, SameComponent(tc.b, tc.a), "symmetric")
		})
	}
}

func TestDedupe(t *testing.T) {
	t.Run("collapses by hash and purl and rewires", func(t *testing.T) {
		a := dedupePkg("a", "pkg:x/lib@1", "h1")
		a.Licenses = []string{"MIT"}
		a2 := dedupePkg("a2", "pkg:x/lib@1", "h1") // same hash
		a2.Description = "described"
		a2.Licenses = []string{"MIT", "Apache-2.0"}
		a2.Hashes[int32(HashAlgorithm_SHA1)] = "s1"
		a2.Properties = []*Property{{Name: "k", Data: "v"}}
		a3 := dedupePkg("a3", "pkg:x/lib@1")             // no hash, same purl
		other := dedupePkg("other", "pkg:x/lib@1", "h2") // same purl, conflicting hash: stays
		nl := &NodeList{
			Nodes: []*Node{dedupePkg("root", "pkg:x/root@1"), a, a2, a3, other, dedupePkg("dep", "pkg:x/dep@1")},
			Edges: []*Edge{
				{Type: Edge_dependsOn, From: "root", To: []string{"a", "a2", "a3", "other"}},
				{Type: Edge_dependsOn, From: "a2", To: []string{"dep", "a"}}, // a self loop after the merge
				{Type: Edge_dependsOn, From: "a3", To: []string{"dep"}},
			},
			RootElements: []string{"root", "a2"},
		}

		dropped := nl.Dedupe(nil)

		require.Equal(t, map[string]string{"a2": "a", "a3": "a"}, dropped)
		require.Equal(t, []string{"root", "a", "other", "dep"}, dedupeIDs(nl.Nodes))
		require.ElementsMatch(t, []string{
			"root>a:dependsOn", "root>other:dependsOn", "a>dep:dependsOn",
		}, dedupeEdges(nl), "duplicate and self edges collapse")
		require.Equal(t, []string{"root", "a"}, nl.RootElements)

		// The survivor absorbed what it lacked and kept what it had.
		require.Equal(t, "described", a.Description)
		require.Equal(t, []string{"MIT", "Apache-2.0"}, a.Licenses)
		require.Equal(t, "s1", a.Hashes[int32(HashAlgorithm_SHA1)])
		require.Equal(t, "h1", a.Hashes[int32(HashAlgorithm_SHA256)])
		require.Len(t, a.Properties, 1)
	})

	t.Run("a hashless node cannot bridge conflicting hashes", func(t *testing.T) {
		// Whatever the order, the two hashed nodes stay apart and the
		// hashless one joins exactly one of them.
		for _, order := range [][]*Node{
			{dedupePkg("h1", "pkg:x/lib@1", "h1"), dedupePkg("h2", "pkg:x/lib@1", "h2"), dedupePkg("nohash", "pkg:x/lib@1")},
			{dedupePkg("nohash", "pkg:x/lib@1"), dedupePkg("h1", "pkg:x/lib@1", "h1"), dedupePkg("h2", "pkg:x/lib@1", "h2")},
		} {
			nl := &NodeList{Nodes: order}
			dropped := nl.Dedupe(nil)
			require.Len(t, dropped, 1)
			require.Len(t, nl.Nodes, 2)
			sums := []string{}
			for _, n := range nl.Nodes {
				sums = append(sums, n.Hashes[int32(HashAlgorithm_SHA256)])
			}
			require.ElementsMatch(t, []string{"h1", "h2"}, sums, "each survivor keeps one of the hashes")
		}
	})

	t.Run("nothing to do", func(t *testing.T) {
		nl := &NodeList{
			Nodes:        []*Node{dedupePkg("root", "pkg:x/root@1"), dedupePkg("dep", "pkg:x/dep@1")},
			Edges:        []*Edge{{Type: Edge_dependsOn, From: "root", To: []string{"dep"}}},
			RootElements: []string{"root"},
		}
		require.Empty(t, nl.Dedupe(nil))
		require.Len(t, nl.Nodes, 2)
		require.Equal(t, []string{"root>dep:dependsOn"}, dedupeEdges(nl))
		require.Empty(t, (&NodeList{}).Dedupe(nil))
	})

	t.Run("files and packages never merge, files with equal hashes do", func(t *testing.T) {
		nl := &NodeList{
			Nodes: []*Node{dedupePkg("p", "", "h1"), dedupeFile("f", "h1"), dedupeFile("g", "h1")},
			Edges: []*Edge{{Type: Edge_dependsOn, From: "p", To: []string{"f", "g"}}},
		}
		require.Equal(t, map[string]string{"g": "f"}, nl.Dedupe(nil))
		require.Equal(t, []string{"p>f:dependsOn"}, dedupeEdges(nl))
	})

	t.Run("custom identity", func(t *testing.T) {
		nl := &NodeList{Nodes: []*Node{dedupePkg("a", "pkg:x/a@1"), dedupePkg("b", "pkg:x/a@1")}}
		byName := func(x, y *Node) bool { return x.GetName() == y.GetName() }
		require.Empty(t, nl.Dedupe(byName), "same purl but the identity says no")
		require.Len(t, nl.Nodes, 2)
	})
}
