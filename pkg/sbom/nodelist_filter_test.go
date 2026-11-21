package sbom

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// filterNode builds a package node whose package URL is of the given type,
// or which has none when the type is empty.
func filterNode(id, purlType string) *Node {
	n := &Node{Id: id, Type: Node_PACKAGE}
	if purlType != "" {
		n.Identifiers = map[int32]string{
			int32(SoftwareIdentifierType_PURL): fmt.Sprintf("pkg:%s/%s@1.0.0", purlType, id),
		}
	}
	return n
}

// filterList builds a list of package nodes with the given ids, the first
// being the root element.
func filterList(edges []*Edge, ids ...string) *NodeList {
	nl := NewNodeList()
	for i, id := range ids {
		if i == 0 {
			nl.RootElements = append(nl.RootElements, id)
		}
		nl.Nodes = append(nl.Nodes, filterNode(id, "golang"))
	}
	nl.Edges = edges
	return nl
}

func filterNodeIDs(nl *NodeList) []string {
	ids := make([]string, 0, len(nl.Nodes))
	for _, n := range nl.Nodes {
		ids = append(ids, n.Id)
	}
	return ids
}

// filterEdges renders the edges as "from>type>to", one entry per destination.
func filterEdges(nl *NodeList) []string {
	out := []string{}
	for _, e := range nl.Edges {
		for _, to := range e.To {
			out = append(out, e.From+">"+e.Type.String()+">"+to)
		}
	}
	sort.Strings(out)
	return out
}

func TestFilterWithoutEdgeTypes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		sut       *NodeList
		types     []Edge_Type
		wantNodes []string
		wantEdges []string
	}{
		{
			name: "inverse edge drops the dependency, not its owner",
			sut: filterList([]*Edge{
				{Type: Edge_dependsOn, From: "root", To: []string{"prod"}},
				{Type: Edge_devDependency, From: "dev", To: []string{"root"}},
			}, "root", "prod", "dev"),
			types:     []Edge_Type{Edge_devDependency},
			wantNodes: []string{"root", "prod"},
			wantEdges: []string{"root>dependsOn>prod"},
		},
		{
			name: "descendants only the dependency led to go with it",
			sut: filterList([]*Edge{
				{Type: Edge_dependsOn, From: "root", To: []string{"prod"}},
				{Type: Edge_testDependency, From: "test", To: []string{"root"}},
				{Type: Edge_dependsOn, From: "test", To: []string{"deep"}},
				{Type: Edge_dependsOn, From: "deep", To: []string{"deeper"}},
			}, "root", "prod", "test", "deep", "deeper"),
			types:     []Edge_Type{Edge_testDependency},
			wantNodes: []string{"root", "prod"},
			wantEdges: []string{"root>dependsOn>prod"},
		},
		{
			name: "a descendant reached another way stays with what is below it",
			sut: filterList([]*Edge{
				{Type: Edge_dependsOn, From: "root", To: []string{"prod"}},
				{Type: Edge_devDependency, From: "dev", To: []string{"root"}},
				{Type: Edge_dependsOn, From: "dev", To: []string{"shared", "devonly"}},
				{Type: Edge_dependsOn, From: "prod", To: []string{"shared"}},
				{Type: Edge_dependsOn, From: "shared", To: []string{"leaf"}},
			}, "root", "prod", "dev", "shared", "devonly", "leaf"),
			types:     []Edge_Type{Edge_devDependency},
			wantNodes: []string{"root", "prod", "shared", "leaf"},
			wantEdges: []string{
				"prod>dependsOn>shared",
				"root>dependsOn>prod",
				"shared>dependsOn>leaf",
			},
		},
		{
			name: "the dependency stays where something else depends on it",
			sut: filterList([]*Edge{
				{Type: Edge_dependsOn, From: "root", To: []string{"prod"}},
				{Type: Edge_devDependency, From: "tool", To: []string{"root"}},
				{Type: Edge_dependsOn, From: "prod", To: []string{"tool"}},
			}, "root", "prod", "tool"),
			types:     []Edge_Type{Edge_devDependency},
			wantNodes: []string{"root", "prod", "tool"},
			wantEdges: []string{"prod>dependsOn>tool", "root>dependsOn>prod"},
		},
		{
			// The shape the CycloneDX unserializer gives a scoped component.
			name: "an edge stating the same pair goes with the filtered one",
			sut: filterList([]*Edge{
				{Type: Edge_contains, From: "root", To: []string{"prod", "dev"}},
				{Type: Edge_devDependency, From: "dev", To: []string{"root"}},
				{Type: Edge_dependsOn, From: "root", To: []string{"prod", "dev"}},
			}, "root", "prod", "dev"),
			types:     []Edge_Type{Edge_devDependency},
			wantNodes: []string{"root", "prod"},
			wantEdges: []string{"root>contains>prod", "root>dependsOn>prod"},
		},
		{
			name: "a forward edge type is cut at its destination",
			sut: filterList([]*Edge{
				{Type: Edge_dependsOn, From: "root", To: []string{"prod"}},
				{Type: Edge_dynamicLink, From: "root", To: []string{"lib"}},
			}, "root", "prod", "lib"),
			types:     []Edge_Type{Edge_dynamicLink},
			wantNodes: []string{"root", "prod"},
			wantEdges: []string{"root>dependsOn>prod"},
		},
		{
			name: "only the filtered destinations of an edge are lost",
			sut: filterList([]*Edge{
				{Type: Edge_devDependency, From: "dev", To: []string{"root", "prod"}},
				{Type: Edge_dependsOn, From: "root", To: []string{"prod"}},
				{Type: Edge_dependsOn, From: "dev", To: []string{"leaf"}},
			}, "root", "prod", "dev", "leaf"),
			types:     []Edge_Type{Edge_testDependency, Edge_devDependency},
			wantNodes: []string{"root", "prod"},
			wantEdges: []string{"root>dependsOn>prod"},
		},
		{
			name: "a cycle below the filtered edge does not hold itself in",
			sut: filterList([]*Edge{
				{Type: Edge_buildTool, From: "tool", To: []string{"root"}},
				{Type: Edge_dependsOn, From: "tool", To: []string{"a"}},
				{Type: Edge_dependsOn, From: "a", To: []string{"tool"}},
			}, "root", "tool", "a"),
			types:     []Edge_Type{Edge_buildTool},
			wantNodes: []string{"root"},
			wantEdges: []string{},
		},
		{
			name: "types the graph does not have change nothing",
			sut: filterList([]*Edge{
				{Type: Edge_dependsOn, From: "root", To: []string{"prod"}},
			}, "root", "prod"),
			types:     []Edge_Type{Edge_devDependency},
			wantNodes: []string{"root", "prod"},
			wantEdges: []string{"root>dependsOn>prod"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			before := tc.sut.Copy()
			got := tc.sut.Filter(WithoutEdgeTypes(tc.types...))
			require.Equal(t, tc.wantNodes, filterNodeIDs(got))
			require.Equal(t, tc.wantEdges, filterEdges(got))
			require.Equal(t, tc.sut.RootElements, got.RootElements)
			require.True(t, before.Equal(tc.sut), "the original list was modified")
		})
	}
}

func TestFilterWithoutPurlTypes(t *testing.T) {
	t.Parallel()
	// root(golang) -> npm -> under (golang), reached only through npm
	//              -> gem -> both  (golang), reached through npm too
	//              -> bare (no purl) -> below (golang)
	//              -> file
	build := func() *NodeList {
		return &NodeList{
			Nodes: []*Node{
				filterNode("root", "golang"),
				filterNode("npm", "npm"),
				filterNode("under", "golang"),
				filterNode("gem", "gem"),
				filterNode("both", "golang"),
				filterNode("bare", ""),
				filterNode("below", "golang"),
				{Id: "file", Type: Node_FILE},
			},
			Edges: []*Edge{
				{Type: Edge_dependsOn, From: "root", To: []string{"npm", "gem", "bare"}},
				{Type: Edge_contains, From: "root", To: []string{"file"}},
				{Type: Edge_dependsOn, From: "npm", To: []string{"under", "both"}},
				{Type: Edge_dependsOn, From: "gem", To: []string{"both"}},
				{Type: Edge_dependsOn, From: "bare", To: []string{"below"}},
			},
			RootElements: []string{"root"},
		}
	}

	for _, tc := range []struct {
		name      string
		types     []string
		wantNodes []string
	}{
		{
			name:      "a type takes what only it led to",
			types:     []string{"npm"},
			wantNodes: []string{"root", "gem", "both", "bare", "below", "file"},
		},
		{
			name:      "types are matched whatever their case",
			types:     []string{"NPM", "Gem"},
			wantNodes: []string{"root", "bare", "below", "file"},
		},
		{
			name:      "the empty type names packages without a purl, never files",
			types:     []string{""},
			wantNodes: []string{"root", "npm", "under", "gem", "both", "file"},
		},
		{
			name:      "root elements are never dropped",
			types:     []string{"golang"},
			wantNodes: []string{"root", "npm", "gem", "bare", "file"},
		},
		{
			name:      "an unknown type changes nothing",
			types:     []string{"cargo"},
			wantNodes: []string{"root", "npm", "under", "gem", "both", "bare", "below", "file"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := build().Filter(WithoutPurlTypes(tc.types...))
			require.Equal(t, tc.wantNodes, filterNodeIDs(got))
			// No edge is left naming a node that is gone.
			index := got.indexNodes()
			for _, e := range got.Edges {
				require.Contains(t, index, e.From)
				for _, to := range e.To {
					require.Contains(t, index, to)
				}
			}
		})
	}
}

func TestFilter(t *testing.T) {
	t.Parallel()

	t.Run("nil list", func(t *testing.T) {
		t.Parallel()
		var nl *NodeList
		got := nl.Filter(WithoutEdgeTypes(Edge_devDependency))
		require.NotNil(t, got)
		require.Empty(t, got.Nodes)
	})

	t.Run("without options nothing is lost", func(t *testing.T) {
		t.Parallel()
		// "island" is reached by no root element and stays all the same.
		sut := filterList([]*Edge{
			{Type: Edge_dependsOn, From: "root", To: []string{"prod"}},
			{Type: Edge_devDependency, From: "dev", To: []string{"root"}},
			{Type: Edge_dependsOn, From: "island", To: []string{"shore"}},
		}, "root", "prod", "dev", "island", "shore")
		got := sut.Filter()
		require.True(t, sut.Equal(got))
		require.Equal(t, filterNodeIDs(sut), filterNodeIDs(got))
		require.Same(t, sut.Nodes[0], got.Nodes[0], "nodes are shared with the original")
		require.NotSame(t, sut.Edges[0], got.Edges[0], "edges are not")
	})

	t.Run("nodes no root reached are left alone", func(t *testing.T) {
		t.Parallel()
		sut := filterList([]*Edge{
			{Type: Edge_devDependency, From: "dev", To: []string{"root"}},
			{Type: Edge_dependsOn, From: "island", To: []string{"shore"}},
		}, "root", "dev", "island", "shore")
		got := sut.Filter(WithoutEdgeTypes(Edge_devDependency))
		require.Equal(t, []string{"root", "island", "shore"}, filterNodeIDs(got))
		require.Equal(t, []string{"island>dependsOn>shore"}, filterEdges(got))
	})

	t.Run("options add up", func(t *testing.T) {
		t.Parallel()
		sut := &NodeList{
			Nodes: []*Node{
				filterNode("root", "golang"),
				filterNode("dev", "golang"),
				filterNode("js", "npm"),
				filterNode("named", "golang"),
				filterNode("kept", "golang"),
			},
			Edges: []*Edge{
				{Type: Edge_devDependency, From: "dev", To: []string{"root"}},
				{Type: Edge_dependsOn, From: "root", To: []string{"js", "named", "kept"}},
			},
			RootElements: []string{"root"},
		}
		got := sut.Filter(
			WithoutEdgeTypes(Edge_devDependency),
			WithoutPurlTypes("npm"),
			WithoutNodes(func(n *Node) bool { return n.Id == "named" }),
			WithoutNodes(nil),
		)
		require.Equal(t, []string{"root", "kept"}, filterNodeIDs(got))
		require.Equal(t, []string{"root>dependsOn>kept"}, filterEdges(got))
	})
}

func TestFilterWithoutEdgeGroups(t *testing.T) {
	t.Parallel()
	sut := filterList([]*Edge{
		{Type: Edge_dependsOn, From: "root", To: []string{"prod"}},
		{Type: Edge_devTool, From: "linter", To: []string{"root"}},
		{Type: Edge_testCase, From: "case", To: []string{"root"}},
		{Type: Edge_buildDependency, From: "compiler", To: []string{"root"}},
	}, "root", "prod", "linter", "case", "compiler")

	got := sut.Filter(WithoutEdgeGroups(EdgeGroupDevelopment, EdgeGroupTest))
	require.Equal(t, []string{"root", "prod", "compiler"}, filterNodeIDs(got))

	got = sut.Filter(WithoutEdgeGroups(EdgeGroups()...))
	require.Equal(t, []string{"root", "prod"}, filterNodeIDs(got))

	got = sut.Filter(WithoutEdgeGroups(), WithoutEdgeGroups("nonesuch"))
	require.True(t, sut.Equal(got))
}

func TestEdgeGroups(t *testing.T) {
	t.Parallel()
	require.Equal(t, []EdgeGroup{
		EdgeGroupDevelopment, EdgeGroupTest, EdgeGroupBuild,
		EdgeGroupOptional, EdgeGroupDocumentation,
	}, EdgeGroups())

	// Every type is in the group that lists it, and in that one only.
	seen := map[Edge_Type]EdgeGroup{}
	for _, g := range EdgeGroups() {
		require.NotEmpty(t, g.EdgeTypes(), g)
		for _, et := range g.EdgeTypes() {
			require.Equal(t, g, et.Group(), et.String())
			require.NotContains(t, seen, et, "%s is in two groups", et)
			seen[et] = g
		}
	}

	for _, et := range []Edge_Type{
		Edge_UNKNOWN, Edge_dependsOn, Edge_dependencyOf, Edge_contains, Edge_runtimeDependency,
	} {
		require.Empty(t, et.Group(), et.String())
	}
	require.Empty(t, EdgeGroup("nonesuch").EdgeTypes())

	// The types of a group are the caller's to change.
	types := EdgeGroupBuild.EdgeTypes()
	types[0] = Edge_UNKNOWN
	require.Equal(t, Edge_buildDependency, EdgeGroupBuild.EdgeTypes()[0])
}

func TestEdgeTypeInverse(t *testing.T) {
	t.Parallel()
	for _, et := range []Edge_Type{
		Edge_dependencyOf, Edge_devDependency, Edge_testTool, Edge_contained_by,
		Edge_optionalComponent, Edge_runtimeDependency,
	} {
		require.True(t, et.Inverse(), et.String())
	}
	for _, et := range []Edge_Type{
		Edge_UNKNOWN, Edge_dependsOn, Edge_contains, Edge_describes,
		Edge_ancestor, Edge_dynamicLink, Edge_other,
	} {
		require.False(t, et.Inverse(), et.String())
	}
}

func TestPackageURLType(t *testing.T) {
	t.Parallel()
	for purl, want := range map[string]string{
		"pkg:golang/github.com/protobom/protobom@v0.7.0": "golang",
		"pkg:npm/%40angular/core@1.0.0":                  "npm",
		"pkg:NPM/left-pad@1.0.0":                         "npm",
		"PKG:deb/debian/curl@8.4.0":                      "deb",
		"pkg:/golang/example.com/a@v1":                   "golang",
		"pkg://golang/example.com/a@v1":                  "golang",
		"pkg:golang":                                     "",
		"golang/example.com/a":                           "",
		"":                                               "",
	} {
		require.Equal(t, want, PackageURL(purl).Type(), purl)
	}
}
