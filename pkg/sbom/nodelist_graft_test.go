package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// graftList builds a list from nodes and "from>to" dependsOn edges; the
// first node is the root.
func graftList(nodes []*Node, deps ...string) *NodeList {
	nl := NewNodeList()
	for i, n := range nodes {
		if i == 0 {
			nl.AddRootNode(n)
		} else {
			nl.AddNode(n)
		}
	}
	for _, d := range deps {
		for i := range d {
			if d[i] == '>' {
				nl.MergeEdges([]*Edge{{From: d[:i], Type: Edge_dependsOn, To: []string{d[i+1:]}}})
			}
		}
	}
	return nl
}

// graftEdges renders the edges as "from>to:type" by node name, since
// grafted copies carry fresh ids.
func graftEdges(nl *NodeList) []string {
	out := []string{}
	for _, e := range nl.GetEdges() {
		for _, to := range e.GetTo() {
			out = append(out, nl.GetNodeByID(e.GetFrom()).GetName()+">"+nl.GetNodeByID(to).GetName()+":"+e.GetType().String())
		}
	}
	return out
}

func graftNames(nodes []*Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.GetName())
	}
	return out
}

func TestGraft(t *testing.T) {
	dst := graftList([]*Node{dedupeFile("bin", "h1")})
	src := graftList(
		[]*Node{dedupePkg("app", "pkg:x/app@1"), dedupePkg("lib", "pkg:x/lib@1"), dedupePkg("leaf", "pkg:x/leaf@1"), dedupePkg("stray", "pkg:x/stray@1")},
		"app>lib", "lib>leaf", "leaf>lib", // a cycle below the root
	)
	srcNodes := len(src.Nodes)

	require.NoError(t, dst.Graft("bin", src, "app", Edge_generatedFrom))

	require.ElementsMatch(t, []string{"bin", "app", "lib", "leaf"}, graftNames(dst.Nodes), "the stray is not reachable")
	require.ElementsMatch(t, []string{
		"bin>app:generatedFrom", "app>lib:dependsOn", "lib>leaf:dependsOn", "leaf>lib:dependsOn",
	}, graftEdges(dst))
	require.Equal(t, []string{"bin"}, dst.RootElements, "the destination keeps its roots")

	// Copies carry fresh ids and the source is untouched.
	require.Nil(t, dst.GetNodeByID("app"))
	require.Len(t, src.Nodes, srcNodes)
	require.NotNil(t, src.GetNodeByID("app"))
	require.Equal(t, []string{"app"}, src.RootElements)

	// Grafting the same source again yields a second, independent copy.
	require.NoError(t, dst.Graft("bin", src, "app", Edge_generatedFrom))
	require.Len(t, dst.Nodes, 7)

	require.Error(t, dst.Graft("nope", src, "app", Edge_contains))
	require.Error(t, dst.Graft("bin", src, "nope", Edge_contains))
	require.Error(t, dst.Graft("bin", nil, "app", Edge_contains))
}

func TestGraftDanglingEdge(t *testing.T) {
	src := &NodeList{
		Nodes:        []*Node{{Id: "app", Name: "app"}, {Id: "lib", Name: "lib"}},
		Edges:        []*Edge{{Type: Edge_dependsOn, From: "app", To: []string{"lib", "ghost"}}},
		RootElements: []string{"app"},
	}
	dst := graftList([]*Node{{Id: "bin", Name: "bin"}})
	require.NoError(t, dst.Graft("bin", src, "app", Edge_contains))
	require.ElementsMatch(t, []string{"bin", "app", "lib"}, graftNames(dst.Nodes))
	require.ElementsMatch(t, []string{"bin>app:contains", "app>lib:dependsOn"}, graftEdges(dst))
}

func TestGraftInto(t *testing.T) {
	target := dedupePkg("found", "pkg:x/app@1", "h1")
	target.Version = "1"
	target.Licenses = []string{"MIT"}
	dst := graftList([]*Node{target, dedupePkg("mine", "pkg:x/mine@1")}, "found>mine")

	root := dedupePkg("app", "pkg:x/app@1", "h1", "s1")
	root.Version = "9"
	root.Description = "from the other document"
	root.Licenses = []string{"MIT", "Apache-2.0"}
	root.Properties = []*Property{{Name: "source", Data: "sbom"}}
	src := graftList([]*Node{root, dedupePkg("lib", "pkg:x/lib@1"), dedupePkg("back", "pkg:x/back@1")}, "app>lib", "lib>back", "back>app")

	require.NoError(t, dst.GraftInto("found", src, "app"))

	require.ElementsMatch(t, []string{"found", "mine", "lib", "back"}, graftNames(dst.Nodes), "the root itself is not added")
	require.ElementsMatch(t, []string{
		"found>mine:dependsOn", "found>lib:dependsOn", "lib>back:dependsOn", "back>found:dependsOn",
	}, graftEdges(dst), "edges leaving or reaching the root now use the target")

	// The target kept its values and gained what it lacked.
	require.Equal(t, "1", target.Version)
	require.Equal(t, "from the other document", target.Description)
	require.Equal(t, []string{"MIT", "Apache-2.0"}, target.Licenses)
	require.Equal(t, "s1", target.Hashes[int32(HashAlgorithm_SHA1)])
	require.Equal(t, "h1", target.Hashes[int32(HashAlgorithm_SHA256)])
	require.Len(t, target.Properties, 1)
	require.Equal(t, []string{"found"}, dst.RootElements)

	// The source is untouched.
	require.Equal(t, "9", src.GetNodeByID("app").Version)
	require.Len(t, src.Nodes, 3)

	require.Error(t, dst.GraftInto("nope", src, "app"))
	require.Error(t, dst.GraftInto("found", src, "nope"))
	require.Error(t, dst.GraftInto("found", nil, "app"))
}
