package sbom

import "strings"

// FilterOption states something NodeList.Filter leaves out of the graph.
type FilterOption func(*nodeListFilter)

// nodeListFilter is what a set of FilterOptions adds up to.
type nodeListFilter struct {
	edgeTypes map[Edge_Type]struct{}
	nodes     []func(*Node) bool
}

// WithoutEdgeTypes leaves out the relationships of the given types, such as
// the development and test dependencies of a graph.
//
// A relationship is left out whole: when an edge of one of the types relates
// two nodes, every other edge that states the same pair the same way round
// goes with it. Documents often qualify a relationship next to stating it. A
// CycloneDX component with a scope reads as contained in its parent and, in a
// second edge, as its development dependency. Dropping only the second edge
// would leave the component where it was.
func WithoutEdgeTypes(types ...Edge_Type) FilterOption {
	return func(f *nodeListFilter) {
		for _, t := range types {
			f.edgeTypes[t] = struct{}{}
		}
	}
}

// WithoutEdgeGroups leaves out the relationships of every edge type of the
// given groups, as WithoutEdgeTypes does for the types it is handed:
// WithoutEdgeGroups(EdgeGroupDevelopment, EdgeGroupTest) leaves a graph
// without its development and test dependencies.
func WithoutEdgeGroups(groups ...EdgeGroup) FilterOption {
	types := []Edge_Type{}
	for _, g := range groups {
		types = append(types, g.EdgeTypes()...)
	}
	return WithoutEdgeTypes(types...)
}

// WithoutNodes leaves out the nodes match answers true for.
func WithoutNodes(match func(*Node) bool) FilterOption {
	return func(f *nodeListFilter) {
		if match != nil {
			f.nodes = append(f.nodes, match)
		}
	}
}

// WithoutPurlTypes leaves out the packages whose package URL is of one of the
// given types ("npm", "golang"). The empty type names the packages that have
// no package URL, or one that cannot be read. Files, which have no package
// URL to go by, are never matched.
func WithoutPurlTypes(types ...string) FilterOption {
	set := make(map[string]struct{}, len(types))
	for _, t := range types {
		set[strings.ToLower(t)] = struct{}{}
	}
	return WithoutNodes(func(n *Node) bool {
		if n.GetType() != Node_PACKAGE {
			return false
		}
		_, ok := set[n.Purl().Type()]
		return ok
	})
}

// relation is one pair of nodes an edge relates, read the way round the
// edge's type states it (see Edge_Type.Inverse).
type relation struct {
	owner, owned string
}

// relations lists the pairs of nodes the edge relates.
func (e *Edge) relations() []relation {
	rels := make([]relation, 0, len(e.To))
	for _, to := range e.To {
		if e.Type.Inverse() {
			rels = append(rels, relation{owner: to, owned: e.From})
		} else {
			rels = append(rels, relation{owner: e.From, owned: to})
		}
	}
	return rels
}

// Filter returns a new NodeList without the relationships and nodes the
// options leave out, and without what they alone held in the graph: a node
// the root elements reached before and no longer reach is dropped, with the
// edges that named it. A node that is still reached another way stays, and
// keeps everything below it.
//
// Paths are followed from each node to the nodes it owns, whichever way
// round the edge is stated: both "A dependsOn B" and "B dependencyOf A" lead
// from A to B (see Edge_Type.Inverse).
//
// Root elements are never dropped, whatever the options say. Nodes the root
// elements did not reach to begin with are left as they were, unless an
// option names them. Without options the result has the nodes, edges and
// root elements of the original.
//
// Nodes and edges keep their order. The nodes of the new list are those of
// the original, not copies of them; its edges are its own.
func (nl *NodeList) Filter(opts ...FilterOption) *NodeList {
	ret := NewNodeList()
	if nl == nil {
		return ret
	}

	f := &nodeListFilter{edgeTypes: map[Edge_Type]struct{}{}}
	for _, opt := range opts {
		opt(f)
	}

	removed := nl.filteredNodes(f)
	cut := nl.cutRelations(f)
	keep := func(r relation) bool {
		if _, ok := cut[r]; ok {
			return false
		}
		_, ownerGone := removed[r.owner]
		_, ownedGone := removed[r.owned]
		return !ownerGone && !ownedGone
	}

	// What the filters matched takes with it everything only it led to.
	before := nl.reachable(func(relation) bool { return true })
	after := nl.reachable(keep)
	for id := range before {
		if _, ok := after[id]; !ok {
			removed[id] = struct{}{}
		}
	}

	for _, n := range nl.Nodes {
		if _, ok := removed[n.Id]; !ok {
			ret.Nodes = append(ret.Nodes, n)
		}
	}
	ret.RootElements = append(ret.RootElements, nl.RootElements...)

	for _, e := range nl.Edges {
		if _, ok := removed[e.From]; ok {
			continue
		}
		kept := &Edge{Type: e.Type, From: e.From, To: []string{}}
		for _, r := range e.relations() {
			if !keep(r) {
				continue
			}
			if e.Type.Inverse() {
				kept.To = append(kept.To, r.owner)
			} else {
				kept.To = append(kept.To, r.owned)
			}
		}
		// An edge that lost all it pointed to says nothing anymore.
		if len(kept.To) == 0 && len(e.To) > 0 {
			continue
		}
		ret.Edges = append(ret.Edges, kept)
	}

	return ret
}

// filteredNodes returns the ids of the nodes the filter's node matchers name,
// leaving the root elements out.
func (nl *NodeList) filteredNodes(f *nodeListFilter) map[string]struct{} {
	removed := map[string]struct{}{}
	if len(f.nodes) == 0 {
		return removed
	}
	roots := nl.indexRootElements()
	for _, n := range nl.Nodes {
		if _, ok := roots[n.Id]; ok {
			continue
		}
		for _, match := range f.nodes {
			if match(n) {
				removed[n.Id] = struct{}{}
				break
			}
		}
	}
	return removed
}

// cutRelations returns the pairs of nodes an edge of a filtered type relates.
func (nl *NodeList) cutRelations(f *nodeListFilter) map[relation]struct{} {
	cut := map[relation]struct{}{}
	if len(f.edgeTypes) == 0 {
		return cut
	}
	for _, e := range nl.Edges {
		if _, ok := f.edgeTypes[e.Type]; !ok {
			continue
		}
		for _, r := range e.relations() {
			cut[r] = struct{}{}
		}
	}
	return cut
}

// reachable returns the ids of the nodes the root elements reach, following
// each relation keep admits from its owner to the node it owns.
func (nl *NodeList) reachable(keep func(relation) bool) map[string]struct{} {
	nodes := nl.indexNodes()
	owned := map[string][]string{}
	for _, e := range nl.Edges {
		for _, r := range e.relations() {
			if keep(r) {
				owned[r.owner] = append(owned[r.owner], r.owned)
			}
		}
	}

	reached := map[string]struct{}{}
	queue := []string{}
	visit := func(id string) {
		if _, ok := nodes[id]; !ok {
			return
		}
		if _, ok := reached[id]; ok {
			return
		}
		reached[id] = struct{}{}
		queue = append(queue, id)
	}

	for _, id := range nl.RootElements {
		visit(id)
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, child := range owned[id] {
			visit(child)
		}
	}
	return reached
}
