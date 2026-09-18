package sbom

import (
	"fmt"
	"slices"
)

// NodeIdentity reports whether two nodes describe the same component. It
// decides which nodes Dedupe collapses.
type NodeIdentity func(a, b *Node) bool

// SameComponent is the default NodeIdentity. Two nodes are the same
// component when they are of the same type and either share a hash under
// some algorithm with no hash disagreeing under another, or, when they
// share no hash algorithm at all, carry the same non-empty purl. A
// disagreeing hash is final: no purl overrides it. Nodes with neither
// hashes nor a purl are never the same component.
func SameComponent(a, b *Node) bool {
	if a == nil || b == nil || a.GetType() != b.GetType() {
		return false
	}
	shared := false
	for algo, av := range a.GetHashes() {
		bv, ok := b.GetHashes()[algo]
		if !ok || av == "" || bv == "" {
			continue
		}
		if av != bv {
			return false
		}
		shared = true
	}
	if shared {
		return true
	}
	ap := a.GetIdentifiers()[int32(SoftwareIdentifierType_PURL)]
	bp := b.GetIdentifiers()[int32(SoftwareIdentifierType_PURL)]
	return ap != "" && ap == bp
}

// Dedupe collapses the nodes that same reports to be one component into a
// single node each, in place. Of each group the first node in list order
// survives and absorbs the others' data (see Node.Absorb). Every edge and
// root reference to a dropped node now names
// the survivor; edges that became duplicates or self-references are
// removed. A nil same means SameComponent.
//
// Identity need not be transitive, and Dedupe never lets a node bridge two
// that are not the same: a node joins a group only when its hashes
// conflict with none of the group's members. The mapping from dropped ids
// to the surviving ids is returned.
func (nl *NodeList) Dedupe(same NodeIdentity) map[string]string {
	if same == nil {
		same = SameComponent
	}
	nodes := nl.GetNodes()

	// Union-find over node indices, with the member list of every set so
	// that a candidate can be checked against all of them.
	parent := make([]int, len(nodes))
	members := make(map[int][]int, len(nodes))
	for i := range nodes {
		parent[i] = i
		members[i] = []int{i}
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra == rb {
			return
		}
		// The lowest index leads, so the first node in list order survives.
		if ra > rb {
			ra, rb = rb, ra
		}
		parent[rb] = ra
		members[ra] = append(members[ra], members[rb]...)
		delete(members, rb)
	}
	compatible := func(i, set int) bool {
		for _, m := range members[set] {
			if nodes[i].HashesConflict(nodes[m]) {
				return false
			}
		}
		return true
	}

	// Candidates share a hash value or a purl; same has the last word on
	// each pair.
	groups := map[string][]int{}
	for i, n := range nodes {
		for algo, v := range n.GetHashes() {
			if v != "" {
				key := fmt.Sprintf("h:%d:%s", algo, v)
				groups[key] = append(groups[key], i)
			}
		}
		if p := n.GetIdentifiers()[int32(SoftwareIdentifierType_PURL)]; p != "" {
			groups["p:"+p] = append(groups["p:"+p], i)
		}
	}
	for _, group := range groups {
		for _, i := range group[1:] {
			for _, j := range group {
				if j == i || find(i) == find(j) {
					break
				}
				if same(nodes[j], nodes[i]) && compatible(i, find(j)) && compatible(j, find(i)) {
					union(j, i)
					break
				}
			}
		}
	}

	dropped := map[string]string{}
	for i, n := range nodes {
		if lead := find(i); lead != i {
			nodes[lead].Absorb(n)
			dropped[n.GetId()] = nodes[lead].GetId()
		}
	}
	if len(dropped) == 0 {
		return dropped
	}

	kept := make([]*Node, 0, len(nodes)-len(dropped))
	for _, n := range nodes {
		if _, gone := dropped[n.GetId()]; !gone {
			kept = append(kept, n)
		}
	}
	nl.Nodes = kept

	remap := func(id string) string {
		if to, ok := dropped[id]; ok {
			return to
		}
		return id
	}
	edges := nl.GetEdges()
	nl.Edges = nil
	for _, e := range edges {
		from := remap(e.GetFrom())
		to := make([]string, 0, len(e.GetTo()))
		for _, t := range e.GetTo() {
			if t = remap(t); t != from && !slices.Contains(to, t) {
				to = append(to, t)
			}
		}
		if len(to) > 0 {
			nl.MergeEdges([]*Edge{{From: from, Type: e.GetType(), To: to}})
		}
	}
	roots := make([]string, 0, len(nl.GetRootElements()))
	for _, r := range nl.GetRootElements() {
		if r = remap(r); !slices.Contains(roots, r) {
			roots = append(roots, r)
		}
	}
	nl.RootElements = roots
	return dropped
}
