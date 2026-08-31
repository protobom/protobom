package sbom

import (
	"cmp"
	"maps"
	"slices"
	"time"

	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

type NodeDiff struct {
	Added     *Node
	Removed   *Node
	DiffCount int

	// Node1 and Node2 reference the pair of nodes the diff describes. They
	// are populated by NodeList.Diff, where a diff can belong to one of many
	// matched pairs; Node.Diff leaves them nil.
	Node1 *Node
	Node2 *Node
}

// Diff analyses a node and returns a a new node populated with all fields
// that are different in n2 from n. If no changes are found, Diff returns nil
func (n *Node) Diff(n2 *Node) *NodeDiff {
	nd := NodeDiff{
		Added:   &Node{},
		Removed: &Node{},
	}

	a, r, c := diff(n.Id, n2.Id)
	nd.Added.Id = a
	nd.Removed.Id = r
	nd.DiffCount += c

	if n.Type != n2.Type {
		nd.Added.Type = n2.Type
		nd.DiffCount++
	}

	a, r, c = diff(n.Name, n2.Name)
	nd.Added.Name = a
	nd.Removed.Name = r
	nd.DiffCount += c

	a, r, c = diff(n.Version, n2.Version)
	nd.Added.Version = a
	nd.Removed.Version = r
	nd.DiffCount += c

	a, r, c = diff(n.FileName, n2.FileName)
	nd.Added.FileName = a
	nd.Removed.FileName = r
	nd.DiffCount += c

	a, r, c = diff(n.UrlHome, n2.UrlHome)
	nd.Added.UrlHome = a
	nd.Removed.UrlHome = r
	nd.DiffCount += c

	a, r, c = diff(n.UrlDownload, n2.UrlDownload)
	nd.Added.UrlDownload = a
	nd.Removed.UrlDownload = r
	nd.DiffCount += c

	a, r, c = diff(n.LicenseConcluded, n2.LicenseConcluded)
	nd.Added.LicenseConcluded = a
	nd.Removed.LicenseConcluded = r
	nd.DiffCount += c

	a, r, c = diff(n.LicenseComments, n2.LicenseComments)
	nd.Added.LicenseComments = a
	nd.Removed.LicenseComments = r
	nd.DiffCount += c

	a, r, c = diff(n.Copyright, n2.Copyright)
	nd.Added.Copyright = a
	nd.Removed.Copyright = r
	nd.DiffCount += c

	a, r, c = diff(n.SourceInfo, n2.SourceInfo)
	nd.Added.SourceInfo = a
	nd.Removed.SourceInfo = r
	nd.DiffCount += c

	ap, rp, cp := diffSlice(n.PrimaryPurpose, n2.PrimaryPurpose)
	nd.Added.PrimaryPurpose = ap
	nd.Removed.PrimaryPurpose = rp
	nd.DiffCount += cp

	a, r, c = diff(n.Comment, n2.Comment)
	nd.Added.Comment = a
	nd.Removed.Comment = r
	nd.DiffCount += c

	a, r, c = diff(n.Summary, n2.Summary)
	nd.Added.Summary = a
	nd.Removed.Summary = r
	nd.DiffCount += c

	a, r, c = diff(n.Description, n2.Description)
	nd.Added.Description = a
	nd.Removed.Description = r
	nd.DiffCount += c

	addedD, removedD, count := diffDates(n.ReleaseDate, n2.ReleaseDate)
	nd.Added.ReleaseDate = addedD
	nd.Removed.ReleaseDate = removedD
	nd.DiffCount += count

	addedD, removedD, count = diffDates(n.BuildDate, n2.BuildDate)
	nd.Added.BuildDate = addedD
	nd.Removed.BuildDate = removedD
	nd.DiffCount += count

	addedD, removedD, count = diffDates(n.ValidUntilDate, n2.ValidUntilDate)
	nd.Added.ValidUntilDate = addedD
	nd.Removed.ValidUntilDate = removedD
	nd.DiffCount += count

	added, removed, count := diffSlice(n.Licenses, n2.Licenses)
	nd.Added.Licenses = added
	nd.Removed.Licenses = removed
	nd.DiffCount += count

	added, removed, count = diffSlice(n.Attribution, n2.Attribution)
	nd.Added.Attribution = added
	nd.Removed.Attribution = removed
	nd.DiffCount += count

	added, removed, count = diffSlice(n.FileTypes, n2.FileTypes)
	nd.Added.FileTypes = added
	nd.Removed.FileTypes = removed
	nd.DiffCount += count

	addedP, removedP, count := diffList(n.Suppliers, n2.Suppliers)
	nd.Added.Suppliers = addedP
	nd.Removed.Suppliers = removedP
	nd.DiffCount += count

	addedP, removedP, count = diffList(n.Originators, n2.Originators)
	nd.Added.Originators = addedP
	nd.Removed.Originators = removedP
	nd.DiffCount += count

	addedER, removedER, count := diffList(n.ExternalReferences, n2.ExternalReferences)
	nd.Added.ExternalReferences = addedER
	nd.Removed.ExternalReferences = removedER
	nd.DiffCount += count

	addedM, removedM, count := diffMap(n.Identifiers, n2.Identifiers)
	nd.Added.Identifiers = addedM
	nd.Removed.Identifiers = removedM
	nd.DiffCount += count

	addedM, removedM, count = diffMap(n.Hashes, n2.Hashes)
	nd.Added.Hashes = addedM
	nd.Removed.Hashes = removedM
	nd.DiffCount += count

	addedPr, removedPr, count := diffList(n.Properties, n2.Properties)
	nd.Added.Properties = addedPr
	nd.Removed.Properties = removedPr
	nd.DiffCount += count

	if nd.DiffCount > 0 {
		return &nd
	}
	return nil
}

// NodeListDiff captures the differences between two NodeLists. Nodes present
// in only one of the lists are collected in Added and Removed. Nodes found in
// both lists whose data differs are captured as NodeDiffs in Modified. Edge
// and root element changes are expressed in the ID space of the NodeList the
// diff was computed from (the receiver of NodeList.Diff).
type NodeListDiff struct {
	Added    []*Node
	Removed  []*Node
	Modified []*NodeDiff

	EdgesAdded   []*Edge
	EdgesRemoved []*Edge

	RootElementsAdded   []string
	RootElementsRemoved []string

	// DiffCount totals the changes in the report: one per added or removed
	// node, edge delta and root element change, plus the DiffCount of each
	// modified node.
	DiffCount int
}

// Diff compares the NodeList to another (nl2) and returns a NodeListDiff
// describing the changes that transform nl into nl2. If the lists are
// equivalent, Diff returns nil. A nil nl2 is treated as an empty NodeList.
//
// Nodes are paired across the two lists first by ID and then, for nodes
// without an ID match, by software identity using [NodeList.GetMatchingNode]
// (hashes, then purl). A node that matches more than one candidate is left
// unpaired and reported as added or removed rather than guessing a pair.
// Paired nodes with differing data are reported as [NodeDiff] entries in
// Modified, with Node1 and Node2 pointing to the paired nodes.
//
// Edges are compared per source node and edge type after translating the IDs
// of paired nodes in nl2 into their equivalents in nl. The edges in the
// report carry only the destinations that changed. Root element changes are
// reported the same way, in the receiver's ID space.
func (nl *NodeList) Diff(nl2 *NodeList) *NodeListDiff {
	if nl2 == nil {
		nl2 = &NodeList{}
	}

	d := &NodeListDiff{
		Added:        []*Node{},
		Removed:      []*Node{},
		Modified:     []*NodeDiff{},
		EdgesAdded:   []*Edge{},
		EdgesRemoved: []*Edge{},
	}

	// Pair the nodes of the two lists, first by ID:
	pairs := map[string]*Node{}
	matched2 := map[string]struct{}{}
	index2 := nl2.indexNodes()
	for _, n := range nl.Nodes {
		if n2, ok := index2[n.Id]; ok {
			pairs[n.Id] = n2
			matched2[n2.Id] = struct{}{}
		}
	}

	// ...then by software identity. Only nodes not already paired are
	// eligible and each node can be claimed by a single pair.
	remaining := &NodeList{}
	for _, n2 := range nl2.Nodes {
		if _, ok := matched2[n2.Id]; !ok {
			remaining.Nodes = append(remaining.Nodes, n2)
		}
	}
	for _, n := range nl.Nodes {
		if _, ok := pairs[n.Id]; ok {
			continue
		}
		// An ambiguous match (ErrorMoreThanOneMatch) leaves the node
		// unpaired to be reported as added and removed.
		n2, err := remaining.GetMatchingNode(n)
		if err != nil || n2 == nil {
			continue
		}
		pairs[n.Id] = n2
		matched2[n2.Id] = struct{}{}
		for i := range remaining.Nodes {
			if remaining.Nodes[i].Id == n2.Id {
				remaining.Nodes = slices.Delete(remaining.Nodes, i, i+1)
				break
			}
		}
	}

	// Classify the nodes based on the pairings:
	for _, n := range nl.Nodes {
		n2, ok := pairs[n.Id]
		if !ok {
			d.Removed = append(d.Removed, n)
			continue
		}
		if nd := n.Diff(n2); nd != nil {
			nd.Node1 = n
			nd.Node2 = n2
			d.Modified = append(d.Modified, nd)
			d.DiffCount += nd.DiffCount
		}
	}
	for _, n2 := range nl2.Nodes {
		if _, ok := matched2[n2.Id]; !ok {
			d.Added = append(d.Added, n2)
		}
	}

	// Translation map from nl2's ID space to the receiver's
	idmap := map[string]string{}
	for id1, n2 := range pairs {
		idmap[n2.Id] = id1
	}

	d.EdgesAdded, d.EdgesRemoved = diffEdges(nl.Edges, nl2.Edges, idmap)

	roots2 := make([]string, 0, len(nl2.RootElements))
	for _, id := range nl2.RootElements {
		roots2 = append(roots2, translateID(idmap, id))
	}
	d.RootElementsAdded, d.RootElementsRemoved, _ = diffSlice(nl.RootElements, roots2)

	d.DiffCount += len(d.Added) + len(d.Removed) +
		len(d.EdgesAdded) + len(d.EdgesRemoved) +
		len(d.RootElementsAdded) + len(d.RootElementsRemoved)

	if d.DiffCount > 0 {
		return d
	}
	return nil
}

// edgeSourceKey identifies a group of edge destinations by origin and type
type edgeSourceKey struct {
	from     string
	edgeType Edge_Type
}

// diffEdges compares two edge lists and returns the added and removed
// relationships. Edges are compared per source node and type, so the returned
// edges carry only the destinations that changed. IDs in edges2 are
// translated through idmap before comparing.
func diffEdges(edges1, edges2 []*Edge, idmap map[string]string) (added, removed []*Edge) {
	added = []*Edge{}
	removed = []*Edge{}

	agg1 := aggregateEdges(edges1, nil)
	agg2 := aggregateEdges(edges2, idmap)

	keys := slices.Collect(maps.Keys(agg1))
	for k := range agg2 {
		if _, ok := agg1[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.SortFunc(keys, func(a, b edgeSourceKey) int {
		return cmp.Or(
			cmp.Compare(a.from, b.from),
			cmp.Compare(a.edgeType, b.edgeType),
		)
	})

	for _, k := range keys {
		addedTos := []string{}
		removedTos := []string{}
		for to := range agg2[k] {
			if _, ok := agg1[k][to]; !ok {
				addedTos = append(addedTos, to)
			}
		}
		for to := range agg1[k] {
			if _, ok := agg2[k][to]; !ok {
				removedTos = append(removedTos, to)
			}
		}
		if len(addedTos) > 0 {
			slices.Sort(addedTos)
			added = append(added, &Edge{From: k.from, Type: k.edgeType, To: addedTos})
		}
		if len(removedTos) > 0 {
			slices.Sort(removedTos)
			removed = append(removed, &Edge{From: k.from, Type: k.edgeType, To: removedTos})
		}
	}
	return added, removed
}

// aggregateEdges collapses a list of edges into destination sets indexed by
// source node and edge type, translating IDs through idmap.
func aggregateEdges(edges []*Edge, idmap map[string]string) map[edgeSourceKey]map[string]struct{} {
	agg := map[edgeSourceKey]map[string]struct{}{}
	for _, e := range edges {
		k := edgeSourceKey{from: translateID(idmap, e.From), edgeType: e.Type}
		if _, ok := agg[k]; !ok {
			agg[k] = map[string]struct{}{}
		}
		for _, to := range e.To {
			agg[k][translateID(idmap, to)] = struct{}{}
		}
	}
	return agg
}

// translateID returns the equivalent of id in the ID space idmap translates
// to, or id itself when it has no translation.
func translateID(idmap map[string]string, id string) string {
	if tid, ok := idmap[id]; ok {
		return tid
	}
	return id
}

type Flattenable interface {
	flatString() string
}

func diffList[T Flattenable](list1, list2 []T) (added, removed []T, count int) {
	added = []T{}
	removed = []T{}

	idx1 := map[string]T{}
	idx2 := map[string]T{}

	for _, el := range list1 {
		flatStr := el.flatString()
		idx1[flatStr] = el
	}
	for _, el := range list2 {
		flatStr := el.flatString()
		idx2[flatStr] = el
	}

	for _, el := range list2 {
		flatStr := el.flatString()
		if _, ok := idx1[flatStr]; !ok {
			added = append(added, el)
		}
	}

	for _, el := range list1 {
		flatStr := el.flatString()
		if _, ok := idx2[flatStr]; !ok {
			removed = append(removed, el)
		}
	}

	if len(added) > 0 || len(removed) > 0 {
		count = 1
	}
	return added, removed, count
}

func diff[T comparable](v1, v2 T) (added, removed T, count int) {
	// Check if v1 and v2 are equal
	if v1 == v2 {
		var zero T // Initialize a zero value of type T
		return zero, zero, 0
	}

	// Check if v2 is a zero value
	var zero T
	if v2 == zero {
		return zero, v1, 1
	}
	return v2, zero, 1
}

// diffDates takes two dates, compares them and returns d2 in added if there is
// a change, s1 in removed if d2 is nil. count will be 1 if there was a change.
func diffDates(dt1, dt2 *timestamppb.Timestamp) (added, removed *timestamppb.Timestamp, count int) {
	var d1, d2 *time.Time
	if dt1 != nil {
		da1 := dt1.AsTime()
		d1 = &da1
	}
	if dt2 != nil {
		da2 := dt2.AsTime()
		d2 = &da2
	}
	if (d1 != nil && d2 != nil && d1.Unix() != d2.Unix()) || (d1 == nil && d2 != nil) {
		return dt2, nil, 1
	} else if d1 != nil && d2 == nil {
		return nil, dt1, 1
	}
	return nil, nil, 0
}

// diffMap compares two maps and returns what was added and removed
func diffMap[K comparable, V comparable](map1, map2 map[K]V) (added, removed map[K]V, count int) {
	added = make(map[K]V)
	removed = make(map[K]V)

	for k, v2 := range map2 {
		if v1, ok := map1[k]; ok {
			if v1 != v2 {
				added[k] = v2
			}
		} else {
			added[k] = v2
		}
	}

	for k, v1 := range map1 {
		if _, ok := map2[k]; !ok {
			removed[k] = v1
		}
	}

	if len(added) > 0 || len(removed) > 0 {
		count = 1
	}
	return added, removed, count
}

// diffSlice compares two slices and returns what was added and removed
func diffSlice[T comparable](arr1, arr2 []T) (added, removed []T, count int) {
	added = []T{}
	removed = []T{}

	for _, s := range arr2 {
		if !contains(arr1, s) {
			added = append(added, s)
		}
	}

	for _, s := range arr1 {
		if !contains(arr2, s) {
			removed = append(removed, s)
		}
	}

	if len(added) > 0 || len(removed) > 0 {
		count = 1
	}
	return added, removed, count
}

// contains checks if a slice contains a specific element
func contains[T comparable](s []T, e T) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
