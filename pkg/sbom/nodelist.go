package sbom

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/google/go-cmp/cmp"
)

// This file adds a few methods to the NodeList type which
// handles fragments of the SBOM graph.

// nodeIndex is a dictionary of node pointers keyed by ID
type nodeIndex map[string]*Node

// edgeIndex is an index of edge pointers keyed by From elements and type
type edgeIndex map[string]map[Edge_Type][]*Edge

// rootElementsIndex is an index of the top level elements by ID
type rootElementsIndex map[string]struct{}

// hashIndex is a struct that indexes a NodeList by the hash values of its nodes
type hashIndex map[string][]*Node

// purlIndex captures the SBOM nodelist ordered by package url
type purlIndex map[PackageURL][]*Node

var ErrorMoreThanOneMatch = fmt.Errorf("more than one node matches")

// NewNodeList returns a new NodeList with empty nodes, edges, and root elements.
func NewNodeList() *NodeList {
	return &NodeList{
		Nodes:        []*Node{},
		Edges:        []*Edge{},
		RootElements: []string{},
	}
}

// indexNodes returns an inverse dictionary with the IDs of the nodes
func (nl *NodeList) indexNodes() nodeIndex {
	ret := nodeIndex{}
	for _, n := range nl.Nodes {
		ret[n.Id] = n
	}
	return ret
}

// indexEdges returns the edges of the nodeList indexed by from and type
func (nl *NodeList) indexEdges() edgeIndex {
	index := edgeIndex{}
	for i := range nl.Edges {
		if _, ok := index[nl.Edges[i].From]; !ok {
			index[nl.Edges[i].From] = map[Edge_Type][]*Edge{}
		}

		if _, ok := index[nl.Edges[i].From][nl.Edges[i].Type]; !ok {
			index[nl.Edges[i].From][nl.Edges[i].Type] = []*Edge{nl.Edges[i]}
			continue
		}
		index[nl.Edges[i].From][nl.Edges[i].Type] = append(index[nl.Edges[i].From][nl.Edges[i].Type], nl.Edges[i])
	}
	return index
}

// indexRootElements returns an index of the NodeList's top level elements by ID
func (nl *NodeList) indexRootElements() rootElementsIndex {
	index := rootElementsIndex{}
	for _, id := range nl.RootElements {
		index[id] = struct{}{}
	}
	return index
}

// indexNodesByHash returns an index of all nodes by their hash value.
// More than one node can have the same hash.
func (nl *NodeList) indexNodesByHash() hashIndex {
	ret := hashIndex{}
	for _, n := range nl.Nodes {
		for algo, hashVal := range n.Hashes {
			if hashVal == "" {
				continue
			}
			s := fmt.Sprintf("%d:%s", algo, hashVal)
			ret[s] = append(ret[s], n)
		}
	}
	return ret
}

// Returns an indexed map of nodes by their package URLs. Note that more than
// one node may have the same purl.
func (nl *NodeList) indexNodesByPurl() map[PackageURL][]*Node {
	ret := map[PackageURL][]*Node{}
	for _, n := range nl.Nodes {
		nodePurl := n.Purl()
		if nodePurl == "" {
			continue
		}

		ret[nodePurl] = append(ret[nodePurl], n)
	}
	return ret
}

// cleanEdges is a utility function that removes broken
// connection and orphaned edges
func (nl *NodeList) cleanEdges() {
	// Build a catalog of the elements ids
	nodeIndex := nl.indexNodes()

	// Add a seen cache to dedupe edges when
	// cleaning them up
	seenCache := map[string]*Edge{}
	newTos := map[string]map[string]string{}

	// Now list all edges and rebuild the list
	for _, edge := range nl.Edges {
		// If the from node is not in the index, skip it
		if _, ok := nodeIndex[edge.From]; !ok {
			continue
		}

		// Use a string key for a simpler datastruct
		edgeKey := edge.From + "+++" + edge.Type.String()
		if _, ok := newTos[edgeKey]; !ok {
			newTos[edgeKey] = map[string]string{}
		}

		// If we already saw an equivalent edge, reuse it
		if _, ok := seenCache[edgeKey]; !ok {
			seenCache[edgeKey] = &Edge{
				Type: edge.Type,
				From: edge.From,
				To:   []string{},
			}
		}

		for _, s := range edge.To {
			if _, ok := nodeIndex[s]; !ok {
				continue
			}
			newTos[edgeKey][s] = s
		}
	}

	newEdges := []*Edge{}
	for f := range seenCache {
		for s := range newTos[f] {
			seenCache[f].To = append(seenCache[f].To, s)
		}
		if len(seenCache[f].To) > 0 {
			newEdges = append(newEdges, seenCache[f])
		}
	}

	nl.Edges = newEdges
}

// AddEdge adds a new edge to the Node List.
func (nl *NodeList) AddEdge(e *Edge) {
	nl.Edges = append(nl.Edges, e)
}

// AddRootNode adds a node to the NodeList and registers it as a Root Elements.
// More than one root element can be added to the NodeList.
func (nl *NodeList) AddRootNode(n *Node) {
	if n.Id == "" {
		// TODO warn here
		return
	}

	for _, id := range nl.RootElements {
		if id == n.Id {
			// TODO warn here
			return
		}
	}

	nl.AddNode(n)
	nl.RootElements = append(nl.RootElements, n.Id)
}

// AddEdge adds a new node to the Node List.
func (nl *NodeList) AddNode(n *Node) {
	nl.Nodes = append(nl.Nodes, n)
}

// Add combines the nodes and edges from NodeList (nl2) into the current NodeList (nl).
// It modifies current NodeList (nl) by adding new roots, nodes and edges or updating existing ones.
// It is the equivalent to the Union of both NodeLists, but it modifies the current NodeList (nl) in place.
func (nl *NodeList) Add(nl2 *NodeList) {
	existingNodes := nl.indexNodes()
	for i := range nl2.Nodes {
		if n, ok := existingNodes[nl2.Nodes[i].Id]; ok {
			existingNodes[nl2.Nodes[i].Id].Augment(n)
		} else {
			nl.Nodes = append(nl.Nodes, nl2.Nodes[i])
		}
	}

	existingEdges := nl.indexEdges()
	for i := range nl2.Edges {
		if _, ok := existingEdges[nl2.Edges[i].From]; !ok {
			nl.Edges = append(nl.Edges, nl2.Edges[i])
			continue
		}

		if _, ok := existingEdges[nl2.Edges[i].From][nl2.Edges[i].Type]; !ok {
			nl.Edges = append(nl.Edges, nl2.Edges[i])
			continue
		}

		// Add it here to the existing edge
		existingEdges[nl2.Edges[i].From][nl2.Edges[i].Type][0].To = append(existingEdges[nl2.Edges[i].From][nl2.Edges[i].Type][0].To, nl2.Edges[i].To...)
	}

	rootElements := nl.indexRootElements()
	for _, id := range nl2.RootElements {
		if _, ok := rootElements[id]; !ok {
			nl.RootElements = append(nl.RootElements, id)
		}
	}

	nl.cleanEdges()
}

// RemoveNodes removes nodes with specified IDs from the NodeList.
// It also removes corresponding edges connected to the removed nodes.
func (nl *NodeList) RemoveNodes(ids []string) {
	// build an inverse dict of the IDs
	idDict := map[string]struct{}{}
	for _, i := range ids {
		idDict[i] = struct{}{}
	}

	newNodeList := []*Node{}
	for i := range nl.Nodes {
		if _, ok := idDict[nl.Nodes[i].Id]; !ok {
			newNodeList = append(newNodeList, nl.Nodes[i])
		}
	}

	nl.Nodes = newNodeList
	nl.cleanEdges()
}

// GetEdgeByType returns the first edge of the specified type (t) originating from the given node ID (fromElement).
// If no such edge is found, it returns nil.
func (nl *NodeList) GetEdgeByType(fromElement string, t Edge_Type) *Edge {
	for _, e := range nl.Edges {
		if e.From == fromElement && e.Type == t {
			return e
		}
	}
	return nil
}

// copyEdgeList is a utility function that deep copies a list of edges
func copyEdgeList(original []*Edge) []*Edge {
	edgeCopy := []*Edge{}
	for _, e := range original {
		edgeCopy = append(edgeCopy, e.Copy())
	}
	return edgeCopy
}

// copyNodeSlice is a utility function that deep copies a list of nodes
func copyNodeSlice(original []*Node) []*Node {
	nodeCopy := []*Node{}
	for _, n := range original {
		nodeCopy = append(nodeCopy, n.Copy())
	}
	return nodeCopy
}

// Copy returns a duplicate of the NodeList.
func (nl *NodeList) Copy() *NodeList {
	nlo := &NodeList{}

	nlo.Nodes = copyNodeSlice(nl.Nodes)
	nlo.Edges = copyEdgeList(nl.Edges)

	nlo.RootElements = append(nlo.RootElements, nl.RootElements...)

	return nlo
}

// Intersect returns a new NodeList that represents the intersection
// of nodes and their relationships between nl and nl2.
// The resulting NodeList contains common nodes and edges copied from nl, and updates them with data from nl2.
func (nl *NodeList) Intersect(nl2 *NodeList) *NodeList {
	rootElements := nl.indexRootElements()
	rootElements2 := nl2.indexRootElements()

	ret := &NodeList{
		Nodes:        []*Node{},
		Edges:        copyEdgeList(nl.Edges), // copied as they will be cleaned
		RootElements: []string{},
	}
	var ni1, ni2 nodeIndex

	ni1 = nl.indexNodes()
	ni2 = nl2.indexNodes()

	for id, node := range ni1 {
		if _, ok := ni2[id]; !ok {
			continue
		}
		// Clone the node
		newnode := node.Copy()
		newnode.Update(ni2[id])
		ret.Nodes = append(ret.Nodes, newnode)

		_, ok := rootElements[id]
		_, ok2 := rootElements2[id]

		if ok || ok2 {
			ret.RootElements = append(ret.RootElements, id)
		}
	}

	// Copy root elements
	for _, e := range nl2.Edges {
		existingEdge := ret.GetEdgeByType(e.From, e.Type)
		if existingEdge == nil {
			ret.Edges = append(ret.Edges, e.Copy())
		} else {
			// Apppend data to existing edge
			invDict := map[string]struct{}{}
			for _, t := range existingEdge.To {
				invDict[t] = struct{}{}
			}

			for _, to := range e.To {
				if _, ok := invDict[to]; !ok {
					existingEdge.To = append(existingEdge.To, to)
				}
			}
		}
	}

	// Clean edges
	ret.cleanEdges()

	return ret
}

// Union returns a new NodeList representing the combination of nodes and their relationships
// from nl and nl2.
// The resulting NodeList contains common nodes and edges copied from nl, and updates them with data from nl2.
func (nl *NodeList) Union(nl2 *NodeList) *NodeList {
	ret := &NodeList{
		Nodes:        []*Node{},
		Edges:        copyEdgeList(nl.Edges),
		RootElements: nl.RootElements,
	}

	// Copy all nodes from the original nodelist
	for _, n := range nl.Nodes {
		ret.Nodes = append(ret.Nodes, n.Copy())
	}

	// Now reindex to know which one to append or update
	nodeindex := ret.indexNodes()
	for _, n := range nl2.Nodes {
		if _, ok := nodeindex[n.Id]; ok {
			nodeindex[n.Id].Update(n)
		} else {
			ret.Nodes = append(ret.Nodes, n)
		}
	}

	// Add or append all edges from nl2
	for _, e := range nl2.Edges {
		existingEdge := ret.GetEdgeByType(e.From, e.Type)
		if existingEdge == nil {
			ret.Edges = append(ret.Edges, e.Copy())
		} else {
			for _, to := range e.To {
				if !existingEdge.PointsTo(to) {
					existingEdge.To = append(existingEdge.To, to)
				}
			}
		}
	}

	ret.cleanEdges()

	// Copy all root nodes from nl2
	rootNodes := ret.indexRootElements()
	for _, rootEl := range nl2.RootElements {
		if _, ok := rootNodes[rootEl]; !ok {
			ret.RootElements = append(ret.RootElements, rootEl)
		}
	}

	return ret
}

// GetNodesByName returns a list of node with the specified name.
func (nl *NodeList) GetNodesByName(name string) []*Node {
	ret := []*Node{}
	for i := range nl.Nodes {
		if nl.Nodes[i].Name == name {
			ret = append(ret, nl.Nodes[i])
		}
	}
	return ret
}

// GetNodeByID returns a node with the specified ID
func (nl *NodeList) GetNodeByID(id string) *Node {
	for i := range nl.Nodes {
		if nl.Nodes[i].Id == id {
			return nl.Nodes[i]
		}
	}

	return nil
}

// GetMatchingNode looks up a node in the NodeList (nl) that matches the software described the provided.
// Matching is performed based on hashes and, if necessary, by Package URL (PURL).
// This function guarantees a single-node match. If more than one node matches, an ErrorMoreThanOneMatch is returned.
//
// If the target node has hashes, it first looks for nodes with matching hashes.
// If exactly one node is found, the function returns it. If no nodes match by hash,
// it attempts to match based on the purl. If more than one node matches by purl, an error is returned.
// If multiple nodes match by hash, it looks for a single node where the purl also matches to break the ambiguity.
//
// See [Node.HashesMatch] for details on how hashes are compared.
func (nl *NodeList) GetMatchingNode(node *Node) (*Node, error) {
	// If the target node has hashes, look for it
	foundNodes := map[string]*Node{}
	if len(node.Hashes) > 0 {
		hashIndex := nl.indexNodesByHash()
		for algo, hashVal := range node.Hashes {
			// If there is at least one node with one of the hashes:
			if _, ok := hashIndex[fmt.Sprintf("%d:%s", algo, hashVal)]; !ok {
				continue
			}
			// Collect all node where hashes match exactly
			for _, n := range hashIndex[fmt.Sprintf("%d:%s", algo, hashVal)] {
				// Ignore if we've seen the node
				if _, ok := foundNodes[n.Id]; ok {
					continue
				}

				// Collect the node if hashes match
				if n.HashesMatch(node.Hashes) {
					foundNodes[n.Id] = n
				}
			}
		}
	}

	// Here, if we have exactly one node, then we have a match. If we have zero
	// then we reindex and match on the purl. If more than one node matched on
	// the hashes, we try to disambiguate by looking at the purl of the hash matches.
	testPurl := node.Purl()
	switch len(foundNodes) {
	case 1:
		// If there is a single match, our job is done.
		for _, n := range foundNodes {
			return n, nil
		}
	case 0:
		// No matches by hash, try to match by purl
		// TODO(puerco): Purls should be normalized to match correctly,
		// even more: ensuring correct globing of qualifiers.
		if testPurl == "" {
			return nil, nil
		}
		pindex := nl.indexNodesByPurl()
		if _, ok := pindex[testPurl]; !ok {
			return nil, nil
		}
		// If there is more than one matching, it's a tie. Error.
		if len(pindex[testPurl]) == 1 {
			return pindex[testPurl][0], nil
		}
		return nil, ErrorMoreThanOneMatch
	default:
		// Multiple hash matches, look to see if there is a single one where
		// the purl matches to break the ambiguity:
		if testPurl == "" {
			return nil, ErrorMoreThanOneMatch
		}

		foundByPurl := []*Node{}
		for _, n := range foundNodes {
			if tp := n.Purl(); tp != "" && tp == testPurl {
				foundByPurl = append(foundByPurl, n)
			}
		}

		if len(foundByPurl) == 1 {
			return foundByPurl[0], nil
		}
		return nil, ErrorMoreThanOneMatch
	}
	return nil, nil
}

// GetNodesByIdentifier returns a list of nodes that match the provided identifier type (t) and value (v).
// For example, the identifier type (t) can be "purl," and its value (v) can be "pkg:deb/debian/libpam-modules@1.4.0-9+deb11u1?arch=i386".
// The function may return an empty list if no nodes match the given identifier.
// Matching is based on simple string comparison.
func (nl *NodeList) GetNodesByIdentifier(t, v string) []*Node {
	ret := []*Node{}
	idType := SoftwareIdentifierTypeFromString(t)
	for i := range nl.Nodes {
		if nl.Nodes[i].Identifiers == nil {
			continue
		}

		if _, ok := nl.Nodes[i].Identifiers[int32(idType)]; ok && nl.Nodes[i].Identifiers[int32(idType)] == v {
			ret = append(ret, nl.Nodes[i])
		}
	}
	return ret
}

// GetRootNodes returns a list of the document root nodes.
func (nl *NodeList) GetRootNodes() []*Node {
	ret := []*Node{}
	index := rootElementsIndex{}
	for _, id := range nl.RootElements {
		index[id] = struct{}{}
	}
	for i := range nl.Nodes {
		if _, ok := index[nl.Nodes[i].Id]; ok {
			ret = append(ret, nl.Nodes[i])
			if len(ret) == len(index) {
				break
			}
		}
	}
	// TODO(ehandling): What if not all nodes were found?
	return ret
}

// Equal compares the current NodeList to another (n2) and returns true if they are identical.
func (nl *NodeList) Equal(nl2 *NodeList) bool {
	if nl2 == nil {
		return false
	}

	// First, quick one: Compare the lengths of the internals:
	if len(nl.Edges) != len(nl2.Edges) ||
		len(nl.Nodes) != len(nl2.Nodes) ||
		len(nl.RootElements) != len(nl2.RootElements) {
		return false
	}

	// Compare the flattened rootElements list
	r1 := nl.RootElements
	r2 := nl2.RootElements
	sort.Strings(r1)
	sort.Strings(r2)
	if !reflect.DeepEqual(r1, r2) {
		return false
	}

	// Compare the flattenned edges
	nlEdges := []string{}
	for _, e := range nl.Edges {
		nlEdges = append(nlEdges, e.flatString())
	}
	sort.Strings(nlEdges)

	nl2Edges := []string{}
	for _, e := range nl2.Edges {
		nl2Edges = append(nl2Edges, e.flatString())
	}
	sort.Strings(nl2Edges)

	if !reflect.DeepEqual(nlEdges, nl2Edges) {
		return false
	}

	// Compare the nodes
	nlNodes := map[string]string{}
	nl2Nodes := map[string]string{}
	for _, n := range nl.Nodes {
		nlNodes[n.Id] = n.Checksum()
	}

	for _, n := range nl2.Nodes {
		nl2Nodes[n.Id] = n.Checksum()
	}

	return cmp.Equal(nlNodes, nl2Nodes)
}

// RelateNodeAtID creates a relationship between the provided Node (n) and an existing node
// in the NodeList specified by ID (nodeID). If the targeted node (looked up by ID) does not
// exist in the Node List, it is added. If the specified nodeID does not exist,
// an error is returned.
func (nl *NodeList) RelateNodeAtID(n *Node, nodeID string, edgeType Edge_Type) error {
	// Check the node exists
	nlIndex := nl.indexNodes()
	nlEdges := nl.indexEdges()

	if _, ok := nlIndex[nodeID]; !ok {
		return fmt.Errorf("node with ID %s not found", nodeID)
	}

	// Check if we have edges matching
	var edge *Edge
	if _, ok := nlEdges[nodeID]; ok {
		if _, ok2 := nlEdges[nodeID][edgeType]; ok2 {
			edge = nlEdges[nodeID][edgeType][0]
		}
	}

	if edge == nil {
		edge = &Edge{
			Type: edgeType,
			From: nodeID,
			To:   []string{n.Id},
		}
		nl.Edges = append(nl.Edges, edge)
	} else {
		// Perhaps we should filter these
		edge.To = append(edge.To, n.Id)
	}

	// It the node does not exist in the nodelist, return
	if _, ok := nlIndex[n.Id]; !ok {
		nl.AddNode(n)
	}
	return nil
}

// RelateNodeListAtID relates nodes from the provided NodeList (nl2) at the top level to an existing node in this NodeList
// with the specified ID (nodeID) using a relationship of the given type (edgeType).
// It returns an error if ID cannot be found in the graph.
// Nodes with the same ID in both the current (nl) and provided (nl2) Node Lists
// are considered equivalent and will be deduplicated.
func (nl *NodeList) RelateNodeListAtID(nl2 *NodeList, nodeID string, edgeType Edge_Type) error {
	// Check the node exists
	nlIndex := nl.indexNodes()
	nlEdges := nl.indexEdges()

	if _, ok := nlIndex[nodeID]; !ok {
		return fmt.Errorf("node with ID %s not found", nodeID)
	}

	// Check if we have edges matching
	var edge *Edge
	if _, ok := nlEdges[nodeID]; ok {
		if _, ok2 := nlEdges[nodeID][edgeType]; ok2 {
			edge = nlEdges[nodeID][edgeType][0]
		}
	}

	if edge == nil {
		edge = &Edge{
			Type: edgeType,
			From: nodeID,
			To:   nl2.RootElements,
		}
		nl.Edges = append(nl.Edges, edge)
	} else {
		// Perhaps we should filter these
		edge.AddDestinationById(nl2.RootElements...)
	}

	for _, n := range nl2.Nodes {
		if _, ok := nlIndex[n.Id]; ok {
			continue
		}
		nl.AddNode(n)
	}

	// Copy the remaining edges from n2
	for _, e := range nl2.Edges {
		// Check if we have an edge of the samer type already in the
		// nodelist and if so, reuse it:
		if _, ok := nlEdges[e.From]; ok {
			if _, ok2 := nlEdges[e.From][e.Type]; ok2 {
				nlEdges[e.From][e.Type][0].AddDestinationById(e.To...)
				continue
			}
		}

		// If the node was not found, add a copy
		nl.Edges = append(nl.Edges, e.Copy())
	}

	return nil
}

// GetNodesByPurlType retrieves nodes with a specific Package URL type (purlType) from the current NodeList (nl).
// Returns a new NodeList with matching nodes and their relationships.
// If no nodes match, an empty NodeList is returned.
func (nl *NodeList) GetNodesByPurlType(purlType string) *NodeList {
	ret := &NodeList{}
	if nl == nil {
		return ret
	}

	for _, n := range nl.Nodes {
		// I think the SPDX libraries have a bug where an extra slash is added when parsing purls
		if strings.HasPrefix(string(n.Purl()), fmt.Sprintf("pkg:%s/", purlType)) ||
			strings.HasPrefix(string(n.Purl()), fmt.Sprintf("pkg:/%s/", purlType)) {
			ret.Nodes = append(ret.Nodes, n)
		}
	}

	index := ret.indexNodes()
	for _, e := range nl.Edges {
		if _, ok := index[e.From]; ok {
			ret.Edges = append(ret.Edges, e.Copy())
		}
	}

	ret.reconnectOrphanNodes()
	ret.cleanEdges()

	return ret
}

// reconnectOrphanNodes cleans the nodelist graph structure by reconnecting all
// orphaned nodes to the top of the nodelist
func (nl *NodeList) reconnectOrphanNodes() {
	edgeIndex := nl.indexEdges()
	rootIndex := nl.indexRootElements()

	for _, id := range nl.RootElements {
		rootIndex[id] = struct{}{}
	}

	for _, n := range nl.Nodes {
		if _, ok := edgeIndex[n.Id]; !ok {
			if _, ok := rootIndex[n.Id]; !ok {
				nl.RootElements = append(nl.RootElements, n.Id)
			}
		}
	}
}

// NodeGraph retruns a new NodeList representing the full dependency
// graph of the node identified by the provided ID. The method traverses the SBOM graph,
// adding all nodes connected to the specified ID.
// If no nodes match, an empty NodeList is returned.
func (nl *NodeList) NodeGraph(id string) *NodeList {
	nodelist := &NodeList{
		Nodes:        []*Node{},
		Edges:        []*Edge{},
		RootElements: []string{},
	}

	// Get the list of connected nodes
	graphIndex := nl.indexConnectedNodes(id)

	// Verify that the root is in the resulting index
	if _, ok := graphIndex[id]; !ok {
		return nil
	}

	edgeIdx := nl.indexEdges()
	for id, n := range graphIndex {
		// Add the node
		nodelist.AddNode(n)

		if _, ok := edgeIdx[id]; !ok {
			continue
		}

		for t := range edgeIdx[id] {
			nodelist.Edges = append(nodelist.Edges, edgeIdx[id][t]...)
		}
	}
	nodelist.RootElements = append(nodelist.RootElements, id)
	nodelist.cleanEdges()

	return nodelist
}

// indexConnectedNodes traverses the graph of NodeList nl and returns an index of
// nodes connected to id. Root nodes are considered boundaries and recursion will
// stop when reaching them.
func (nl *NodeList) indexConnectedNodes(id string) nodeIndex {
	index := nodeIndex{}
	node := nl.GetNodeByID(id)
	if node == nil {
		return index
	}

	index[id] = node

	boundaries := nl.indexRootElements()
	nl.connectedIndexRecursion(node.Id, &boundaries, &index)
	return index
}

// connectedIndexRecursion traverses the NodeList graph starting at id to
// populate the connectedNodes index stopping at the end of the edges or when
// it hits a node in the boundaries list.
func (nl *NodeList) connectedIndexRecursion(id string, boundaries *rootElementsIndex, connectedNodes *nodeIndex) {
	siblings := nl.NodeSiblings(id)
	for _, s := range siblings.Nodes {
		// If we've seen it, skip
		if _, ok := (*connectedNodes)[s.Id]; ok {
			continue
		}

		// If the node is in the boundaries list, skip
		if _, ok := (*boundaries)[s.Id]; ok {
			continue
		}

		(*connectedNodes)[s.Id] = s

		// Traverse the node path:
		nl.connectedIndexRecursion(s.Id, boundaries, connectedNodes)
	}
}

// NodeSiblings returns a new NodeList containing the specified node at the root
// and a graph fragment with its immediate siblings with their edges preserved.
// If no nodes match, an empty NodeList is returned.
func (nl *NodeList) NodeSiblings(id string) *NodeList {
	nodelist := &NodeList{}

	if id == "" {
		return nil
	}

	// Check that the node actually exists
	node := nl.GetNodeByID(id)
	if node == nil {
		return nodelist
	}

	nodelist.RootElements = append(nodelist.RootElements, node.Id)
	ni := nodeIndex{node.Id: node}
	for _, r := range nl.Edges {
		if r.From != id {
			continue
		}

		for _, to := range r.To {
			if _, ok := ni[to]; !ok {
				n := nl.GetNodeByID(to)
				if n == nil {
					continue
				}
				ni[to] = n
			}
		}

		nodelist.Edges = append(nodelist.Edges, r)
	}

	for _, n := range ni {
		nodelist.Nodes = append(nodelist.Nodes, n)
	}

	nodelist.cleanEdges()

	return nodelist
}

// NodeDescendants traverses the NodeList graph starting at the node specified
// by id and returns a new node list with elements related at a maximal distance
// of maxDepth levels. If the specified id is not found, the NodeList will be
// empty. Traversing the graph will stop if any of the related nodes is a RootNode.
func (nl *NodeList) NodeDescendants(id string, maxDepth int) *NodeList {
	rootIdx := nl.indexRootElements()
	edgeIdx := nl.indexEdges()
	startNode := nl.GetNodeByID(id)
	if startNode == nil {
		return &NodeList{}
	}

	nl2 := NodeList{
		Nodes:        []*Node{},
		Edges:        nl.Edges,
		RootElements: []string{startNode.Id},
	}

	siblings := nodeIndex{}

	var loopNodes []*Node
	newLoopNodes := []*Node{}

	for i := 0; i < maxDepth; i++ {
		if i == 0 {
			loopNodes = []*Node{startNode}
		} else {
			loopNodes = newLoopNodes
		}
		newLoopNodes = []*Node{}
		for _, n := range loopNodes {
			// If we've seen it, we're done
			if _, ok := siblings[n.Id]; ok {
				continue
			}

			siblings[n.Id] = n

			// If node has no relationships, we're done
			if _, ok := edgeIdx[n.Id]; !ok {
				continue
			}

			// If node is a root node, we're done
			if _, ok := rootIdx[n.Id]; ok && n.Id != id {
				continue
			}

			for et := range edgeIdx[n.Id] {
				for j := range edgeIdx[n.Id][et] {
					for _, siblingID := range edgeIdx[n.Id][et][j].To {
						if _, ok := siblings[siblingID]; ok {
							continue
						}

						sibling := nl.GetNodeByID(siblingID)
						if sibling != nil {
							newLoopNodes = append(newLoopNodes, sibling)
						}
					}
				}
			}
		}
	}

	// Assign found nodes to nodelist
	for _, n := range siblings {
		nl2.AddNode(n)
	}

	nl2.cleanEdges()
	return &nl2
}
