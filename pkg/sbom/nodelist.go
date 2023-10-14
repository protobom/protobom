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

// rootElementsIndex is an index of the top levele elements by ID
type rootElementsIndex map[string]struct{}

// hashIndex is a struct that indexes a NodeList by the hash values of its nodes
type hashIndex map[string][]*Node

// purlIndex captures the SBOM nodelist ordered by package url
type purlIndex map[PackageURL][]*Node

var ErrorMoreThanOneMatch = fmt.Errorf("More than one node matches")

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

func (nl *NodeList) AddEdge(e *Edge) {
	nl.Edges = append(nl.Edges, e)
}

// AddRootNode adds a node to the nodelist and alos registers it to the
// RootElements list.
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

func (nl *NodeList) AddNode(n *Node) {
	nl.Nodes = append(nl.Nodes, n)
}

// Add combines NodeList nl2 into nl. It is the equivalent to Union but
// instead of returning a new NodeList it modifies nl.
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

// RemoveNodes removes a list of nodes and its edges from the nodelist
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

// GetEdgeByType returns a pointer to the first edge found from fromElement
// of type t.
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
	nodeCopy := []*Edge{}
	for _, e := range original {
		nodeCopy = append(nodeCopy, e.Copy())
	}
	return nodeCopy
}

// Intersect returns a new NodeList with nodes which are common in nl and nl2.
// All common nodes will be copied from nl and then `Update`d with data from nl2
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

// Union returns a new NodeList with all nodes from nl and nl2 joined together
// any nodes common in nl also found in nl2 will be `Update`d from data from the
// former.
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

// GetNodesByName returns a list of node pointers whose name equals name
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

// GetMatchingNode looks up a node in the NodeList that matches the piece of
// software described by testNode. It will not match on ID but rather matching
// is performed by hash then by purl.
//
// This function is guaranteed to only return a node when there is a single node
// match. If more than one node matches, an ErrorMoreThanOneMatch is returned.
//
// See node.HashesMatch to understand how hashes are compared.
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
			// Collect all node where hashes match excactly
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
	// the hashes, we try to disabiguate by looking at the purl of the hash matches.
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
		// If there is more than one matching, its a tie. Error.
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

// GetNodesByIdentifier returns nodes that match an identifier of type t and
// value v, for example t = "purl" v = "pkg:deb/debian/libpam-modules@1.4.0-9+deb11u1?arch=i386"
// Not that this only does "dumb" string matching no assumptions are made on the
// identifier type.
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

// GetRootNodes returns a list of pointers of the root nodes of the document
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

// Equal returns true if the NodeList nl is equal to nl2
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

// RelateNodeListAtID relates the top level nodes in nl2 to the node with ID
// nodeID using a relationship of type edgeType. Returns an error if nodeID cannot
// be found in the graph. This function assumes that nodes in nl and nl2 having
// the same ID are equivalent and will be deduped.
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
		edge.To = append(edge.To, nl2.RootElements...)
	}

	for _, n := range nl2.Nodes {
		if _, ok := nlIndex[n.Id]; ok {
			continue
		}
		nl.AddNode(n)
	}

	return nil
}

// GetNodesByPurlType returns a nodelist containing all nodes that match
// a purl (package url) type. An empty purlType returns a blank nodelist
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

// NodeGraph looks for node id and returns a new NodeList with its full dependency
// graph. NodeGraph will traverse the SBOM graph and add all nodes connected to id.
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

// NodeSiblings takes a node identifier `id` and returns a NodeList with the node
// at the top and the immediate siblings that are related to it.
func (nl *NodeList) NodeSiblings(id string) *NodeList {
	nodelist := &NodeList{}

	if id == "" {
		return nil
	}

	// Check that the node actually esists
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
