package sbom

// This file adds a few methods to the NodeList type which
// handles fragments of the SBOM graph.

// nodeIndex is a dictionary of node pointers keyed by ID
type nodeIndex map[string]*Node

// edgeIndex is an index of edge pointers keyed by From elements and type
type edgeIndex map[string]map[Edge_Type][]*Edge

// rootElementsIndex is an index of the top levele elements by ID
type rootElementsIndex map[string]struct{}

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

// cleanEdges is a utility function that removes broken
// connection and orphaned edges
func (nl *NodeList) cleanEdges() {
	// First copy the nodelist edges
	newEdges := []*Edge{}

	// Build a catalog of the elements ids
	nodeIndex := nl.indexNodes()

	// Add a seen cache to dedupe edges when
	// cleaning them up
	seenCache := map[string]map[Edge_Type]*Edge{}
	var seenEdge bool
	// Now list all edges and rebuild the list
	for _, edge := range nl.Edges {
		newTos := []string{}
		oldTos := []string{}

		// If the from node is not in the index, skip it
		if _, ok := nodeIndex[edge.From]; !ok {
			continue
		}

		// If we already saw an equivalent edge, reuse it
		seenEdge = false
		if _, ok := seenCache[edge.From]; ok {
			if _, ok2 := seenCache[edge.From][edge.Type]; ok2 {
				oldTos = edge.To
				edge = seenCache[edge.From][edge.Type]
				seenEdge = true
			}
		} else {
			seenCache[edge.From] = map[Edge_Type]*Edge{}
		}
		seenCache[edge.From][edge.Type] = edge

		for _, s := range edge.To {
			if _, ok := nodeIndex[s]; ok {
				newTos = append(newTos, s)
			}
		}

		newTos = append(newTos, oldTos...)

		if len(newTos) == 0 {
			continue
		}

		edge.To = newTos
		if !seenEdge {
			newEdges = append(newEdges, edge)
		}
	}

	nl.Edges = newEdges
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
func copyEdgeList(original []*Edge) (copy []*Edge) {
	copy = []*Edge{}
	for _, e := range original {
		copy = append(copy, e.Copy())
	}
	return copy
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

// GetNodesByIdentifier returns nodes that match an identifier of type t and
// value v, for example t = "purl" v = "pkg:deb/debian/libpam-modules@1.4.0-9+deb11u1?arch=i386"
// Not that this only does "dumb" string matching no assumptions are made on the
// identifer type.
func (nl *NodeList) GetNodesByIdentifier(t, v string) []*Node {
	ret := []*Node{}
	for i := range nl.Nodes {
		if nl.Nodes[i].Identifiers == nil {
			continue
		}

		for j := range nl.Nodes[i].Identifiers {
			if nl.Nodes[i].Identifiers[j].Type == t && nl.Nodes[i].Identifiers[j].Value == v {
				ret = append(ret, nl.Nodes[i])
			}
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
