package sbom

// This file adds a few methods to the NodeList type which
// handles fragments of the SBOM graph.

// nodeIdList is an iverse dictionary to hold node identifiers
type nodeIdList map[string]struct{}

// indexIdentifiers returns an inverse dictionary with the IDs of thenodes
func (nl *NodeList) indexIdentifiers() nodeIdList {
	ret := nodeIdList{}
	for i := range nl.Nodes {
		ret[nl.Nodes[i].Id] = struct{}{}
	}
	return ret
}

// cleanEdges is a utility function that removes broken
// connection and orphaned edges
func (nl *NodeList) cleanEdges() {
	// First copy the nodelist edges
	newEdges := []*Edge{}

	// Build a catalog of the elements ids
	idDict := map[string]struct{}{}
	for i := range nl.Nodes {
		idDict[nl.Nodes[i].Id] = struct{}{}
	}

	// Now list all edges and rebuild the list
	for _, edge := range nl.Edges {
		newTos := []string{}
		if _, ok := idDict[edge.From]; !ok {
			continue
		}

		for _, s := range edge.To {
			if _, ok := idDict[s]; ok {
				newTos = append(newTos, s)
			}
		}

		if len(newTos) == 0 {
			continue
		}

		edge.To = newTos
		newEdges = append(newEdges, edge)
	}

	nl.Edges = newEdges
}

// Add combines NodeList nl2 into nl. It is te equivalent to Union but
// instead of retuirn a new NodeList modifies nl
func (nl *NodeList) Add(nl2 *NodeList) {
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

// Intersect returns a new NodeList with nodes which are common in nl and nl2.
func (nl *NodeList) Intersect(nl2 *NodeList) *NodeList {
	return nil
}

// Union returns a new NodeList with all nodes from nl and nl2 joined together
func (nl *NodeList) Union(nl2 *NodeList) *NodeList {
	return nil
}
