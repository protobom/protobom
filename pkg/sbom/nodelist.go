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
}

// RemoveNodes removes a list of nodes and its edges from the nodelist
func (nl *NodeList) RemoveNodes(...*Node) {
}

// Intersect returns a new NodeList with nodes which are common in nl and nl2
func (nl *NodeList) Intersect(nl2 *NodeList) *NodeList {

}

// Union returns a new NodeList with all nodes from nl and nl2 joined together
func (nl *NodeList) Union(nl2 *NodeList) *NodeList {

}
