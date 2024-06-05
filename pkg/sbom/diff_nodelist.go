package sbom

import (
	"sort"
	"strings"
)

// NodeListDiff represents the difference between two lists NodeLists.
type NodeListDiff struct {
	Nodes        NodeSetDiff
	Edges        EdgeSetDiff
	RootElements RootElementsDiff
}

func (nlDiff *NodeListDiff) AddedNodeList() *NodeList {
	var addedNodeList NodeList
	for _, addedNode := range nlDiff.Nodes.Added {
		addedNodeList.AddNode(addedNode)
	}
	for _, addedEdge := range nlDiff.Edges.Added {
		addedNodeList.AddEdge(addedEdge)
	}
	addedNodeList.RootElements = append(addedNodeList.RootElements, nlDiff.RootElements.Added...)

	for _, diffNodeAdded := range nlDiff.Nodes.NodeDiff {
		addedNodeList.AddNode(diffNodeAdded.Added)
	}

	return &addedNodeList
}

func (nlDiff *NodeListDiff) RemovedNodeList() *NodeList {
	var removedNodeList NodeList
	for _, removedNode := range nlDiff.Nodes.Removed {
		removedNodeList.AddNode(removedNode)
	}
	for _, removedEdge := range nlDiff.Edges.Removed {
		removedNodeList.AddEdge(removedEdge)
	}
	removedNodeList.RootElements = append(removedNodeList.RootElements, nlDiff.RootElements.Removed...)

	for _, diffNodeRemoved := range nlDiff.Nodes.NodeDiff {
		removedNodeList.AddNode(diffNodeRemoved.Removed)
	}

	return &removedNodeList
}

// NodeSetDiff represents the differences between two NodeList nodes.
type NodeSetDiff struct {
	Added    []*Node
	Removed  []*Node
	NodeDiff []*NodeDiff
}

// EdgeSetDiff represents the differences between two NodeList edges.
type EdgeSetDiff struct {
	Added   []*Edge
	Removed []*Edge
}

// NodeListRootElementDiff represents the differences between two NodeLists root elements.
type RootElementsDiff struct {
	Added   []string
	Removed []string
}

// Diff analyses a NodeList and returns a NodeList populated with all fields
// that are different in nl2 from nl.
func (nl *NodeList) Diff(nl2 *NodeList) NodeListDiff {
	return NodeListDiff{
		Nodes:        nl.diffNodes(nl2),
		Edges:        nl.diffEdges(nl2),
		RootElements: nl.diffRootElements(nl2),
	}
}

// diffRootElements computes the differences in root elements between two NodeLists.
func (nl *NodeList) diffRootElements(nl2 *NodeList) RootElementsDiff {
	diff := RootElementsDiff{}

	nlRoots := nl.indexRootElements()
	nl2Roots := nl2.indexRootElements()

	// Compare root elements and populate the diff
	for root := range nlRoots {
		if _, exists := nl2Roots[root]; !exists {
			diff.Removed = append(diff.Removed, root)
		}
	}
	for root := range nl2Roots {
		if _, exists := nlRoots[root]; !exists {
			diff.Added = append(diff.Added, root)
		}
	}

	sort.Strings(diff.Added)
	sort.Strings(diff.Removed)

	return diff
}

func (nl *NodeList) diffNodes(nl2 *NodeList) NodeSetDiff {
	diff := NodeSetDiff{}

	nlNodes := nl.Nodes
	nl2Nodes := nl2.Nodes

	// Sort both node lists
	sort.Slice(nlNodes, func(i, j int) bool {
		return strings.Compare(nlNodes[i].Id, nlNodes[j].Id) <= 0
	})
	sort.Slice(nl2Nodes, func(i, j int) bool {
		return strings.Compare(nl2Nodes[i].Id, nl2Nodes[j].Id) <= 0
	})

	index1, index2 := 0, 0

	// Iterate through both sorted node lists
	for index1 < len(nlNodes) || index2 < len(nl2Nodes) {
		switch {
		case index1 < len(nlNodes) && index2 < len(nl2Nodes):
			n, n2 := nlNodes[index1], nl2Nodes[index2]
			switch strings.Compare(n.Id, n2.Id) { // Use ID to decide if to compare
			case 0: // Nodes are equal
				index1++
				index2++
				nodeDiff := n.Diff(n2)
				if nodeDiff != nil {
					diff.NodeDiff = append(diff.NodeDiff, nodeDiff)
				}
			case -1: // Node1 is less than Node2
				diff.Removed = append(diff.Removed, n)
				index1++
			case 1: // Node1 is greater than Node2
				diff.Added = append(diff.Added, n2)
				index2++
			}
		case index1 < len(nlNodes):
			diff.Removed = append(diff.Removed, nlNodes[index1])
			index1++
		default:
			diff.Added = append(diff.Added, nl2Nodes[index2])
			index2++
		}
	}

	sort.Slice(diff.Added, func(i, j int) bool {
		return strings.Compare(diff.Added[i].Id, diff.Added[j].Id) <= 0
	})
	sort.Slice(diff.Removed, func(i, j int) bool {
		return strings.Compare(diff.Removed[i].Id, diff.Removed[j].Id) <= 0
	})

	sort.Slice(diff.NodeDiff, func(i, j int) bool {
		return strings.Compare(diff.NodeDiff[i].Added.flatString(), diff.NodeDiff[j].Added.flatString()) <= 0
	})

	return diff
}

func (nl *NodeList) diffEdges(nl2 *NodeList) EdgeSetDiff {
	diff := EdgeSetDiff{}

	nlEdges := nl.Edges
	nl2Edges := nl2.Edges

	// Sort both edge lists
	sort.Slice(nlEdges, func(i, j int) bool {
		return nlEdges[i].Equal(nlEdges[j])
	})
	sort.Slice(nl2Edges, func(i, j int) bool {
		return nl2Edges[i].Equal(nl2Edges[j])
	})

	index1, index2 := 0, 0

	// Iterate through both sorted edge lists
	for index1 < len(nlEdges) || index2 < len(nl2Edges) {
		switch {
		case index1 < len(nlEdges) && index2 < len(nl2Edges):
			e, e2 := nlEdges[index1], nl2Edges[index2]

			if e.From == e2.From && e.Type == e2.Type {
				// Edge To split
				index1++
				index2++
				removedTo := getSliceDiff(e.To, e2.To)
				addedTo := getSliceDiff(e2.To, e.To)

				if len(removedTo) > 0 {
					diff.Removed = append(diff.Removed, &Edge{
						From: e.From,
						To:   removedTo,
						Type: e.Type,
					})
				}

				if len(addedTo) > 0 {
					diff.Added = append(diff.Added, &Edge{
						From: e2.From,
						To:   addedTo,
						Type: e2.Type,
					})
				}

				continue
			}

			switch compareEdges(e, e2) {
			case 0: // Edges are equal
				index1++
				index2++
			case -1: // Edge1 is less than Edge2
				diff.Removed = append(diff.Removed, e)
				index1++
			case 1: // Edge1 is greater than Edge2
				diff.Added = append(diff.Added, e2)
				index2++
			}
		case index1 < len(nlEdges):
			diff.Removed = append(diff.Removed, nlEdges[index1])
			index1++
		default:
			diff.Added = append(diff.Added, nl2Edges[index2])
			index2++
		}
	}

	sort.Slice(diff.Added, func(i, j int) bool {
		return diff.Added[i].Equal(diff.Added[j])
	})
	sort.Slice(diff.Removed, func(i, j int) bool {
		return diff.Removed[i].Equal(diff.Removed[j])
	})

	return diff
}

func compareEdges(e1, e2 *Edge) int {
	sort.Strings(e1.To)
	sort.Strings(e2.To)
	return strings.Compare(e1.String(), e2.String())
}

func getSliceDiff(l, l2 []string) []string {
	sort.Strings(l)

	sort.Strings(l2)

	diff := []string{}
	for _, el := range l {
		if !contains(l2, el) {
			diff = append(diff, el)
		}
	}

	return diff
}
