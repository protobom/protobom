package sbom

import (
	"regexp"
	"sort"
	"strings"
)

// NodeListDiff represents the difference between two lists NodeLists.
type NodeListDiff struct {
	NodesDiff         NodeListDiffNodes
	EdgesDiff         NodeListDiffEdges
	RootElmementsDiff NodeListRootElementDiff
}

func (nlDiff *NodeListDiff) AddedNodeList() *NodeList {
	var addedNodeList NodeList
	for _, addedNode := range nlDiff.NodesDiff.Added {
		addedNodeList.AddNode(addedNode)
	}
	for _, addedEdge := range nlDiff.EdgesDiff.Added {
		addedNodeList.AddEdge(addedEdge)
	}
	addedNodeList.RootElements = append(addedNodeList.RootElements, nlDiff.RootElmementsDiff.Added...)

	for _, diffNodeAdded := range nlDiff.NodesDiff.NodeDiff {
		addedNodeList.AddNode(diffNodeAdded.Added)
	}

	return &addedNodeList
}

func (nlDiff *NodeListDiff) RemovedNodeList() *NodeList {
	var removedNodeList NodeList
	for _, removedNode := range nlDiff.NodesDiff.Removed {
		removedNodeList.AddNode(removedNode)
	}
	for _, removedEdge := range nlDiff.EdgesDiff.Removed {
		removedNodeList.AddEdge(removedEdge)
	}
	removedNodeList.RootElements = append(removedNodeList.RootElements, nlDiff.RootElmementsDiff.Removed...)

	for _, diffNodeRemoved := range nlDiff.NodesDiff.NodeDiff {
		removedNodeList.AddNode(diffNodeRemoved.Removed)
	}

	return &removedNodeList
}

// NodeListDiffNodes represents the differences between two NodeList nodes.
type NodeListDiffNodes struct {
	Added    []*Node
	Removed  []*Node
	NodeDiff []*NodeDiff
}

// NodeListDiffEdges represents the differences between two NodeList edges.
type NodeListDiffEdges struct {
	Added   []*Edge
	Removed []*Edge
}

// NodeListRootElementDiff represents the differences between two NodeLists root elements.
type NodeListRootElementDiff struct {
	Added   []string
	Removed []string
}

// Diff analyses a NodeList and returns a NodeList populated with all fields
// that are different in nl2 from nl.
func (nl *NodeList) Diff(nl2 *NodeList) NodeListDiff {
	return NodeListDiff{
		NodesDiff:         nl.diffNodes(nl2, false),
		EdgesDiff:         nl.diffEdges(nl2),
		RootElmementsDiff: nl.diffRootElements(nl2),
	}
}

// DiffWithStripQulifiers analyses a NodeList and returns a NodeList populated with all fields
// that are different in nl2 from nl after stripping identifier Quilifiers.
func (nl *NodeList) DiffWithStripQulifiers(nl2 *NodeList, strip bool) NodeListDiff {
	return NodeListDiff{
		NodesDiff:         nl.diffNodes(nl2, strip),
		EdgesDiff:         nl.diffEdges(nl2),
		RootElmementsDiff: nl.diffRootElements(nl2),
	}
}

// diffRootElements computes the differences in root elements between two NodeLists.
func (nl *NodeList) diffRootElements(nl2 *NodeList) NodeListRootElementDiff {
	diff := NodeListRootElementDiff{}

	nlRoots := make(map[string]struct{}) // map to store root elements of nl
	for _, root := range nl.RootElements {
		nlRoots[root] = struct{}{}
	}

	nl2Roots := make(map[string]struct{}) // map to store root elements of nl2
	for _, root := range nl2.RootElements {
		nl2Roots[root] = struct{}{}
	}

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

func stripQualifiers(url string) string {
	// Define a regular expression pattern to match everything after "?"
	pattern := regexp.MustCompile(`\?.*`)
	// Substitute the matched pattern with an empty string to remove it
	strippedURL := pattern.ReplaceAllString(url, "")
	return strippedURL
}

func stripNodeQualifiers(n *Node) {
	n.Id = stripQualifiers(n.Id)
	newNIds := make(map[int32]string, len(n.Identifiers))
	for u, id := range n.Identifiers {
		newNIds[u] = stripQualifiers(id)
	}
	n.Identifiers = newNIds
}

func (nl *NodeList) diffNodes(nl2 *NodeList, strip bool) NodeListDiffNodes {
	diff := NodeListDiffNodes{}

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
		if index1 < len(nlNodes) && index2 < len(nl2Nodes) {
			n, n2 := nlNodes[index1], nl2Nodes[index2]
			if strip {
				stripNodeQualifiers(n)
				stripNodeQualifiers(n2)
			}
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
		} else if index1 < len(nlNodes) {
			diff.Removed = append(diff.Removed, nlNodes[index1])
			index1++
		} else {
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

func (nl *NodeList) diffEdges(nl2 *NodeList) NodeListDiffEdges {
	diff := NodeListDiffEdges{}

	nlEdges := nl.Edges
	nl2Edges := nl2.Edges

	// Sort both edge lists
	sort.Slice(nlEdges, func(i, j int) bool {
		return compareEdges(nlEdges[i], nlEdges[j]) <= 0
	})
	sort.Slice(nl2Edges, func(i, j int) bool {
		return compareEdges(nl2Edges[i], nl2Edges[j]) <= 0
	})

	index1, index2 := 0, 0

	// Iterate through both sorted edge lists
	for index1 < len(nlEdges) || index2 < len(nl2Edges) {
		if index1 < len(nlEdges) && index2 < len(nl2Edges) {
			e, e2 := nlEdges[index1], nl2Edges[index2]

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
		} else if index1 < len(nlEdges) {
			diff.Removed = append(diff.Removed, nlEdges[index1])
			index1++
		} else {
			diff.Added = append(diff.Added, nl2Edges[index2])
			index2++
		}
	}

	sort.Slice(diff.Added, func(i, j int) bool {
		return compareEdges(diff.Added[i], diff.Added[j]) <= 0
	})
	sort.Slice(diff.Removed, func(i, j int) bool {
		return compareEdges(diff.Removed[i], diff.Removed[j]) <= 0
	})

	return diff
}

func compareEdges(e1, e2 *Edge) int {
	sort.Strings(e1.To)
	sort.Strings(e2.To)
	return strings.Compare(e1.String(), e2.String())
}
