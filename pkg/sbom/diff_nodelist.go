package sbom

import (
	"sort"
	"strings"
)

// NodeListDiff represents the difference between two lists NodeLists.
type NodeListDiff struct {
	Added    []*Node
	Removed  []*Node
	NodeDiff []*NodeDiff
}

// Diff analyses a NodeList and returns a NodeList populated with all fields
// that are different in nl2 from nl. If no changes are found, Diff returns nil
func (nl *NodeList) Diff(nl2 *NodeList) NodeListDiff {
	diff := NodeListDiff{}

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
			switch strings.Compare(n.Id, n2.Id) { //Use ID to decide if to compare
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
		return strings.Compare(diff.Removed[i].Id, diff.Added[j].Id) <= 0
	})
	sort.Slice(diff.NodeDiff, func(i, j int) bool {
		return strings.Compare(diff.NodeDiff[i].Added.flatString(), diff.NodeDiff[j].Added.flatString()) <= 0
	})

	return diff
}
