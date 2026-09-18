package sbom

import (
	"errors"
	"fmt"
)

// Graft copies the graph reachable from the node rootID of src into nl,
// giving every copied node a fresh id, and relates the copy of that node
// to the node atID of nl with an edge of the given type. It is how a
// graph from one document is hung below a node of another: a bill of
// materials for a binary under the file found on disk, a subtree under
// the component it was resolved for. Only outgoing edges are followed
// from rootID, so nothing else in src comes along, and cycles below it
// are preserved. src is not modified.
func (nl *NodeList) Graft(atID string, src *NodeList, rootID string, edgeType Edge_Type) error {
	if nl.GetNodeByID(atID) == nil {
		return fmt.Errorf("node %q not found in the destination", atID)
	}
	sub, err := src.copyReachable(rootID)
	if err != nil {
		return err
	}
	for _, n := range sub.nodes {
		nl.AddNode(n)
	}
	nl.MergeEdges(sub.edges)
	nl.MergeEdges([]*Edge{{From: atID, Type: edgeType, To: []string{sub.rootID}}})
	return nil
}

// GraftInto folds the node rootID of src into the node atID of nl and
// copies the graph reachable from it below atID, with fresh ids. The
// destination node absorbs the root (see Node.Absorb): it keeps every
// value it states, fills what it lacks, and gains the root's hashes,
// identifiers, licenses, references and properties. Edges that left or
// reached the root now leave or reach atID. It is how two descriptions of
// the same component are combined into one node with the union of their
// graphs below it. src is not modified.
func (nl *NodeList) GraftInto(atID string, src *NodeList, rootID string) error {
	target := nl.GetNodeByID(atID)
	if target == nil {
		return fmt.Errorf("node %q not found in the destination", atID)
	}
	sub, err := src.copyReachable(rootID)
	if err != nil {
		return err
	}
	for _, n := range sub.nodes {
		if n.GetId() == sub.rootID {
			target.Absorb(n)
			continue
		}
		nl.AddNode(n)
	}
	for _, e := range sub.edges {
		if e.GetFrom() == sub.rootID {
			e.From = atID
		}
		for i, to := range e.GetTo() {
			if to == sub.rootID {
				e.To[i] = atID
			}
		}
	}
	nl.MergeEdges(sub.edges)
	return nil
}

// subgraph is a copy of the part of a NodeList reachable from one node.
type subgraph struct {
	rootID string
	nodes  []*Node
	edges  []*Edge
}

// copyReachable copies the node rootID and everything reachable from it
// through outgoing edges, giving every node a fresh id so the copy can
// join any list without colliding with ids the source document chose.
func (nl *NodeList) copyReachable(rootID string) (*subgraph, error) {
	if nl == nil {
		return nil, errors.New("no source graph")
	}
	if nl.GetNodeByID(rootID) == nil {
		return nil, fmt.Errorf("node %q not found in the source", rootID)
	}
	outgoing := map[string][]*Edge{}
	for _, e := range nl.GetEdges() {
		outgoing[e.GetFrom()] = append(outgoing[e.GetFrom()], e)
	}

	ids := map[string]string{rootID: NewNodeIdentifier(NodeIdentifierPrefixAuto)}
	sub := &subgraph{rootID: ids[rootID]}
	queue := []string{rootID}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		n := nl.GetNodeByID(id).Copy()
		n.Id = ids[id]
		sub.nodes = append(sub.nodes, n)
		for _, e := range outgoing[id] {
			copied := &Edge{From: ids[id], Type: e.GetType()}
			for _, to := range e.GetTo() {
				if nl.GetNodeByID(to) == nil {
					continue // a dangling edge in the source
				}
				if _, seen := ids[to]; !seen {
					ids[to] = NewNodeIdentifier(NodeIdentifierPrefixAuto)
					queue = append(queue, to)
				}
				copied.To = append(copied.To, ids[to])
			}
			if len(copied.GetTo()) > 0 {
				sub.edges = append(sub.edges, copied)
			}
		}
	}
	return sub, nil
}
