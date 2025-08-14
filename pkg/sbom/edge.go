package sbom

import (
	"slices"
	"sort"
	"strings"
)

// NewEdge creates and returns a new graph edge.
func NewEdge() *Edge {
	return &Edge{
		To: []string{},
	}
}

// Copy returns a duplicate of the edge, including all connected graph edges.
func (e *Edge) Copy() *Edge {
	return &Edge{
		Type: e.Type,
		From: e.From,
		To:   e.To,
	}
}

// PointsTo returns true if the edge is directed towards a specific node.
// It evaluates to true only if the edge includes the provided node ID in its list of To nodes.
func (e *Edge) PointsTo(id string) bool {
	return slices.Contains(e.To, id)
}

// Equal compares the current edge to another (e2) and returns true if they are identical.
// It checks if both edges have the same source, type, and destination nodes.
func (e *Edge) Equal(e2 *Edge) bool {
	if e2 == nil {
		return false
	}
	return e.flatString() == e2.flatString()
}

// flatString returns a serialized representation of the edge as a string,
// suitable for indexing or comparison of the contents of the current edge.
func (e *Edge) flatString() string {
	tos := e.To
	sort.Strings(tos)
	return e.From + ":" + e.Type.String() + ":" + strings.Join(tos, "+")
}

// AddDestinationById adds identifiers to the destination list of the edge. The
// new destination identifiers are guaranteed to be added only once and will
// not be duplicated if there is already a destination with the same ID.
func (e *Edge) AddDestinationById(ids ...string) {
	dests := map[string]struct{}{}
	for _, id := range e.To {
		dests[id] = struct{}{}
	}

	for _, id := range ids {
		if _, ok := dests[id]; ok {
			continue
		}
		dests[id] = struct{}{}
		e.To = append(e.To, id)
	}
}
