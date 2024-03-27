// File updated by protoc-gen-ent.

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
)

type Document struct {
	ent.Schema
}

func (Document) Fields() []ent.Field {
	return nil
}
func (Document) Edges() []ent.Edge {
	return []ent.Edge{edge.To("metadata", Metadata.Type), edge.To("node_list", NodeList.Type)}
}
func (Document) Annotations() []schema.Annotation {
	return nil
}
