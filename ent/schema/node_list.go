// File updated by protoc-gen-ent.

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

type NodeList struct {
	ent.Schema
}

func (NodeList) Fields() []ent.Field {
	return []ent.Field{field.String("root_elements")}
}
func (NodeList) Edges() []ent.Edge {
	return []ent.Edge{edge.To("nodes", Node.Type), edge.To("edges", Edge.Type)}
}
func (NodeList) Annotations() []schema.Annotation {
	return nil
}
