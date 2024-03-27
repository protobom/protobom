// File updated by protoc-gen-ent.

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

type Tool struct {
	ent.Schema
}

func (Tool) Fields() []ent.Field {
	return []ent.Field{field.String("name"), field.String("version"), field.String("vendor")}
}

func (Tool) Edges() []ent.Edge {
	return []ent.Edge{edge.From("metadata", Metadata.Type).Ref("tools").Unique()}
}

func (Tool) Annotations() []schema.Annotation { return nil }
