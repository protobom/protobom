// File updated by protoc-gen-ent.

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

type Metadata struct {
	ent.Schema
}

func (Metadata) Fields() []ent.Field {
	return []ent.Field{field.String("id").Unique().Immutable(), field.String("version"), field.String("name"), field.String("comment")}
}

func (Metadata) Edges() []ent.Edge {
	return []ent.Edge{edge.To("tools", Tool.Type), edge.To("authors", Person.Type), edge.To("documentTypes", DocumentType.Type), edge.To("date", Timestamp.Type), edge.From("document", Document.Type).Ref("metadata").Required().Unique()}
}

func (Metadata) Annotations() []schema.Annotation { return nil }
