// File updated by protoc-gen-ent.

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
)

type Timestamp struct {
	ent.Schema
}

func (Timestamp) Fields() []ent.Field { return nil }

func (Timestamp) Edges() []ent.Edge {
	return []ent.Edge{edge.To("date", Timestamp.Type), edge.From("metadata", Metadata.Type).Ref("date").Unique()}
}

func (Timestamp) Annotations() []schema.Annotation { return nil }
