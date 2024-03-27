// File updated by protoc-gen-ent.

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

type DocumentType struct {
	ent.Schema
}

func (DocumentType) Fields() []ent.Field {
	return []ent.Field{field.Enum("type").Optional().Values("OTHER", "DESIGN", "SOURCE", "BUILD", "ANALYZED", "DEPLOYED", "RUNTIME", "DISCOVERY", "DECOMISSION"), field.String("name").Optional(), field.String("description").Optional()}
}
func (DocumentType) Edges() []ent.Edge {
	return nil
}
func (DocumentType) Annotations() []schema.Annotation {
	return nil
}
