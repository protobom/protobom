// File updated by protoc-gen-ent.

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

type IdentifiersEntry struct {
	ent.Schema
}

func (IdentifiersEntry) Fields() []ent.Field {
	return []ent.Field{field.Enum("software_identifier_type").Values("UNKNOWN_IDENTIFIER_TYPE", "PURL", "CPE22", "CPE23", "GITOID"), field.String("software_identifier_value")}
}
func (IdentifiersEntry) Edges() []ent.Edge {
	return nil
}
func (IdentifiersEntry) Annotations() []schema.Annotation {
	return nil
}
