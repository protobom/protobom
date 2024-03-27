// File updated by protoc-gen-ent.

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

type Person struct {
	ent.Schema
}

func (Person) Fields() []ent.Field {
	return []ent.Field{field.String("name"), field.Bool("is_org"), field.String("email"), field.String("url"), field.String("phone")}
}
func (Person) Edges() []ent.Edge {
	return []ent.Edge{edge.To("contacts", Person.Type)}
}
func (Person) Annotations() []schema.Annotation {
	return nil
}
