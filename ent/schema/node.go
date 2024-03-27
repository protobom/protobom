// File updated by protoc-gen-ent.

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

type Node struct {
	ent.Schema
}

func (Node) Fields() []ent.Field {
	return []ent.Field{field.String("id"), field.Enum("type").Values("PACKAGE", "FILE"), field.String("name"), field.String("version"), field.String("file_name"), field.String("url_home"), field.String("url_download"), field.String("licenses"), field.String("license_concluded"), field.String("license_comments"), field.String("copyright"), field.String("source_info"), field.String("comment"), field.String("summary"), field.String("description"), field.String("attribution"), field.String("file_types"), field.Enum("primary_purpose").Values("UNKNOWN_PURPOSE", "APPLICATION", "ARCHIVE", "BOM", "CONFIGURATION", "CONTAINER", "DATA", "DEVICE", "DEVICE_DRIVER", "DOCUMENTATION", "EVIDENCE", "EXECUTABLE", "FILE", "FIRMWARE", "FRAMEWORK", "INSTALL", "LIBRARY", "MACHINE_LEARNING_MODEL", "MANIFEST", "MODEL", "MODULE", "OPERATING_SYSTEM", "OTHER", "PATCH", "PLATFORM", "REQUIREMENT", "SOURCE", "SPECIFICATION", "TEST")}
}
func (Node) Edges() []ent.Edge {
	return []ent.Edge{edge.To("suppliers", Person.Type), edge.To("originators", Person.Type), edge.To("external_references", ExternalReference.Type), edge.To("identifiers", IdentifiersEntry.Type), edge.To("hashes", HashesEntry.Type), edge.To("release_date", Timestamp.Type), edge.To("build_date", Timestamp.Type), edge.To("valid_until_date", Timestamp.Type)}
}
func (Node) Annotations() []schema.Annotation {
	return nil
}
