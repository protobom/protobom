// File updated by protoc-gen-ent.

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

type HashesEntry struct {
	ent.Schema
}

func (HashesEntry) Fields() []ent.Field {
	return []ent.Field{field.Enum("hash_algorithm_type").Values("UNKNOWN", "MD5", "SHA1", "SHA256", "SHA384", "SHA512", "SHA3_256", "SHA3_384", "SHA3_512", "BLAKE2B_256", "BLAKE2B_384", "BLAKE2B_512", "BLAKE3", "MD2", "ADLER32", "MD4", "MD6", "SHA224"), field.String("hash_data")}
}

func (HashesEntry) Edges() []ent.Edge {
	return []ent.Edge{edge.From("external_references", ExternalReference.Type).Ref("hashes"), edge.From("nodes", Node.Type).Ref("hashes")}
}

func (HashesEntry) Annotations() []schema.Annotation { return nil }
