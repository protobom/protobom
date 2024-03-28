// ------------------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright © 2024 The Protobom Authors
// SPDX-FileName: ent/schema/hashes_entry.go
// SPDX-FileType: SOURCE
// SPDX-License-Identifier: Apache-2.0
// ------------------------------------------------------------------------
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ------------------------------------------------------------------------
package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type HashesEntry struct {
	ent.Schema
}

func (HashesEntry) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("hash_algorithm_type").Values(
			"UNKNOWN",
			"MD5",
			"SHA1",
			"SHA256",
			"SHA384",
			"SHA512",
			"SHA3_256",
			"SHA3_384",
			"SHA3_512",
			"BLAKE2B_256",
			"BLAKE2B_384",
			"BLAKE2B_512",
			"BLAKE3",
			"MD2",
			"ADLER32",
			"MD4",
			"MD6",
			"SHA224",
		),
		field.String("hash_data"),
	}
}

func (HashesEntry) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("external_references", ExternalReference.Type).Ref("hashes").Unique(),
		edge.From("nodes", Node.Type).Ref("hashes").Unique(),
	}
}

func (HashesEntry) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("hash_algorithm_type", "hash_data").Unique(),
	}
}

func (HashesEntry) Annotations() []schema.Annotation { return nil }
