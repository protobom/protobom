// ------------------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright © 2024 The Protobom Authors
// SPDX-FileName: ent/schema/node.go
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
)

type Node struct {
	ent.Schema
}

func (Node) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").NotEmpty().Unique().Immutable(),
		field.Enum("type").Values("PACKAGE", "FILE"),
		field.String("name"),
		field.String("version"),
		field.String("file_name"),
		field.String("url_home"),
		field.String("url_download"),
		field.Strings("licenses"),
		field.String("license_concluded"),
		field.String("license_comments"),
		field.String("copyright"),
		field.String("source_info"),
		field.String("comment"),
		field.String("summary"),
		field.String("description"),
		field.Time("release_date"),
		field.Time("build_date"),
		field.Time("valid_until_date"),
		field.Strings("attribution"),
		field.Strings("file_types"),
	}
}

func (Node) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("suppliers", Person.Type),
		edge.To("originators", Person.Type),
		edge.To("external_references", ExternalReference.Type),
		edge.To("identifiers", IdentifiersEntry.Type),
		edge.To("hashes", HashesEntry.Type),
		edge.To("primary_purpose", Purpose.Type),
		edge.To("nodes", Node.Type).Through("edge_types", EdgeType.Type),
		edge.From("node_list", NodeList.Type).Ref("nodes").Required().Unique(),
	}
}

func (Node) Annotations() []schema.Annotation { return nil }
