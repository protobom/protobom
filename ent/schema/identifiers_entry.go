// ------------------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright © 2024 The Protobom Authors
// SPDX-FileName: ent/schema/identifiers_entry.go
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

type IdentifiersEntry struct {
	ent.Schema
}

func (IdentifiersEntry) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("software_identifier_type").Values(
			"UNKNOWN_IDENTIFIER_TYPE",
			"PURL",
			"CPE22",
			"CPE23",
			"GITOID",
		),
		field.String("software_identifier_value"),
	}
}

func (IdentifiersEntry) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("nodes", Node.Type).Ref("identifiers").Unique(),
	}
}

func (IdentifiersEntry) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("software_identifier_type", "software_identifier_value").Unique(),
	}
}

func (IdentifiersEntry) Annotations() []schema.Annotation { return nil }
