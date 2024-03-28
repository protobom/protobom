// ------------------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright © 2024 The Protobom Authors
// SPDX-FileName: ent/schema/metadata.go
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

type Metadata struct {
	ent.Schema
}

func (Metadata) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Unique().Immutable(),
		field.String("version"),
		field.String("name"),
		field.Time("date"),
		field.String("comment"),
	}
}

func (Metadata) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("tools", Tool.Type),
		edge.To("authors", Person.Type),
		edge.To("document_types", DocumentType.Type),
		edge.To("document", Document.Type).Unique(),
	}
}

func (Metadata) Annotations() []schema.Annotation { return nil }
