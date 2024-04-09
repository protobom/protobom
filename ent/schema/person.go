// ------------------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright © 2024 The Protobom Authors
// SPDX-FileName: ent/schema/person.go
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

type Person struct {
	ent.Schema
}

func (Person) Fields() []ent.Field {
	return []ent.Field{
		field.String("name"),
		field.Bool("is_org"),
		field.String("email"),
		field.String("url"),
		field.String("phone"),
	}
}

func (Person) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("contacts", Person.Type).From("contact_owner").Unique(),
		edge.From("metadata", Metadata.Type).Ref("authors").Unique(),
		edge.From("node", Node.Type).Ref("suppliers").Unique().Ref("originators").Unique(),
	}
}

func (Person) Annotations() []schema.Annotation { return nil }
