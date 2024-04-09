// ------------------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright © 2024 The Protobom Authors
// SPDX-FileName: ent/schema/edge_type.go
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

type EdgeType struct {
	ent.Schema
}

func (EdgeType) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("type").Values(
			"UNKNOWN",
			"amends",
			"ancestor",
			"buildDependency",
			"buildTool",
			"contains",
			"contained_by",
			"copy",
			"dataFile",
			"dependencyManifest",
			"dependsOn",
			"dependencyOf",
			"descendant",
			"describes",
			"describedBy",
			"devDependency",
			"devTool",
			"distributionArtifact",
			"documentation",
			"dynamicLink",
			"example",
			"expandedFromArchive",
			"fileAdded",
			"fileDeleted",
			"fileModified",
			"generates",
			"generatedFrom",
			"metafile",
			"optionalComponent",
			"optionalDependency",
			"other",
			"packages",
			"patch",
			"prerequisite",
			"prerequisiteFor",
			"providedDependency",
			"requirementFor",
			"runtimeDependency",
			"specificationFor",
			"staticLink",
			"test",
			"testCase",
			"testDependency",
			"testTool",
			"variant",
		),
		field.String("node_id"),
		field.String("to_id"),
	}
}

func (EdgeType) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("from", Node.Type).Required().Unique().Field("node_id"),
		edge.To("to", Node.Type).Required().Unique().Field("to_id"),
	}
}

func (EdgeType) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("type").Edges("from", "to").Unique(),
	}
}

func (EdgeType) Annotations() []schema.Annotation { return nil }
