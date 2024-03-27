// File updated by protoc-gen-ent.

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

type Edge struct {
	ent.Schema
}

func (Edge) Fields() []ent.Field {
	return []ent.Field{field.Enum("type").Values("UNKNOWN", "amends", "ancestor", "buildDependency", "buildTool", "contains", "contained_by", "copy", "dataFile", "dependencyManifest", "dependsOn", "dependencyOf", "descendant", "describes", "describedBy", "devDependency", "devTool", "distributionArtifact", "documentation", "dynamicLink", "example", "expandedFromArchive", "fileAdded", "fileDeleted", "fileModified", "generates", "generatedFrom", "metafile", "optionalComponent", "optionalDependency", "other", "packages", "patch", "prerequisite", "prerequisiteFor", "providedDependency", "requirementFor", "runtimeDependency", "specificationFor", "staticLink", "test", "testCase", "testDependency", "testTool", "variant"), field.String("from"), field.String("to")}
}

func (Edge) Edges() []ent.Edge {
	return []ent.Edge{edge.From("node_list", NodeList.Type).Ref("edges").Required().Unique()}
}

func (Edge) Annotations() []schema.Annotation { return nil }
