// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package unserializers

import (
	"github.com/carabiner-dev/spdx3/profiles/core"

	"github.com/protobom/protobom/pkg/sbom"
)

// spdx3Edge is what an SPDX 3 relationship type says in protobom's terms.
type spdx3Edge struct {
	edgeType sbom.Edge_Type

	// invert says the ends have to be swapped, because protobom states this
	// relationship the other way round. SPDX 3 deleted every inverse
	// relationship type, so the twenty protobom expresses only as "... of"
	// have to be turned back around on the way in.
	invert bool
}

// spdx3RelationshipTypes reads SPDX 3's relationship vocabulary into
// protobom's. It is the reverse of edgeTypeToSPDX3 in the serializer, which
// is not a one-to-one mapping: protobom has both `contains` and
// `contained_by` where SPDX 3 has only `contains`, so the reverse picks the
// one that leaves the relationship pointing the way the document states it.
//
// Twenty-four of SPDX 3's fifty-nine types are absent because protobom has
// nothing to say them with: thirteen belong to the Security profile, four to
// Build, two to AI, and five are Core ideas protobom has no field for
// (availableFrom, configures, delegatedTo, hasEvidence, serializedInArtifact).
var spdx3RelationshipTypes = map[core.RelationshipType]spdx3Edge{
	// Said the same way round, under the same name.
	core.RelationshipTypeContains:     {edgeType: sbom.Edge_contains},
	core.RelationshipTypeDependsOn:    {edgeType: sbom.Edge_dependsOn},
	core.RelationshipTypeDescribes:    {edgeType: sbom.Edge_describes},
	core.RelationshipTypeGenerates:    {edgeType: sbom.Edge_generates},
	core.RelationshipTypeOther:        {edgeType: sbom.Edge_other},
	core.RelationshipTypeAncestorOf:   {edgeType: sbom.Edge_ancestor},
	core.RelationshipTypeDescendantOf: {edgeType: sbom.Edge_descendant},

	// Said the same way round, under another name.
	core.RelationshipTypeHasDistributionArtifact: {edgeType: sbom.Edge_distributionArtifact},
	core.RelationshipTypeHasDynamicLink:          {edgeType: sbom.Edge_dynamicLink},
	core.RelationshipTypeHasStaticLink:           {edgeType: sbom.Edge_staticLink},
	core.RelationshipTypeHasPrerequisite:         {edgeType: sbom.Edge_prerequisite},

	// Said the other way round: protobom has only the "... of" form.
	core.RelationshipTypeAmendedBy:             {edgeType: sbom.Edge_amends, invert: true},
	core.RelationshipTypeCopiedTo:              {edgeType: sbom.Edge_copy, invert: true},
	core.RelationshipTypeHasDataFile:           {edgeType: sbom.Edge_dataFile, invert: true},
	core.RelationshipTypeHasDependencyManifest: {edgeType: sbom.Edge_dependencyManifest, invert: true},
	core.RelationshipTypeHasDocumentation:      {edgeType: sbom.Edge_documentation, invert: true},
	core.RelationshipTypeHasExample:            {edgeType: sbom.Edge_example, invert: true},
	core.RelationshipTypeExpandsTo:             {edgeType: sbom.Edge_expandedFromArchive, invert: true},
	core.RelationshipTypeHasAddedFile:          {edgeType: sbom.Edge_fileAdded, invert: true},
	core.RelationshipTypeHasDeletedFile:        {edgeType: sbom.Edge_fileDeleted, invert: true},
	core.RelationshipTypeHasMetadata:           {edgeType: sbom.Edge_metafile, invert: true},
	core.RelationshipTypeHasOptionalComponent:  {edgeType: sbom.Edge_optionalComponent, invert: true},
	core.RelationshipTypeHasOptionalDependency: {edgeType: sbom.Edge_optionalDependency, invert: true},
	core.RelationshipTypePackagedBy:            {edgeType: sbom.Edge_packages, invert: true},
	core.RelationshipTypePatchedBy:             {edgeType: sbom.Edge_patch, invert: true},
	core.RelationshipTypeHasProvidedDependency: {edgeType: sbom.Edge_providedDependency, invert: true},
	core.RelationshipTypeHasRequirement:        {edgeType: sbom.Edge_requirementFor, invert: true},
	core.RelationshipTypeHasSpecification:      {edgeType: sbom.Edge_specificationFor, invert: true},
	core.RelationshipTypeHasTest:               {edgeType: sbom.Edge_test, invert: true},
	core.RelationshipTypeHasTestCase:           {edgeType: sbom.Edge_testCase, invert: true},
	core.RelationshipTypeHasVariant:            {edgeType: sbom.Edge_variant, invert: true},

	// The serializer writes protobom's fileModified as modifiedBy, which is
	// the closest SPDX 3 has, so it is read back as what it was.
	core.RelationshipTypeModifiedBy: {edgeType: sbom.Edge_fileModified},

	// usesTool has no entry of its own: protobom says a tool is used with
	// buildTool, devTool or testTool, each naming the period it is used in,
	// and SPDX 3 states that period as the scope of a lifecycle scoped
	// relationship. The pairs are read through spdx3ScopedRelationshipTypes;
	// a usesTool without a scope protobom can name is dropped.
}

// scopedRelationship is a relationship type together with the period of an
// element's life it holds during.
type scopedRelationship struct {
	relType core.RelationshipType
	scope   core.LifecycleScopeType
}

// spdx3ScopedRelationshipTypes reads the pairs SPDX 3 states with a lifecycle
// scoped relationship back into the protobom edge types that name the period
// themselves. It is the reverse of the scoped entries of the serializer's
// edgeTypeToSPDX3: protobom says "b is a build dependency of a" where SPDX 3
// says "a depends on b, during build", so each comes back turned around,
// like the other "... of" types.
//
// Protobom has no edge type for a dependency or a tool during the design
// phase, or during an unnamed one, so those scopes are not here: a
// dependsOn under them is read as a plain dependsOn and a usesTool is
// dropped.
var spdx3ScopedRelationshipTypes = map[scopedRelationship]spdx3Edge{
	{core.RelationshipTypeDependsOn, core.LifecycleScopeTypeBuild}:       {edgeType: sbom.Edge_buildDependency, invert: true},
	{core.RelationshipTypeDependsOn, core.LifecycleScopeTypeDevelopment}: {edgeType: sbom.Edge_devDependency, invert: true},
	{core.RelationshipTypeDependsOn, core.LifecycleScopeTypeRuntime}:     {edgeType: sbom.Edge_runtimeDependency, invert: true},
	{core.RelationshipTypeDependsOn, core.LifecycleScopeTypeTest}:        {edgeType: sbom.Edge_testDependency, invert: true},
	{core.RelationshipTypeUsesTool, core.LifecycleScopeTypeBuild}:        {edgeType: sbom.Edge_buildTool, invert: true},
	{core.RelationshipTypeUsesTool, core.LifecycleScopeTypeDevelopment}:  {edgeType: sbom.Edge_devTool, invert: true},
	{core.RelationshipTypeUsesTool, core.LifecycleScopeTypeTest}:         {edgeType: sbom.Edge_testTool, invert: true},
}

// edgeFromSPDX3 returns what a relationship type says in protobom's terms,
// and whether protobom can say it at all.
func edgeFromSPDX3(t core.RelationshipType) (spdx3Edge, bool) {
	edge, ok := spdx3RelationshipTypes[t]
	return edge, ok
}

// edgeFromScopedSPDX3 returns what a relationship type holding during a
// period of an element's life says in protobom's terms. A pair protobom has
// no edge type for is read as the relationship type alone.
// TODO(degradation): the scope is then dropped.
func edgeFromScopedSPDX3(t core.RelationshipType, scope core.LifecycleScopeType) (spdx3Edge, bool) {
	if edge, ok := spdx3ScopedRelationshipTypes[scopedRelationship{t, scope}]; ok {
		return edge, true
	}
	return edgeFromSPDX3(t)
}
