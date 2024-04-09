// ------------------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright © 2024 The Protobom Authors
// SPDX-FileName: ent/schema/external_reference.go
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

type ExternalReference struct {
	ent.Schema
}

func (ExternalReference) Fields() []ent.Field {
	return []ent.Field{
		field.String("url"),
		field.String("comment"),
		field.String("authority").Optional(),
		field.Enum("type").Values(
			"UNKNOWN",
			"ATTESTATION",
			"BINARY",
			"BOM",
			"BOWER",
			"BUILD_META",
			"BUILD_SYSTEM",
			"CERTIFICATION_REPORT",
			"CHAT",
			"CODIFIED_INFRASTRUCTURE",
			"COMPONENT_ANALYSIS_REPORT",
			"CONFIGURATION",
			"DISTRIBUTION_INTAKE",
			"DOCUMENTATION",
			"DOWNLOAD",
			"DYNAMIC_ANALYSIS_REPORT",
			"EOL_NOTICE",
			"EVIDENCE",
			"EXPORT_CONTROL_ASSESSMENT",
			"FORMULATION",
			"FUNDING",
			"ISSUE_TRACKER",
			"LICENSE",
			"LOG",
			"MAILING_LIST",
			"MATURITY_REPORT",
			"MAVEN_CENTRAL",
			"METRICS",
			"MODEL_CARD",
			"NPM",
			"NUGET",
			"OTHER",
			"POAM",
			"PRIVACY_ASSESSMENT",
			"PRODUCT_METADATA",
			"PURCHASE_ORDER",
			"QUALITY_ASSESSMENT_REPORT",
			"QUALITY_METRICS",
			"RELEASE_HISTORY",
			"RELEASE_NOTES",
			"RISK_ASSESSMENT",
			"RUNTIME_ANALYSIS_REPORT",
			"SECURE_SOFTWARE_ATTESTATION",
			"SECURITY_ADVERSARY_MODEL",
			"SECURITY_ADVISORY",
			"SECURITY_CONTACT",
			"SECURITY_FIX",
			"SECURITY_OTHER",
			"SECURITY_PENTEST_REPORT",
			"SECURITY_POLICY",
			"SECURITY_SWID",
			"SECURITY_THREAT_MODEL",
			"SOCIAL",
			"SOURCE_ARTIFACT",
			"STATIC_ANALYSIS_REPORT",
			"SUPPORT",
			"VCS",
			"VULNERABILITY_ASSERTION",
			"VULNERABILITY_DISCLOSURE_REPORT",
			"VULNERABILITY_EXPLOITABILITY_ASSESSMENT",
			"WEBSITE",
		),
	}
}

func (ExternalReference) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("hashes", HashesEntry.Type),
		edge.From("node", Node.Type).Ref("external_references").Required().Unique(),
	}
}

func (ExternalReference) Annotations() []schema.Annotation { return nil }
