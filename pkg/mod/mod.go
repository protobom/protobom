// --------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright 2024 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0
// --------------------------------------------------------------

// Package mod defines constant strings that represent a custom behavior in
// protobom. Mods behave like feature flags, enabling features in the writer
// and reader only when requested.
package mod

type Mod string

// SPDX_RENDER_PROPERTIES_IN_ANNOTATIONS is a mod that cuases the SPDX serializers
// to render the protobom property bags as annotations in SPDX.
//
// When enabled, protobom will marshall the property proto value into JSON and
// add they will be rendered into an SPDX annotation in the comment field. The
// property annotator will be fixed to protobom - v1.0.0 to make it identifiable
// when reading them back.
const SPDX_RENDER_PROPERTIES_IN_ANNOTATIONS = Mod("SPDX_RENDER_PROPERTIES")

// SPDX_READ_ANNOTATIONS_TO_PROPERTIES is a mode that causes the spdx unserializer
// to look for protobom properties encoded in SPDX the annotations of packages.
// When enabled, the serializer will try to unmarshal the contents of any
// annotations by "protobom - v1.0.0" into an sbom.Property and store it in the
// node properties.
const SPDX_READ_ANNOTATIONS_TO_PROPERTIES = Mod("SPDX_READ_ANNOTATIONS_TO_PROPERTIES")
