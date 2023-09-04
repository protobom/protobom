// SPDX-FileCopyrightText: Copyright 2023 The StarBOM Authors
// SPDX-License-Identifier: Apache-2.0

package native

import (
	"io"

	"github.com/bom-squad/protobom/pkg/reader/options"
	"github.com/bom-squad/protobom/pkg/sbom"
)

type Unserializer interface {
	ParseStream(*options.Options, io.Reader) (*sbom.Document, error)
}
