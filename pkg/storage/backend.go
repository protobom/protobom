// --------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright © 2024 The Protobom Authors
// SPDX-FileType: SOURCE
// SPDX-License-Identifier: Apache-2.0
// --------------------------------------------------------------

package storage

import (
	"github.com/protobom/protobom/pkg/sbom"
)

type (
	ProtobomType interface {
		*sbom.Document | *sbom.DocumentType | *sbom.Edge | *sbom.ExternalReference |
			*sbom.Metadata | *sbom.Node | *sbom.NodeList | *sbom.Person | *sbom.Purpose | *sbom.Tool |
			map[sbom.HashAlgorithm]string | map[sbom.SoftwareIdentifierType]string
	}

	Storer[T ProtobomType] interface {
		Store(T, *StoreOptions) error
	}

	Retriever[T ProtobomType] interface {
		Retrieve(string, *RetrieveOptions) (T, error)
	}

	Backend[T ProtobomType] interface {
		Storer[T]
		Retriever[T]
	}
)
