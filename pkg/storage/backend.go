// --------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright © 2024 The Protobom Authors
// SPDX-FileType: SOURCE
// SPDX-License-Identifier: Apache-2.0
// --------------------------------------------------------------

package storage

import "github.com/protobom/protobom/pkg/sbom"

type (
	Storer interface {
		Store(*sbom.Document, *StoreOptions) error
	}

	Retriever interface {
		Retrieve(string, *RetrieveOptions) (*sbom.Document, error)
	}

	StoreRetriever interface {
		Storer
		Retriever
	}

	Backend interface {
		StoreRetriever
	}
)
