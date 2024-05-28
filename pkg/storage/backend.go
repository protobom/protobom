// --------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright © 2024 The Protobom Authors
// SPDX-FileType: SOURCE
// SPDX-License-Identifier: Apache-2.0
// --------------------------------------------------------------

package storage

import "github.com/protobom/protobom/pkg/sbom"

type (
	Document           = *sbom.Document
	DocumentType       = *sbom.DocumentType
	DocumentTypes      = []DocumentType
	Edge               = *sbom.Edge
	Edges              = []Edge
	ExternalReference  = *sbom.ExternalReference
	ExternalReferences = []ExternalReference
	Metadata           = *sbom.Metadata
	Node               = *sbom.Node
	NodeList           = *sbom.NodeList
	Nodes              = []Node
	Person             = *sbom.Person
	Persons            = []Person
	Purpose            = sbom.Purpose
	Purposes           = []Purpose
	Tool               = *sbom.Tool
	Tools              = []Tool

	ProtobomType interface {
		Document | Metadata | NodeList |
			DocumentType | DocumentTypes |
			Edge | Edges |
			ExternalReference | ExternalReferences |
			Node | Nodes |
			Person | Persons |
			Purpose | Purposes |
			Tool | Tools |
			map[sbom.HashAlgorithm]string |
			map[sbom.SoftwareIdentifierType]string
	}

	Storer[T ProtobomType] interface {
		Store(T, *StoreOptions) error
	}

	Retriever[T ProtobomType] interface {
		Retrieve(string, *RetrieveOptions) (T, error)
	}

	StoreRetriever[T ProtobomType] interface {
		Storer[T]
		Retriever[T]
	}

	Backend[T ProtobomType] interface {
		StoreRetriever[T]
	}
)
