// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package unserializers

import (
	"errors"
	"fmt"
	"io"

	spdx3 "github.com/carabiner-dev/spdx3"
	"github.com/carabiner-dev/spdx3/profiles/core"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
)

var _ native.Unserializer = &SPDX3{}

// spdx3SpecVersion is the version of the specification this reader
// understands. A document that says it is any other version is not read as
// though it were this one.
const spdx3SpecVersion = "3.0.1"

// errNoSpdxDocument is returned for a graph carrying no document element.
// SPDX 3 allows a bare element as the whole payload, but protobom reads
// bills of materials, and one is always carried by a document.
var errNoSpdxDocument = errors.New("no SpdxDocument element in the graph")

// SPDX3 reads SPDX 3.0.1 documents into protobom.
type SPDX3 struct{}

func NewSPDX3() *SPDX3 {
	return &SPDX3{}
}

// Unserialize reads an SPDX 3 document from a stream.
func (u *SPDX3) Unserialize(r io.Reader, _ *native.UnserializeOptions, _ interface{}) (*sbom.Document, error) {
	env, err := spdx3.NewParser().Parse(r)
	if err != nil {
		return nil, fmt.Errorf("parsing SPDX 3 document: %w", err)
	}

	document, err := spdx3DocumentElement(env)
	if err != nil {
		return nil, err
	}

	if err := checkSPDX3Version(env, document); err != nil {
		return nil, err
	}

	bom := sbom.NewDocument()
	bom.Metadata.Id = document.GetSPDXID()
	bom.Metadata.Name = document.Name
	bom.Metadata.Comment = document.Comment

	// TODO(degradation): SPDX 3 has no version for the document itself, so
	// Metadata.Version has nothing to read.

	if ci := document.CreationInfo; ci != nil && ci.Created != nil {
		bom.Metadata.Date = timestamppb.New(ci.Created.Value)
	}

	// The elements, the relationships between them and the agents the
	// document credits are read in the steps that follow this one.

	return bom, nil
}

// spdx3DocumentElement returns the graph's document element, which is what
// says the document is a document rather than a loose collection of elements.
func spdx3DocumentElement(env *spdx3.Envelope) (*core.SpdxDocument, error) {
	for _, node := range env.Graph {
		if document, ok := node.(*core.SpdxDocument); ok {
			return document, nil
		}
	}
	return nil, errNoSpdxDocument
}

// checkSPDX3Version reads the version the document states and refuses to
// read one this reader does not understand, rather than reading it as though
// it were 3.0.1 and quietly making up the difference.
//
// The version is stated in the creation information, which every element
// carries; the context URL pins it as well, and the two are checked against
// each other, since a document that says two different things about its own
// version is not one to guess about.
func checkSPDX3Version(env *spdx3.Envelope, document *core.SpdxDocument) error {
	stated := ""
	if document.CreationInfo != nil {
		stated = document.CreationInfo.SpecVersion
	}
	if stated == "" {
		return errors.New("document states no specVersion")
	}
	if stated != spdx3SpecVersion {
		return fmt.Errorf(
			"unsupported SPDX version %q, this reader understands %s",
			stated, spdx3SpecVersion,
		)
	}

	// An absent or unrecognized context is not fatal: the version the
	// document states about itself is what governs.
	if context := env.Context.Version(); context != "" && context != stated {
		return fmt.Errorf(
			"document states version %s but its @context is for %s",
			stated, context,
		)
	}
	return nil
}
