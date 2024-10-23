// Automatically generated code. DO NOT EDIT.
// --------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright © 2024 The Protobom Authors
// SPDX-FileType: SOURCE
// SPDX-License-Identifier: Apache-2.0
// --------------------------------------------------------------

package sbom

import (
	"database/sql/driver"
	"fmt"

	"google.golang.org/protobuf/proto"
)

func (x *Document) Value() (driver.Value, error) {
	return value(x)
}

func (x *Document) Scan(src any) error {
	return scan(src, x)
}

func (x *DocumentType) Value() (driver.Value, error) {
	return value(x)
}

func (x *DocumentType) Scan(src any) error {
	return scan(src, x)
}

func (x *Edge) Value() (driver.Value, error) {
	return value(x)
}

func (x *Edge) Scan(src any) error {
	return scan(src, x)
}

func (x *ExternalReference) Value() (driver.Value, error) {
	return value(x)
}

func (x *ExternalReference) Scan(src any) error {
	return scan(src, x)
}

func (x *Metadata) Value() (driver.Value, error) {
	return value(x)
}

func (x *Metadata) Scan(src any) error {
	return scan(src, x)
}

func (x *Node) Value() (driver.Value, error) {
	return value(x)
}

func (x *Node) Scan(src any) error {
	return scan(src, x)
}

func (x *NodeList) Value() (driver.Value, error) {
	return value(x)
}

func (x *NodeList) Scan(src any) error {
	return scan(src, x)
}

func (x *Person) Value() (driver.Value, error) {
	return value(x)
}

func (x *Person) Scan(src any) error {
	return scan(src, x)
}

func (x *Property) Value() (driver.Value, error) {
	return value(x)
}

func (x *Property) Scan(src any) error {
	return scan(src, x)
}

func (x *SourceData) Value() (driver.Value, error) {
	return value(x)
}

func (x *SourceData) Scan(src any) error {
	return scan(src, x)
}

func (x *Tool) Value() (driver.Value, error) {
	return value(x)
}

func (x *Tool) Scan(src any) error {
	return scan(src, x)
}

func value(msg proto.Message) (driver.Value, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(msg)
}

func scan(src any, msg proto.Message) error {
	switch src := src.(type) {
	case nil:
		return nil
	case []byte:
		return proto.Unmarshal(src, msg)
	default:
		return fmt.Errorf("unexpected type %T", src)
	}
}
