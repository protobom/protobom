// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package spdx

import "github.com/protobom/protobom/pkg/licenselist"

// The license expression grammar now lives in the licenselist package next to
// the SPDX License List it checks against. These names forward to it so
// existing callers keep working.
//
// Deprecated: use the licenselist package. The forwarders will be removed in a
// future release, no date has been set.
const (
	OperatorAND = licenselist.OperatorAND
	OperatorOR  = licenselist.OperatorOR
)

// NormalizeOperator forwards to licenselist.NormalizeOperator.
//
// Deprecated: use licenselist.NormalizeOperator. This forwarder will be
// removed in a future release, no date has been set.
func NormalizeOperator(operator string) (string, error) {
	return licenselist.NormalizeOperator(operator)
}

// JoinLicenses forwards to licenselist.JoinLicenses.
//
// Deprecated: use licenselist.JoinLicenses. This forwarder will be removed in
// a future release, no date has been set.
func JoinLicenses(licenses []string, operator string) (string, error) {
	return licenselist.JoinLicenses(licenses, operator)
}

// SplitLicenses forwards to licenselist.SplitLicenses.
//
// Deprecated: use licenselist.SplitLicenses. This forwarder will be removed in
// a future release, no date has been set.
func SplitLicenses(expression, operator string) []string {
	return licenselist.SplitLicenses(expression, operator)
}
