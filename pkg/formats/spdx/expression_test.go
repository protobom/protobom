// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package spdx

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/protobom/protobom/pkg/licenselist"
)

// The forwarders must keep answering as the licenselist package does until
// they are removed.
func TestExpressionForwarders(t *testing.T) {
	require.Equal(t, licenselist.OperatorAND, OperatorAND)
	require.Equal(t, licenselist.OperatorOR, OperatorOR)

	op, err := NormalizeOperator(" or ")
	require.NoError(t, err)
	require.Equal(t, licenselist.OperatorOR, op)

	joined, err := JoinLicenses([]string{"MIT", "Apache-2.0 OR ISC"}, "and")
	require.NoError(t, err)
	require.Equal(t, "MIT AND (Apache-2.0 OR ISC)", joined)

	require.Equal(t, []string{"MIT", "Apache-2.0 OR ISC"}, SplitLicenses(joined, "AND"))
}
