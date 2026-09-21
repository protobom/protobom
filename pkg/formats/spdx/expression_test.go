// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package spdx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJoinLicenses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		licenses []string
		operator string
		expected string
	}{
		{"none", nil, OperatorAND, ""},
		{"one simple", []string{"MIT"}, OperatorAND, "MIT"},
		{"one compound is not wrapped", []string{"MIT OR Apache-2.0"}, OperatorAND, "MIT OR Apache-2.0"},
		{"simple entries", []string{"MIT", "Apache-2.0"}, OperatorAND, "MIT AND Apache-2.0"},
		{"simple entries with OR", []string{"MIT", "Apache-2.0"}, OperatorOR, "MIT OR Apache-2.0"},
		{
			"compound entry is wrapped",
			[]string{"GPL-2.0-or-later OR LGPL-3.0-or-later", "MIT"},
			OperatorAND,
			"(GPL-2.0-or-later OR LGPL-3.0-or-later) AND MIT",
		},
		{
			"conjunction joined with OR is wrapped",
			[]string{"MIT AND BSD-3-Clause", "Apache-2.0"},
			OperatorOR,
			"(MIT AND BSD-3-Clause) OR Apache-2.0",
		},
		{
			"exception is not compound",
			[]string{"GPL-2.0-only WITH Classpath-exception-2.0", "MIT"},
			OperatorAND,
			"GPL-2.0-only WITH Classpath-exception-2.0 AND MIT",
		},
		{
			"already bracketed entry is not wrapped twice",
			[]string{"(MIT OR Apache-2.0)", "BSD-3-Clause"},
			OperatorAND,
			"(MIT OR Apache-2.0) AND BSD-3-Clause",
		},
		{"empty entries are skipped", []string{"", "MIT", " "}, OperatorAND, "MIT"},
		{"lower case operator", []string{"MIT", "Apache-2.0"}, "and", "MIT AND Apache-2.0"},
		{"operator with spaces", []string{"MIT", "Apache-2.0"}, " Or ", "MIT OR Apache-2.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			joined, err := JoinLicenses(tc.licenses, tc.operator)
			require.NoError(t, err)
			require.Equal(t, tc.expected, joined)
		})
	}
}

func TestJoinLicensesInvalidOperator(t *testing.T) {
	t.Parallel()
	for _, op := range []string{"", "WITH", "XOR", "&&"} {
		_, err := JoinLicenses([]string{"MIT", "Apache-2.0"}, op)
		require.Error(t, err, op)
	}
	// With a single license there is nothing to join.
	joined, err := JoinLicenses([]string{"MIT"}, "")
	require.NoError(t, err)
	require.Equal(t, "MIT", joined)
}

func TestNormalizeOperator(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, expected string }{
		{"AND", "AND"}, {"and", "AND"}, {" or ", "OR"}, {"Or", "OR"},
	} {
		op, err := NormalizeOperator(tc.in)
		require.NoError(t, err)
		require.Equal(t, tc.expected, op)
	}
	_, err := NormalizeOperator("NOT")
	require.Error(t, err)
}

func TestSplitLicenses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		expression string
		operator   string
		expected   []string
	}{
		{"single license", "MIT", OperatorAND, []string{"MIT"}},
		{"conjunction", "MIT AND Apache-2.0", OperatorAND, []string{"MIT", "Apache-2.0"}},
		{"disjunction split on OR", "MIT OR Apache-2.0", OperatorOR, []string{"MIT", "Apache-2.0"}},
		{"other operator is kept whole", "MIT OR Apache-2.0", OperatorAND, []string{"MIT OR Apache-2.0"}},
		{
			"mixed top level is kept whole",
			"MIT AND BSD-3-Clause OR Apache-2.0", OperatorAND,
			[]string{"MIT AND BSD-3-Clause OR Apache-2.0"},
		},
		{
			"bracketed entries are unwrapped",
			"(GPL-2.0-or-later OR LGPL-3.0-or-later) AND MIT", OperatorAND,
			[]string{"GPL-2.0-or-later OR LGPL-3.0-or-later", "MIT"},
		},
		{
			"a single bracketed expression is kept",
			"(BSD-3-Clause AND GPL-3.0-or-later)", OperatorAND,
			[]string{"(BSD-3-Clause AND GPL-3.0-or-later)"},
		},
		{
			"top level OR around a bracketed conjunction is kept",
			"(MIT AND BSD-3-Clause) OR Apache-2.0", OperatorAND,
			[]string{"(MIT AND BSD-3-Clause) OR Apache-2.0"},
		},
		{
			"exception stays with its license",
			"GPL-2.0-only WITH Classpath-exception-2.0 AND MIT", OperatorAND,
			[]string{"GPL-2.0-only WITH Classpath-exception-2.0", "MIT"},
		},
		{
			"only enclosing parentheses are removed",
			"((MIT) AND (BSD-3-Clause)) AND Apache-2.0", OperatorAND,
			[]string{"(MIT) AND (BSD-3-Clause)", "Apache-2.0"},
		},
		{"empty", "", OperatorAND, nil},
		{"lower case operator", "MIT and Apache-2.0", OperatorAND, []string{"MIT", "Apache-2.0"}},
		{"only an operator", "AND", OperatorAND, []string{}},
		{"trailing operator", "MIT AND", OperatorAND, []string{"MIT"}},
		{"leading and doubled operators", "AND MIT AND AND Apache-2.0", OperatorAND, []string{"MIT", "Apache-2.0"}},
		{"empty parentheses", "() AND MIT", OperatorAND, []string{"MIT"}},
		{
			"unclosed parenthesis is kept whole",
			"(MIT OR Apache-2.0 AND BSD-3-Clause", OperatorAND,
			[]string{"(MIT OR Apache-2.0 AND BSD-3-Clause"},
		},
		{
			"stray closing parenthesis is kept whole",
			"MIT) AND (Apache-2.0", OperatorAND,
			[]string{"MIT) AND (Apache-2.0"},
		},
		{"unknown operator is kept whole", "MIT AND Apache-2.0", "XOR", []string{"MIT AND Apache-2.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expected, SplitLicenses(tc.expression, tc.operator))
		})
	}
}

// Joining and splitting with the same operator gives the list back.
func TestJoinSplitLicensesRoundTrip(t *testing.T) {
	t.Parallel()
	for _, licenses := range [][]string{
		{"MIT"},
		{"MIT", "Apache-2.0"},
		{"GPL-2.0-or-later OR LGPL-3.0-or-later", "MIT"},
		{"MIT AND BSD-3-Clause", "Apache-2.0 OR MIT"},
	} {
		for _, op := range []string{OperatorAND, OperatorOR} {
			joined, err := JoinLicenses(licenses, op)
			require.NoError(t, err)
			require.Equal(t, licenses, SplitLicenses(joined, op))
		}
	}
}

// A single compound entry is not bracketed, so it comes back split into the
// licenses it joins, which means the same.
func TestJoinSplitLicensesSingleCompoundEntry(t *testing.T) {
	t.Parallel()
	joined, err := JoinLicenses([]string{"MIT AND BSD-3-Clause"}, OperatorAND)
	require.NoError(t, err)
	require.Equal(t, "MIT AND BSD-3-Clause", joined)
	require.Equal(t, []string{"MIT", "BSD-3-Clause"}, SplitLicenses(joined, OperatorAND))
}
