// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package spdx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplitActor(t *testing.T) {
	for name, tc := range map[string]struct {
		actor, name, email string
	}{
		"name and email":          {"Jane Doe (jane@example.com)", "Jane Doe", "jane@example.com"},
		"empty email":             {"Acme ()", "Acme", ""},
		"no parentheses":          {"Acme", "Acme", ""},
		"surrounding whitespace":  {"  Acme (acme@example.com)  ", "Acme", "acme@example.com"},
		"spaces inside":           {"Acme ( acme@example.com )", "Acme", "acme@example.com"},
		"parenthesized word kept": {"Example (Europe)", "Example (Europe)", ""},
		"email with parentheses":  {"Acme, Inc. (sales@acme.example)", "Acme, Inc.", "sales@acme.example"},
		"only an email":           {"(jane@example.com)", "", "jane@example.com"},
		"empty":                   {"", "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			gotName, gotEmail := SplitActor(tc.actor)
			require.Equal(t, tc.name, gotName)
			require.Equal(t, tc.email, gotEmail)
		})
	}
}
