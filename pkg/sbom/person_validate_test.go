// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPersonValidate(t *testing.T) {
	require.NoError(t, (&Person{Name: "Alice"}).Validate())
	require.NoError(t, (&Person{Name: "Example Inc", IsOrg: true}).Validate())
	require.NoError(t, (&Person{Name: "scanner", IsSoftwareAgent: true}).Validate())

	err := (&Person{Name: "both", IsOrg: true, IsSoftwareAgent: true}).Validate()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPersonIsOrgAndSoftwareAgent)
	require.Contains(t, err.Error(), "both", "the message names the offender")
}

// A new field has to reach Copy, or copying quietly drops it.
func TestPersonCopyCarriesSoftwareAgent(t *testing.T) {
	agent := &Person{Name: "scanner", IsSoftwareAgent: true, Email: "s@example.com"}
	require.True(t, agent.Copy().IsSoftwareAgent)
	require.False(t, (&Person{Name: "Alice"}).Copy().IsSoftwareAgent)
}

// The flat string is what equality and diffing compare, so a software agent
// must not read as an ordinary person. It is appended only when set, so the
// strings of everything that already exists are unchanged.
func TestPersonFlatStringDistinguishesSoftwareAgent(t *testing.T) {
	person := &Person{Name: "x"}
	agent := &Person{Name: "x", IsSoftwareAgent: true}
	require.NotEqual(t, person.flatString(), agent.flatString())
	require.Equal(t, "n(x)o(false)", person.flatString())
}

// The same for nodes: the new fields have to survive a copy, and be taken by
// Update and Augment.
func TestNodeCarriesContentTypeAndFileKind(t *testing.T) {
	n := &Node{Id: "a", ContentType: "text/plain", FileKind: Node_FILE_KIND_DIRECTORY}
	c := n.Copy()
	require.Equal(t, "text/plain", c.ContentType)
	require.Equal(t, Node_FILE_KIND_DIRECTORY, c.FileKind)

	t.Run("update takes the other node's values", func(t *testing.T) {
		target := &Node{Id: "a", ContentType: "application/json", FileKind: Node_FILE_KIND_FILE}
		target.Update(n)
		require.Equal(t, "text/plain", target.ContentType)
		require.Equal(t, Node_FILE_KIND_DIRECTORY, target.FileKind)
	})

	t.Run("augment only fills what is missing", func(t *testing.T) {
		target := &Node{Id: "a", ContentType: "application/json", FileKind: Node_FILE_KIND_FILE}
		target.Augment(n)
		require.Equal(t, "application/json", target.ContentType)
		require.Equal(t, Node_FILE_KIND_FILE, target.FileKind)

		empty := &Node{Id: "a"}
		empty.Augment(n)
		require.Equal(t, "text/plain", empty.ContentType)
		require.Equal(t, Node_FILE_KIND_DIRECTORY, empty.FileKind)
	})
}
