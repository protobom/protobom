// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package spdx

import "strings"

// SplitActor takes apart the name and email SPDX 2 states an actor with: a
// creator, supplier or originator is written as "name (email)", with the
// parentheses present and empty when the email is not known.
//
// The parenthesized part is taken as the email only when it is empty or
// holds an "@", so a name that merely ends in a parenthesized word, such as
// "Example (Europe)", is kept whole.
func SplitActor(actor string) (name, email string) {
	actor = strings.TrimSpace(actor)
	if !strings.HasSuffix(actor, ")") {
		return actor, ""
	}
	open := strings.LastIndex(actor, "(")
	if open < 0 {
		return actor, ""
	}
	inner := strings.TrimSpace(actor[open+1 : len(actor)-1])
	if inner != "" && !strings.Contains(inner, "@") {
		return actor, ""
	}
	return strings.TrimSpace(actor[:open]), inner
}
