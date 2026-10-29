// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors
// SPDX-License-Identifier: Apache-2.0

package licenselist

import (
	"fmt"
	"strings"
)

// The license expression operators that combine licenses.
const (
	OperatorAND = "AND"
	OperatorOR  = "OR"
)

// NormalizeOperator returns the license expression operator a string names,
// in the upper case SPDX writes it in, and an error if it names neither AND
// nor OR.
func NormalizeOperator(operator string) (string, error) {
	switch op := strings.ToUpper(strings.TrimSpace(operator)); op {
	case OperatorAND, OperatorOR:
		return op, nil
	default:
		return "", fmt.Errorf("invalid license expression operator %q, must be %q or %q", operator, OperatorAND, OperatorOR)
	}
}

// JoinLicenses combines a list of licenses into a single SPDX license
// expression with the given operator, AND or OR in any case. Entries that
// are compound expressions themselves are wrapped in parentheses so the
// result keeps the meaning of every entry: ["MIT OR Apache-2.0",
// "BSD-3-Clause"] joined with AND becomes "(MIT OR Apache-2.0) AND
// BSD-3-Clause" rather than an expression that binds differently. Empty
// entries are skipped. It returns an error for any other operator when
// there is more than one license to join.
func JoinLicenses(licenses []string, operator string) (string, error) {
	parts := make([]string, 0, len(licenses))
	for _, license := range licenses {
		license = strings.TrimSpace(license)
		if license == "" {
			continue
		}
		parts = append(parts, license)
	}
	if len(parts) < 2 {
		return strings.Join(parts, ""), nil
	}
	operator, err := NormalizeOperator(operator)
	if err != nil {
		return "", err
	}
	for i, part := range parts {
		if ops, _ := topLevelOperators(part); len(ops) > 0 {
			parts[i] = "(" + part + ")"
		}
	}
	return strings.Join(parts, " "+operator+" "), nil
}

// SplitLicenses takes apart an expression whose top level is nothing but
// licenses joined with the given operator and returns the entries, without
// the parentheses JoinLicenses wraps around compound ones. An expression
// whose top level uses any other operator is returned whole, since its
// pieces are not licenses on their own: "(MIT OR Apache-2.0) AND
// BSD-3-Clause" split on AND gives ["MIT OR Apache-2.0", "BSD-3-Clause"],
// while "MIT AND BSD-3-Clause OR Apache-2.0" is kept as it is. So is an
// expression with unbalanced parentheses, which cannot be taken apart
// safely. Empty entries, as in "MIT AND", are dropped.
//
// Splitting what JoinLicenses joined with the same operator keeps the
// meaning of the list, but not always its shape: a list holding a single
// compound entry is not bracketed when joined, so ["MIT AND BSD-3-Clause"]
// joined and split on AND comes back as ["MIT", "BSD-3-Clause"], which
// states the same licenses.
func SplitLicenses(expression, operator string) []string {
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return nil
	}
	ops, balanced := topLevelOperators(expression)
	if len(ops) == 0 || !balanced {
		return []string{expression}
	}
	for _, op := range ops {
		if !strings.EqualFold(op.word, strings.TrimSpace(operator)) {
			return []string{expression}
		}
	}

	parts := make([]string, 0, len(ops)+1)
	add := func(part string) {
		if part = unwrap(strings.TrimSpace(part)); part != "" {
			parts = append(parts, part)
		}
	}
	start := 0
	for _, op := range ops {
		add(expression[start:op.start])
		start = op.end
	}
	add(expression[start:])
	return parts
}

// exprOperator is an operator found in a license expression and where it is.
type exprOperator struct {
	word       string
	start, end int
}

// topLevelOperators returns the AND and OR operators of an expression that
// are not inside parentheses, and whether its parentheses are balanced. WITH
// is not one of them: it binds an exception to a single license, which
// leaves the result a single license too.
func topLevelOperators(expression string) (ops []exprOperator, balanced bool) {
	depth := 0
	for i := 0; i < len(expression); {
		switch c := expression[i]; {
		case c == '(':
			depth++
			i++
		case c == ')':
			depth--
			if depth < 0 {
				return ops, false
			}
			i++
		case isExpressionSpace(c):
			i++
		default:
			j := i
			for j < len(expression) && !isExpressionSpace(expression[j]) &&
				expression[j] != '(' && expression[j] != ')' {
				j++
			}
			word := expression[i:j]
			if depth == 0 && (strings.EqualFold(word, OperatorAND) || strings.EqualFold(word, OperatorOR)) {
				ops = append(ops, exprOperator{word: word, start: i, end: j})
			}
			i = j
		}
	}
	return ops, depth == 0
}

// unwrap removes one pair of parentheses enclosing the whole expression.
func unwrap(expression string) string {
	if len(expression) < 2 || expression[0] != '(' || expression[len(expression)-1] != ')' {
		return expression
	}
	depth := 0
	for i := range len(expression) {
		switch expression[i] {
		case '(':
			depth++
		case ')':
			depth--
			// The opening parenthesis closes before the end, as in
			// "(MIT) AND (BSD-3-Clause)", so it does not enclose everything.
			if depth == 0 && i != len(expression)-1 {
				return expression
			}
		}
	}
	return strings.TrimSpace(expression[1 : len(expression)-1])
}

func isExpressionSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// The license expression keywords and prefixes besides AND and OR.
const (
	operatorWITH     = "WITH"
	licenseRefPrefix = "LicenseRef-"
	documentRefTag   = "DocumentRef-"
)

// ListedExpression reports whether a string is a well formed SPDX license
// expression that names only licenses and exceptions in the SPDX License
// List, or license references, and returns it in canonical form: the listed
// identifiers in their canonical spelling and the operators in upper case,
// with one pair of parentheses enclosing the whole expression removed.
//
// It is how a converter tells an expression from a free-form license name
// when a format does not say which one it holds. A single listed identifier
// is an expression too, so a name that merely spells a listed license in
// another case comes back as that license.
func ListedExpression(expression string) (string, bool) {
	expression = unwrap(strings.TrimSpace(expression))
	if expression == "" {
		return "", false
	}

	var out []string
	depth := 0
	wantOperand := true
	i := 0
	for i < len(expression) {
		c := expression[i]
		switch {
		case isExpressionSpace(c):
			i++
			continue
		case c == '(':
			if !wantOperand {
				return "", false
			}
			depth++
			out = append(out, "(")
			i++
			continue
		case c == ')':
			if wantOperand || depth == 0 {
				return "", false
			}
			depth--
			out[len(out)-1] += ")"
			i++
			continue
		}

		j := i
		for j < len(expression) && !isExpressionSpace(expression[j]) &&
			expression[j] != '(' && expression[j] != ')' {
			j++
		}
		word := expression[i:j]
		i = j

		switch {
		case strings.EqualFold(word, OperatorAND), strings.EqualFold(word, OperatorOR):
			if wantOperand {
				return "", false
			}
			out = append(out, strings.ToUpper(word))
			wantOperand = true
		case strings.EqualFold(word, operatorWITH):
			// WITH binds an exception to the license just read.
			if wantOperand {
				return "", false
			}
			exception, ok := nextWord(expression, &i)
			if !ok {
				return "", false
			}
			canonical, _, listed := Exception(exception)
			if !listed {
				return "", false
			}
			out = append(out, operatorWITH, canonical)
		default:
			if !wantOperand {
				return "", false
			}
			license, ok := listedLicense(word)
			if !ok {
				return "", false
			}
			out = append(out, license)
			wantOperand = false
		}
	}
	if wantOperand || depth != 0 {
		return "", false
	}
	return joinTokens(out), true
}

// listedLicense returns the canonical form of a license token: a listed
// identifier, with the "+" suffix kept when present, or a license reference,
// which is returned as it is.
func listedLicense(token string) (string, bool) {
	if strings.HasPrefix(token, licenseRefPrefix) ||
		(strings.HasPrefix(token, documentRefTag) && strings.Contains(token, ":"+licenseRefPrefix)) {
		return token, true
	}
	plus := strings.HasSuffix(token, "+")
	if canonical, _, ok := License(strings.TrimSuffix(token, "+")); ok {
		if plus {
			return canonical + "+", true
		}
		return canonical, true
	}
	return "", false
}

// nextWord reads the next word of the expression starting at *i, skipping
// spaces, and advances *i past it. Parentheses end a word.
func nextWord(expression string, i *int) (string, bool) {
	for *i < len(expression) && isExpressionSpace(expression[*i]) {
		*i++
	}
	j := *i
	for j < len(expression) && !isExpressionSpace(expression[j]) &&
		expression[j] != '(' && expression[j] != ')' {
		j++
	}
	word := expression[*i:j]
	*i = j
	return word, word != ""
}

// joinTokens writes the tokens with single spaces, keeping an opening
// parenthesis attached to what follows it and a closing one to what
// precedes it.
func joinTokens(tokens []string) string {
	var b strings.Builder
	for i, t := range tokens {
		if i > 0 && tokens[i-1] != "(" {
			b.WriteByte(' ')
		}
		b.WriteString(t)
	}
	return b.String()
}
