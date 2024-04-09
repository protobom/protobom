// Code generated by ent, DO NOT EDIT.
// ------------------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright © 2024 The Protobom Authors
// SPDX-FileType: SOURCE
// SPDX-License-Identifier: Apache-2.0
// ------------------------------------------------------------------------
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ------------------------------------------------------------------------

package externalreference

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/bom-squad/protobom/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...int) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id int) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldLTE(FieldID, id))
}

// URL applies equality check predicate on the "url" field. It's identical to URLEQ.
func URL(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldEQ(FieldURL, v))
}

// Comment applies equality check predicate on the "comment" field. It's identical to CommentEQ.
func Comment(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldEQ(FieldComment, v))
}

// Authority applies equality check predicate on the "authority" field. It's identical to AuthorityEQ.
func Authority(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldEQ(FieldAuthority, v))
}

// URLEQ applies the EQ predicate on the "url" field.
func URLEQ(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldEQ(FieldURL, v))
}

// URLNEQ applies the NEQ predicate on the "url" field.
func URLNEQ(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldNEQ(FieldURL, v))
}

// URLIn applies the In predicate on the "url" field.
func URLIn(vs ...string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldIn(FieldURL, vs...))
}

// URLNotIn applies the NotIn predicate on the "url" field.
func URLNotIn(vs ...string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldNotIn(FieldURL, vs...))
}

// URLGT applies the GT predicate on the "url" field.
func URLGT(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldGT(FieldURL, v))
}

// URLGTE applies the GTE predicate on the "url" field.
func URLGTE(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldGTE(FieldURL, v))
}

// URLLT applies the LT predicate on the "url" field.
func URLLT(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldLT(FieldURL, v))
}

// URLLTE applies the LTE predicate on the "url" field.
func URLLTE(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldLTE(FieldURL, v))
}

// URLContains applies the Contains predicate on the "url" field.
func URLContains(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldContains(FieldURL, v))
}

// URLHasPrefix applies the HasPrefix predicate on the "url" field.
func URLHasPrefix(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldHasPrefix(FieldURL, v))
}

// URLHasSuffix applies the HasSuffix predicate on the "url" field.
func URLHasSuffix(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldHasSuffix(FieldURL, v))
}

// URLEqualFold applies the EqualFold predicate on the "url" field.
func URLEqualFold(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldEqualFold(FieldURL, v))
}

// URLContainsFold applies the ContainsFold predicate on the "url" field.
func URLContainsFold(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldContainsFold(FieldURL, v))
}

// CommentEQ applies the EQ predicate on the "comment" field.
func CommentEQ(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldEQ(FieldComment, v))
}

// CommentNEQ applies the NEQ predicate on the "comment" field.
func CommentNEQ(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldNEQ(FieldComment, v))
}

// CommentIn applies the In predicate on the "comment" field.
func CommentIn(vs ...string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldIn(FieldComment, vs...))
}

// CommentNotIn applies the NotIn predicate on the "comment" field.
func CommentNotIn(vs ...string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldNotIn(FieldComment, vs...))
}

// CommentGT applies the GT predicate on the "comment" field.
func CommentGT(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldGT(FieldComment, v))
}

// CommentGTE applies the GTE predicate on the "comment" field.
func CommentGTE(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldGTE(FieldComment, v))
}

// CommentLT applies the LT predicate on the "comment" field.
func CommentLT(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldLT(FieldComment, v))
}

// CommentLTE applies the LTE predicate on the "comment" field.
func CommentLTE(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldLTE(FieldComment, v))
}

// CommentContains applies the Contains predicate on the "comment" field.
func CommentContains(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldContains(FieldComment, v))
}

// CommentHasPrefix applies the HasPrefix predicate on the "comment" field.
func CommentHasPrefix(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldHasPrefix(FieldComment, v))
}

// CommentHasSuffix applies the HasSuffix predicate on the "comment" field.
func CommentHasSuffix(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldHasSuffix(FieldComment, v))
}

// CommentEqualFold applies the EqualFold predicate on the "comment" field.
func CommentEqualFold(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldEqualFold(FieldComment, v))
}

// CommentContainsFold applies the ContainsFold predicate on the "comment" field.
func CommentContainsFold(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldContainsFold(FieldComment, v))
}

// AuthorityEQ applies the EQ predicate on the "authority" field.
func AuthorityEQ(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldEQ(FieldAuthority, v))
}

// AuthorityNEQ applies the NEQ predicate on the "authority" field.
func AuthorityNEQ(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldNEQ(FieldAuthority, v))
}

// AuthorityIn applies the In predicate on the "authority" field.
func AuthorityIn(vs ...string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldIn(FieldAuthority, vs...))
}

// AuthorityNotIn applies the NotIn predicate on the "authority" field.
func AuthorityNotIn(vs ...string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldNotIn(FieldAuthority, vs...))
}

// AuthorityGT applies the GT predicate on the "authority" field.
func AuthorityGT(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldGT(FieldAuthority, v))
}

// AuthorityGTE applies the GTE predicate on the "authority" field.
func AuthorityGTE(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldGTE(FieldAuthority, v))
}

// AuthorityLT applies the LT predicate on the "authority" field.
func AuthorityLT(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldLT(FieldAuthority, v))
}

// AuthorityLTE applies the LTE predicate on the "authority" field.
func AuthorityLTE(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldLTE(FieldAuthority, v))
}

// AuthorityContains applies the Contains predicate on the "authority" field.
func AuthorityContains(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldContains(FieldAuthority, v))
}

// AuthorityHasPrefix applies the HasPrefix predicate on the "authority" field.
func AuthorityHasPrefix(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldHasPrefix(FieldAuthority, v))
}

// AuthorityHasSuffix applies the HasSuffix predicate on the "authority" field.
func AuthorityHasSuffix(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldHasSuffix(FieldAuthority, v))
}

// AuthorityIsNil applies the IsNil predicate on the "authority" field.
func AuthorityIsNil() predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldIsNull(FieldAuthority))
}

// AuthorityNotNil applies the NotNil predicate on the "authority" field.
func AuthorityNotNil() predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldNotNull(FieldAuthority))
}

// AuthorityEqualFold applies the EqualFold predicate on the "authority" field.
func AuthorityEqualFold(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldEqualFold(FieldAuthority, v))
}

// AuthorityContainsFold applies the ContainsFold predicate on the "authority" field.
func AuthorityContainsFold(v string) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldContainsFold(FieldAuthority, v))
}

// TypeEQ applies the EQ predicate on the "type" field.
func TypeEQ(v Type) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldEQ(FieldType, v))
}

// TypeNEQ applies the NEQ predicate on the "type" field.
func TypeNEQ(v Type) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldNEQ(FieldType, v))
}

// TypeIn applies the In predicate on the "type" field.
func TypeIn(vs ...Type) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldIn(FieldType, vs...))
}

// TypeNotIn applies the NotIn predicate on the "type" field.
func TypeNotIn(vs ...Type) predicate.ExternalReference {
	return predicate.ExternalReference(sql.FieldNotIn(FieldType, vs...))
}

// HasHashes applies the HasEdge predicate on the "hashes" edge.
func HasHashes() predicate.ExternalReference {
	return predicate.ExternalReference(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, HashesTable, HashesColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasHashesWith applies the HasEdge predicate on the "hashes" edge with a given conditions (other predicates).
func HasHashesWith(preds ...predicate.HashesEntry) predicate.ExternalReference {
	return predicate.ExternalReference(func(s *sql.Selector) {
		step := newHashesStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasNode applies the HasEdge predicate on the "node" edge.
func HasNode() predicate.ExternalReference {
	return predicate.ExternalReference(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, NodeTable, NodeColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasNodeWith applies the HasEdge predicate on the "node" edge with a given conditions (other predicates).
func HasNodeWith(preds ...predicate.Node) predicate.ExternalReference {
	return predicate.ExternalReference(func(s *sql.Selector) {
		step := newNodeStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.ExternalReference) predicate.ExternalReference {
	return predicate.ExternalReference(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.ExternalReference) predicate.ExternalReference {
	return predicate.ExternalReference(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.ExternalReference) predicate.ExternalReference {
	return predicate.ExternalReference(sql.NotPredicates(p))
}
