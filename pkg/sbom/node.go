package sbom

import (
	"crypto/sha256"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// This file contains methods to work with the generated node type
// updates to the node proto should also be reflected in most of these
// functions as they operate on the Node's fields

func NewNode() *Node {
	return &Node{
		Licenses:           []string{},
		Attribution:        []string{},
		Suppliers:          []*Person{},
		Originators:        []*Person{},
		ExternalReferences: []*ExternalReference{},
		FileTypes:          []string{},
		Identifiers:        map[int32]string{},
		Hashes:             map[int32]string{},
	}
}

// Update updates a node's fields with information from the second node
// Any fields in n2 which are not null (empty string, lists longer than 0 or not nill
// pointers will overwrite fields in Node n.
func (n *Node) Update(n2 *Node) {
	if n2.Name != "" {
		n.Name = n2.Name
	}
	if n2.Version != "" {
		n.Version = n2.Version
	}
	if n2.FileName != "" {
		n.FileName = n2.FileName
	}
	if n2.UrlHome != "" {
		n.UrlHome = n2.UrlHome
	}
	if n2.UrlDownload != "" {
		n.UrlDownload = n2.UrlDownload
	}
	if len(n2.Licenses) > 0 {
		n.Licenses = n2.Licenses
	}
	if n2.LicenseConcluded != "" {
		n.LicenseConcluded = n2.LicenseConcluded
	}
	if n2.LicenseComments != "" {
		n.LicenseComments = n2.LicenseComments
	}
	if n2.Copyright != "" {
		n.Copyright = n2.Copyright
	}
	if len(n2.Hashes) > 0 {
		n.Hashes = n2.Hashes
	}
	if n2.SourceInfo != "" {
		n.SourceInfo = n2.SourceInfo
	}
	if len(n2.PrimaryPurpose) > 0 {
		n.PrimaryPurpose = n2.PrimaryPurpose
	}
	if n2.Comment != "" {
		n.Comment = n2.Comment
	}
	if n2.Summary != "" {
		n.Summary = n2.Summary
	}
	if n2.Description != "" {
		n.Description = n2.Description
	}
	if len(n2.Attribution) > 0 {
		n.Attribution = n2.Attribution
	}
	if len(n2.Suppliers) > 0 {
		n.Suppliers = n2.Suppliers
	}
	if len(n2.Originators) > 0 {
		n.Originators = n2.Originators
	}
	if n2.ReleaseDate != nil {
		n.ReleaseDate = n2.ReleaseDate
	}
	if n2.BuildDate != nil {
		n.BuildDate = n2.BuildDate
	}
	if n2.ValidUntilDate != nil {
		n.ValidUntilDate = n2.ValidUntilDate
	}
	if len(n2.ExternalReferences) > 0 {
		n.ExternalReferences = n2.ExternalReferences
	}
	if len(n2.Identifiers) > 0 {
		n.Identifiers = n2.Identifiers
	}
	if len(n2.FileTypes) > 0 {
		n.FileTypes = n2.FileTypes
	}
}

// Augment takes updates fields in n with data from n2 which is not already defined
// (not empty string, not 0 length string, not nill pointer).
func (n *Node) Augment(n2 *Node) {
	if n.Name == "" && n2.Name != "" {
		n.Name = n2.Name
	}
	if n.Version == "" && n2.Version != "" {
		n.Version = n2.Version
	}
	if n.FileName == "" && n2.FileName != "" {
		n.FileName = n2.FileName
	}
	if n.UrlHome == "" && n2.UrlHome != "" {
		n.UrlHome = n2.UrlHome
	}
	if n.UrlDownload == "" && n2.UrlDownload != "" {
		n.UrlDownload = n2.UrlDownload
	}
	if len(n.Licenses) == 0 && len(n2.Licenses) > 0 {
		n.Licenses = n2.Licenses
	}
	if n.LicenseConcluded == "" && n2.LicenseConcluded != "" {
		n.LicenseConcluded = n2.LicenseConcluded
	}
	if n.LicenseComments == "" && n2.LicenseComments != "" {
		n.LicenseComments = n2.LicenseComments
	}
	if n.Copyright == "" && n2.Copyright != "" {
		n.Copyright = n2.Copyright
	}
	if len(n.Hashes) == 0 && len(n2.Hashes) > 0 {
		n.Hashes = n2.Hashes
	}
	if n.SourceInfo == "" && n2.SourceInfo != "" {
		n.SourceInfo = n2.SourceInfo
	}
	if len(n.PrimaryPurpose) == 0 && len(n2.PrimaryPurpose) > 0 {
		n.PrimaryPurpose = n2.PrimaryPurpose
	}
	if n.Comment == "" && n2.Comment != "" {
		n.Comment = n2.Comment
	}
	if n.Summary == "" && n2.Summary != "" {
		n.Summary = n2.Summary
	}
	if n.Description == "" && n2.Description != "" {
		n.Description = n2.Description
	}
	if len(n.Attribution) == 0 && len(n2.Attribution) > 0 {
		n.Attribution = n2.Attribution
	}
	if len(n.Suppliers) == 0 && len(n2.Suppliers) > 0 {
		n.Suppliers = n2.Suppliers
	}
	if len(n.Originators) == 0 && len(n2.Originators) > 0 {
		n.Originators = n2.Originators
	}
	if n.ReleaseDate == nil && n2.ReleaseDate != nil {
		n.ReleaseDate = n2.ReleaseDate
	}
	if n.BuildDate == nil && n2.BuildDate != nil {
		n.BuildDate = n2.BuildDate
	}
	if n.ValidUntilDate == nil && n2.ValidUntilDate != nil {
		n.ValidUntilDate = n2.ValidUntilDate
	}
	if len(n.ExternalReferences) == 0 && len(n2.ExternalReferences) > 0 {
		n.ExternalReferences = n2.ExternalReferences
	}
	if len(n.Identifiers) == 0 && len(n2.Identifiers) > 0 {
		n.Identifiers = n2.Identifiers
	}
	if len(n.FileTypes) == 0 && len(n2.FileTypes) > 0 {
		n.FileTypes = n2.FileTypes
	}
}

// Copy returns a new node that is a copy of the node
func (n *Node) Copy() *Node {
	no := &Node{
		Id:                 n.Id,
		Type:               n.Type,
		Name:               n.Name,
		Version:            n.Version,
		FileName:           n.FileName,
		UrlHome:            n.UrlHome,
		UrlDownload:        n.UrlDownload,
		Licenses:           slices.Clone(n.Licenses),
		LicenseConcluded:   n.LicenseConcluded,
		LicenseComments:    n.LicenseComments,
		Copyright:          n.Copyright,
		Hashes:             maps.Clone(n.Hashes),
		SourceInfo:         n.SourceInfo,
		PrimaryPurpose:     n.PrimaryPurpose,
		Comment:            n.Comment,
		Summary:            n.Summary,
		Description:        n.Description,
		Attribution:        slices.Clone(n.Attribution),
		Suppliers:          []*Person{},
		Originators:        []*Person{},
		ReleaseDate:        nil,
		BuildDate:          nil,
		ValidUntilDate:     nil,
		ExternalReferences: []*ExternalReference{},
		Identifiers:        maps.Clone(n.Identifiers),
		FileTypes:          slices.Clone(n.FileTypes),
	}

	if n.ReleaseDate != nil {
		no.ReleaseDate = timestamppb.New(n.ReleaseDate.AsTime())
	}
	if n.BuildDate != nil {
		no.BuildDate = timestamppb.New(n.BuildDate.AsTime())
	}
	if n.ValidUntilDate != nil {
		no.ValidUntilDate = timestamppb.New(n.ValidUntilDate.AsTime())
	}

	for _, p := range n.Suppliers {
		no.Suppliers = append(no.Suppliers, p.Copy())
	}
	for _, p := range n.Originators {
		no.Originators = append(no.Originators, p.Copy())
	}
	for _, e := range n.ExternalReferences {
		no.ExternalReferences = append(no.ExternalReferences, e.Copy())
	}

	return no
}

// Equal compares Node n to n2 and returns true if they are the same
func (n *Node) Equal(n2 *Node) bool {
	if n2 == nil {
		return false
	}
	return n.flatString() == n2.flatString()
}

// flatString returns a string representation of the node which can be used to
// index the node or compare it against another
func (n *Node) flatString() string {
	pairs := []string{}
	n.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch fd.FullName() {
		case "bomsquad.protobom.Node.external_references":
			for _, ex := range n.ExternalReferences {
				pairs = append(pairs, fmt.Sprintf("extref:%s", ex.flatString()))
			}
		case "bomsquad.protobom.Node.suppliers":
			for _, i := range n.Suppliers {
				pairs = append(pairs, fmt.Sprintf("supplier:%s", i.flatString()))
			}
		case "bomsquad.protobom.Node.originators":
			for _, i := range n.Originators {
				pairs = append(pairs, fmt.Sprintf("originator:%s", i.flatString()))
			}
		case "bomsquad.protobom.Node.identifiers":
			// Index the keys and sort them to make the string deterministic
			idKeys := []int{}
			for t := range n.Identifiers {
				idKeys = append(idKeys, int(t))
			}
			sort.Ints(idKeys)
			for _, t := range idKeys {
				pairs = append(pairs, fmt.Sprintf("identifiers[%d]:%s", t, n.Identifiers[int32(t)]))
			}
		case "bomsquad.protobom.Node.release_date":
			if n.ReleaseDate != nil {
				pairs = append(pairs, fmt.Sprintf("%s:%d", fd.FullName(), n.ReleaseDate.AsTime().Unix()))
			}
		case "bomsquad.protobom.Node.valid_until_date":
			if n.ValidUntilDate != nil {
				pairs = append(pairs, fmt.Sprintf("%s:%d", fd.FullName(), n.ValidUntilDate.AsTime().Unix()))
			}
		case "bomsquad.protobom.Node.build_date":
			if n.BuildDate != nil {
				pairs = append(pairs, fmt.Sprintf("%s:%d", fd.FullName(), n.BuildDate.AsTime().Unix()))
			}
		case "bomsquad.protobom.Node.hashes":
			pairs = append(pairs, string(fd.FullName())+":"+flatStringMap(v.Map()))
		case "bomsquad.protobom.Node.licenses",
			"bomsquad.protobom.Node.attribution",
			"bomsquad.protobom.Node.file_types",
			"bomsquad.protobom.Node.primary_purpose":
			pairs = append(pairs, flatStringStrSlice(fd.FullName(), v.List()))

		default:
			pairs = append(pairs, string(fd.FullName())+":"+v.String())
		}
		return true
	})

	sort.Strings(pairs)
	return strings.Join(pairs, ":")
}

// flatStringStrSlice returns a deterministic string representation of a slice of strings
func flatStringStrSlice(name protoreflect.FullName, protoSlice protoreflect.List) string {
	vals := []string{}
	for i := 0; i < protoSlice.Len(); i++ {
		vals = append(vals, protoSlice.Get(i).String())
	}
	slices.Sort(vals)
	ret := ""
	for i, s := range vals {
		ret += fmt.Sprintf("%s[%d]:%s", name, i, s)
	}
	return ret
}

func flatStringMap(protoMap protoreflect.Map) string {
	keys := []string{}
	values := map[string]string{}
	protoMap.Range(func(mk protoreflect.MapKey, v protoreflect.Value) bool {
		keys = append(keys, mk.String())
		values[mk.String()] = v.String()
		return true
	})

	sort.Strings(keys)
	ret := ""
	for _, algo := range keys {
		ret += fmt.Sprintf("%s:%s", algo, values[algo])
	}

	return ret
}

// Checksum returns a a sha256 hash representing the node's data
func (n *Node) Checksum() string {
	sum := sha256.Sum256([]byte(n.flatString()))
	return fmt.Sprintf("%x", sum)
}

type PackageURL string

// Purl returns the node purl as a string
func (n *Node) Purl() PackageURL {
	if n.Type == Node_FILE {
		return ""
	}

	if _, ok := n.Identifiers[int32(SoftwareIdentifierType_PURL)]; ok {
		return PackageURL(n.Identifiers[int32(SoftwareIdentifierType_PURL)])
	}

	return ""
}

// HashesMatch takes a map of hashes th and returns a boolean indicating
// if the test hashes match those of the node. The algorithm will only take
// into account algorithms that are common to the node and test set.
//
// In other words, if th has any hashes in algorithms without a peer in the
// node, the function will ignore them and return true if others match,
// silently ignoring those missing in the node.
//
// If either the node or the test hashes are empty, no match is assumed.
func (n *Node) HashesMatch(th map[int32]string) bool {
	if len(n.Hashes) == 0 || len(th) == 0 {
		return false
	}
	atLeastOneMatch := false
	for algo, hashValue := range th {
		if _, ok := n.Hashes[algo]; !ok {
			continue
		}

		if n.Hashes[algo] != hashValue {
			return false
		}
		atLeastOneMatch = true
	}
	return atLeastOneMatch
}

// AddHash adds a new hash of algorithm algo to the node. If the node
// already has a hash of the same algorithm it will get silently replaced.
func (n *Node) AddHash(algo HashAlgorithm, value string) {
	if value == "" {
		return
	}
	if n.Hashes == nil {
		n.Hashes = map[int32]string{}
	}
	n.Hashes[int32(algo)] = value
}
