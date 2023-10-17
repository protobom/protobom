package sbom

import (
	"slices"
	"time"

	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

type NodeDiff struct {
	Added     *Node
	Removed   *Node
	DiffCount int
}

// Diff analyses a node and returns a a new node populated with all fields
// that are different in n2 from n. If no changes are found, Diff returns nil
func (n *Node) Diff(n2 *Node) *NodeDiff {
	nd := NodeDiff{
		Added:   &Node{},
		Removed: &Node{},
	}

	a, r, c := diffString(n.Id, n2.Id)
	nd.Added.Id = a
	nd.Removed.Id = r
	nd.DiffCount += c

	if n.Type != n2.Type {
		nd.Added.Type = n2.Type
		nd.DiffCount++
	}

	a, r, c = diffString(n.Name, n2.Name)
	nd.Added.Name = a
	nd.Removed.Name = r
	nd.DiffCount += c

	a, r, c = diffString(n.Version, n2.Version)
	nd.Added.Version = a
	nd.Removed.Version = r
	nd.DiffCount += c

	a, r, c = diffString(n.FileName, n2.FileName)
	nd.Added.FileName = a
	nd.Removed.FileName = r
	nd.DiffCount += c

	a, r, c = diffString(n.UrlHome, n2.UrlHome)
	nd.Added.UrlHome = a
	nd.Removed.UrlHome = r
	nd.DiffCount += c

	a, r, c = diffString(n.UrlDownload, n2.UrlDownload)
	nd.Added.UrlDownload = a
	nd.Removed.UrlDownload = r
	nd.DiffCount += c

	a, r, c = diffString(n.LicenseConcluded, n2.LicenseConcluded)
	nd.Added.LicenseConcluded = a
	nd.Removed.LicenseConcluded = r
	nd.DiffCount += c

	a, r, c = diffString(n.LicenseComments, n2.LicenseComments)
	nd.Added.LicenseComments = a
	nd.Removed.LicenseComments = r
	nd.DiffCount += c

	a, r, c = diffString(n.Copyright, n2.Copyright)
	nd.Added.Copyright = a
	nd.Removed.Copyright = r
	nd.DiffCount += c

	a, r, c = diffString(n.SourceInfo, n2.SourceInfo)
	nd.Added.SourceInfo = a
	nd.Removed.SourceInfo = r
	nd.DiffCount += c

	a, r, c = diffString(n.PrimaryPurpose, n2.PrimaryPurpose)
	nd.Added.PrimaryPurpose = a
	nd.Removed.PrimaryPurpose = r
	nd.DiffCount += c

	a, r, c = diffString(n.Comment, n2.Comment)
	nd.Added.Comment = a
	nd.Removed.Comment = r
	nd.DiffCount += c

	a, r, c = diffString(n.Summary, n2.Summary)
	nd.Added.Summary = a
	nd.Removed.Summary = r
	nd.DiffCount += c

	a, r, c = diffString(n.Description, n2.Description)
	nd.Added.Description = a
	nd.Removed.Description = r
	nd.DiffCount += c

	addedD, removedD, count := diffDates(n.ReleaseDate, n2.ReleaseDate)
	nd.Added.ReleaseDate = addedD
	nd.Removed.ReleaseDate = removedD
	nd.DiffCount += int(count)

	addedD, removedD, count = diffDates(n.BuildDate, n2.BuildDate)
	nd.Added.BuildDate = addedD
	nd.Removed.BuildDate = removedD
	nd.DiffCount += count

	addedD, removedD, count = diffDates(n.ValidUntilDate, n2.ValidUntilDate)
	nd.Added.ValidUntilDate = addedD
	nd.Removed.ValidUntilDate = removedD
	nd.DiffCount += count

	added, removed, count := diffStrSlice(n.Licenses, n2.Licenses)
	nd.Added.Licenses = added
	nd.Removed.Licenses = removed
	nd.DiffCount += count

	added, removed, count = diffStrSlice(n.Attribution, n2.Attribution)
	nd.Added.Attribution = added
	nd.Removed.Attribution = removed
	nd.DiffCount += count

	added, removed, count = diffStrSlice(n.FileTypes, n2.FileTypes)
	nd.Added.FileTypes = added
	nd.Removed.FileTypes = removed
	nd.DiffCount += count

	addedP, removedP, count := diffPersonList(n.Suppliers, n2.Suppliers)
	nd.Added.Suppliers = addedP
	nd.Removed.Suppliers = removedP
	nd.DiffCount += count

	addedP, removedP, count = diffPersonList(n.Originators, n2.Originators)
	nd.Added.Originators = addedP
	nd.Removed.Originators = removedP
	nd.DiffCount += count

	addedER, removedER, count := diffExtRefList(n.ExternalReferences, n2.ExternalReferences)
	nd.Added.ExternalReferences = addedER
	nd.Removed.ExternalReferences = removedER
	nd.DiffCount += count

	addedM, removedM, count := diffIntStrMap(n.Identifiers, n2.Identifiers)
	nd.Added.Identifiers = addedM
	nd.Removed.Identifiers = removedM
	nd.DiffCount += count

	addedM, removedM, count = diffIntStrMap(n.Hashes, n2.Hashes)
	nd.Added.Hashes = addedM
	nd.Removed.Hashes = removedM
	nd.DiffCount += count

	if nd.DiffCount > 0 {
		return &nd
	}
	return nil
}

// diffString takes compares s2 against s1. If they differ returns the value of
// s2 in the removed return value. If s2 is blank, removed will have the original
// value of s1. If the strings are differente count will be 1, zero if not.
func diffString(s1, s2 string) (added, removed string, count int) {
	if s1 == s2 {
		return "", "", 0
	}

	if s2 == "" {
		return "", s1, 1
	}
	return s2, "", 1
}

// diffDates takes two dates, comapres them and returns d2 in added if there is
// a change, s1 in removed if d2 is nil. count will be 1 if there was a change.
func diffDates(dt1, dt2 *timestamppb.Timestamp) (added, removed *timestamppb.Timestamp, count int) {
	var d1, d2 *time.Time
	if dt1 != nil {
		da1 := dt1.AsTime()
		d1 = &da1
	}
	if dt2 != nil {
		da2 := dt2.AsTime()
		d2 = &da2
	}
	if (d1 != nil && d2 != nil && d1.Unix() != d2.Unix()) || (d1 == nil && d2 != nil) {
		return dt2, nil, 1
	} else if d1 != nil && d2 == nil {
		return nil, dt1, 1
	}
	return nil, nil, 0
}

func diffPersonList(list1, list2 []*Person) (added, removed []*Person, count int) {
	added = []*Person{}
	removed = []*Person{}

	// Index persons
	idx1 := map[string]*Person{}
	idx2 := map[string]*Person{}

	for _, p := range list1 {
		idx1[p.flatString()] = p
	}
	for _, p := range list2 {
		idx2[p.flatString()] = p
	}

	for _, p := range list2 {
		if _, ok := idx1[p.flatString()]; !ok {
			added = append(added, p)
		}
	}

	for _, p := range list1 {
		if _, ok := idx2[p.flatString()]; !ok {
			removed = append(removed, p)
		}
	}
	if len(added) > 0 || len(removed) > 0 {
		count = 1
	}
	return added, removed, count
}

func diffExtRefList(list1, list2 []*ExternalReference) (added, removed []*ExternalReference, count int) {
	added = []*ExternalReference{}
	removed = []*ExternalReference{}

	// Index persons
	idx1 := map[string]*ExternalReference{}
	idx2 := map[string]*ExternalReference{}

	for _, er := range list1 {
		idx1[er.flatString()] = er
	}
	for _, er := range list2 {
		idx2[er.flatString()] = er
	}

	for _, er := range list2 {
		if _, ok := idx1[er.flatString()]; !ok {
			added = append(added, er)
		}
	}

	for _, er := range list1 {
		if _, ok := idx2[er.flatString()]; !ok {
			removed = append(removed, er)
		}
	}

	if len(added) > 0 || len(removed) > 0 {
		count = 1
	}
	return added, removed, count
}

// diffIntStrMap(map1, )
func diffIntStrMap(map1, map2 map[int32]string) (added, removed map[int32]string, count int) {
	added = map[int32]string{}
	removed = map[int32]string{}
	for k, v2 := range map2 {
		if v1, ok := map1[k]; ok {
			if v2 != v1 {
				added[k] = v2
			}
		} else {
			added[k] = v2
		}
	}

	for k, v1 := range map1 {
		if _, ok := map2[k]; !ok {
			removed[k] = v1
		}
	}

	if len(added) > 0 || len(removed) > 0 {
		count = 1
	}
	return added, removed, count
}

// diffStrSlice compares two
func diffStrSlice(arr1, arr2 []string) (added, removed []string, count int) {
	added = []string{}
	removed = []string{}

	for _, s := range arr2 {
		if !slices.Contains(arr1, s) {
			added = append(added, s)
		}
	}

	for _, s := range arr1 {
		if !slices.Contains(arr2, s) {
			removed = append(removed, s)
		}
	}

	if len(added) > 0 || len(removed) > 0 {
		count = 1
	}
	return added, removed, count
}
