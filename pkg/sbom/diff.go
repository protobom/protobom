package sbom

import (
	"slices"

	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

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
func diffDates(d1, d2 *timestamppb.Timestamp) (added, removed *timestamppb.Timestamp, count int) {
	if (d1 != nil && d2 != nil && d1 != d2) || (d1 == nil && d2 != nil) {
		return d2, nil, 1
	} else if d1 != nil && d2 == nil {
		return nil, d1, 1
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
