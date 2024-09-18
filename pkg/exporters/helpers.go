package exporters

import "slices"

// Is a sub-slice of slice
func subslice(sub []string, main []string) bool {
	if len(sub) > len(main) {
		return false
	}
	for _, s := range sub {
		if !slices.Contains(main, s) {
			return false
		}
	}
	return true
}
