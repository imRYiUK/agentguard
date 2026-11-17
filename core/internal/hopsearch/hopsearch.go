// Package hopsearch finds the Identity Hop chains that lead away from an
// Identity, up to a depth limit.
package hopsearch

// MaxDepth is the most Identity Hops one Reach Path may contain. A chain
// longer than this is not followed, so analysis stays bounded and
// explainable.
const MaxDepth = 3

// Hop is one Identity Hop: a step to the Identity named To, with the evidence
// the caller attaches to it as Via.
type Hop[V any] struct {
	To  string
	Via V
}

// Search returns the Identity Hop chains that start at start and are at most
// maxDepth hops long. For each reachable Identity it keeps only the shortest
// chains that reach it, and a chain never visits an Identity twice. Chains
// are ordered by length, then in the order hopsFrom lists the hops.
func Search[V any](start string, maxDepth int, hopsFrom func(node string) []Hop[V]) [][]Hop[V] {
	reached := map[string]bool{start: true}
	frontier := [][]Hop[V]{nil}
	var out [][]Hop[V]
	for depth := 1; depth <= maxDepth && len(frontier) > 0; depth++ {
		var next [][]Hop[V]
		reachedNow := map[string]bool{}
		for _, chain := range frontier {
			from := start
			if len(chain) > 0 {
				from = chain[len(chain)-1].To
			}
			for _, h := range hopsFrom(from) {
				if reached[h.To] {
					continue
				}
				extended := append(append([]Hop[V](nil), chain...), h)
				next = append(next, extended)
				reachedNow[h.To] = true
			}
		}
		for node := range reachedNow {
			reached[node] = true
		}
		out = append(out, next...)
		frontier = next
	}
	return out
}
