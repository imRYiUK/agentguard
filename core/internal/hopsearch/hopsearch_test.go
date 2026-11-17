package hopsearch_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/imRYiUK/agentguard/core/internal/hopsearch"
)

// graph maps a node to the hops out of it, each written "to:via".
type graph map[string][]string

func (g graph) hops(node string) []hopsearch.Hop[string] {
	var out []hopsearch.Hop[string]
	for _, h := range g[node] {
		to, via, _ := strings.Cut(h, ":")
		out = append(out, hopsearch.Hop[string]{To: to, Via: via})
	}
	return out
}

// chains renders each chain as "via,via>destination".
func chains(g graph, start string, depth int) []string {
	var out []string
	for _, c := range hopsearch.Search(start, depth, g.hops) {
		var vias []string
		for _, h := range c {
			vias = append(vias, h.Via)
		}
		out = append(out, strings.Join(vias, ",")+">"+c[len(c)-1].To)
	}
	return out
}

func TestSearchFollowsHopsInOrderOfLength(t *testing.T) {
	g := graph{"a": {"b:ab"}, "b": {"c:bc"}}
	want := []string{"ab>b", "ab,bc>c"}
	if got := chains(g, "a", 3); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSearchStopsAtTheDepthLimit(t *testing.T) {
	g := graph{"a": {"b:ab"}, "b": {"c:bc"}, "c": {"d:cd"}, "d": {"e:de"}}
	want := []string{"ab>b", "ab,bc>c", "ab,bc,cd>d"}
	if got := chains(g, "a", hopsearch.MaxDepth); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v (node e is 4 hops away)", got, want)
	}
}

func TestSearchNeverRevisitsANode(t *testing.T) {
	g := graph{"a": {"b:ab"}, "b": {"a:ba", "c:bc"}, "c": {"a:ca"}}
	want := []string{"ab>b", "ab,bc>c"}
	if got := chains(g, "a", 3); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSearchKeepsOnlyTheShortestChainsToANode(t *testing.T) {
	g := graph{"a": {"b:ab", "c:ac"}, "c": {"b:cb"}}
	want := []string{"ab>b", "ac>c"}
	if got := chains(g, "a", 3); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSearchKeepsParallelHopsOfTheSameLength(t *testing.T) {
	g := graph{"a": {"b:one", "b:two"}}
	want := []string{"one>b", "two>b"}
	if got := chains(g, "a", 3); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
