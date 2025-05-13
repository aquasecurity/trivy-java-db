package hash

import (
	"hash/fnv"
)

// GA hashes GroupId + ArtifactId for sharding
func GA(g, a string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(g))
	h.Write([]byte("|"))
	h.Write([]byte(a))
	return h.Sum64()
}

// GAVC hashes GroupId + ArtifactId + Version + Classifier for deduplication
func GAVC(g, a, v, c string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(g))
	h.Write([]byte("|"))
	h.Write([]byte(a))
	h.Write([]byte("|"))
	h.Write([]byte(v))
	if c != "" {
		h.Write([]byte("|"))
		h.Write([]byte(c))
	}
	return h.Sum64()
}
