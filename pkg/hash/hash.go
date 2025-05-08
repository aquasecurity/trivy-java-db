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

// GAV hashes GroupId + ArtifactId + Version for deduplication
func GAV(g, a, v string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(g))
	h.Write([]byte("|"))
	h.Write([]byte(a))
	h.Write([]byte("|"))
	h.Write([]byte(v))
	return h.Sum64()
}
