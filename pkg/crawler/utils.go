package crawler

import (
	"fmt"
	"hash/fnv"
	"strings"
)

func getLicenseKey(l License) string {
	if len(l.URL) > 0 && strings.HasPrefix(l.URL, "http") {
		return hash(l.URL)
	}
	return hash(l.Name)
}

func getPomURL(baseURL, artifactID, version string) string {
	pomFileName := fmt.Sprintf("/%s-%s.pom", artifactID, version)
	return baseURL + version + pomFileName
}

func hash(s string) string {
	h := fnv.New32a()
	h.Write([]byte(s))
	return fmt.Sprint(h.Sum32())
}

func min(a int, b int) int {
	if a > b {
		return b
	}
	return a
}
