package maven

import "strings"

func ValidateClassifier(classifier string) bool {
	// e.g. tests-javadoc, test-fixtures, source-release, debug-sources, etc.
	if strings.HasPrefix(classifier, "source") || strings.HasPrefix(classifier, "test") || strings.HasPrefix(classifier, "debug") ||
		strings.HasPrefix(classifier, "javadoc") || strings.HasSuffix(classifier, "javadoc") {
		return false
	}
	switch classifier {
	case "src", "schemas", "config", "properties", "docs", "readme", "changelog", "cyclonedx", "kdoc":
		return false
	}
	return true
}
