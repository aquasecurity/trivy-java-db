package sha1

import (
	"bytes"
	"strings"

	"github.com/aquasecurity/trivy-java-db/pkg/index"
)

func Parse(data []byte) string {
	data = bytes.TrimSpace(data)

	// Handle empty SHA1 files
	// e.g.
	//    https://repo.maven.apache.org/maven2/org/wso2/msf4j/msf4j-swagger/2.5.2/msf4j-swagger-2.5.2.jar.sha1
	//    https://repo.maven.apache.org/maven2/org/wso2/carbon/analytics/org.wso2.carbon.permissions.rest.api/2.0.248/org.wso2.carbon.permissions.rest.api-2.0.248.jar.sha1
	if len(data) == 0 {
		return index.NotAvailable
	}

	// Find a valid SHA1 hash in the content
	parts := strings.Fields(string(data))

	// Validate SHA1 as there are xxx.jar.sha1 files with additional data.
	// e.g.
	//   https://repo.maven.apache.org/maven2/aspectj/aspectjrt/1.5.2a/aspectjrt-1.5.2a.jar.sha1
	//   https://repo.maven.apache.org/maven2/xerces/xercesImpl/2.9.0/xercesImpl-2.9.0.jar.sha1
	for _, part := range parts {
		if len(part) == 40 && isHexString(part) {
			return part
		}
	}

	// Record wrong SHA1 digests so we can skip them in the future
	return index.NotAvailable
}

// isHexString checks if a string contains only hex characters
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
