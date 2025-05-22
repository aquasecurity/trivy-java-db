package gcs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_parseItemName(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantGroup      string
		wantArtifact   string
		wantVersion    string
		wantClassifier string
	}{
		{
			name:           "no classifier (normal case)",
			input:          "maven2/abbot/abbot/1.4.0/abbot-1.4.0.jar.sha1",
			wantGroup:      "abbot",
			wantArtifact:   "abbot",
			wantVersion:    "1.4.0",
			wantClassifier: "",
		},
		{
			name:           "with classifier (hyphen, normal case)",
			input:          "maven2/abbot/abbot/1.4.0/abbot-1.4.0-lite.jar.sha1",
			wantGroup:      "abbot",
			wantArtifact:   "abbot",
			wantVersion:    "1.4.0",
			wantClassifier: "lite",
		},
		{
			name:           "with classifier (hyphen, normal case 2)",
			input:          "maven2/com/example/foo/2.0.0/foo-2.0.0-sources.jar.sha1",
			wantGroup:      "com.example",
			wantArtifact:   "foo",
			wantVersion:    "2.0.0",
			wantClassifier: "sources",
		},
		{
			name:           "no maven2 prefix (normal case)",
			input:          "com/example/bar/1.0.0/bar-1.0.0.jar.sha1",
			wantGroup:      "com.example",
			wantArtifact:   "bar",
			wantVersion:    "1.0.0",
			wantClassifier: "",
		},
		{
			name:           "invalid path (too short)",
			input:          "maven2/com/example/bar.jar.sha1",
			wantGroup:      "",
			wantArtifact:   "",
			wantVersion:    "",
			wantClassifier: "",
		},
		// Edge case: dot-separated classifier (not standard, but seen in the wild)
		// Note: The leading dot is NOT trimmed. This is by design in the current implementation.
		{
			name:           "edge case: dot-separated classifier (dot is not trimmed)",
			input:          "maven2/io/github/gnuf0rce/debug-helper/1.3.5/debug-helper-1.3.5.mirai2.jar.sha1",
			wantGroup:      "io.github.gnuf0rce",
			wantArtifact:   "debug-helper",
			wantVersion:    "1.3.5",
			wantClassifier: ".mirai2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groupID, artifactID, version, classifier := parseItemName(tt.input)
			require.Equal(t, tt.wantGroup, groupID)
			require.Equal(t, tt.wantArtifact, artifactID)
			require.Equal(t, tt.wantVersion, version)
			require.Equal(t, tt.wantClassifier, classifier)
		})
	}
}
