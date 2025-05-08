package crawler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net/http"
	"strings"

	"github.com/aquasecurity/trivy-java-db/pkg/index"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/samber/lo"
	"golang.org/x/xerrors"
)

const (
	mavenCentralBucket = "maven-central"
	mavenPrefix        = "maven2/"
)

// GCSRequestParams represents parameters for GCS API requests
type GCSRequestParams struct {
	Prefix     string // Object prefix to filter results
	Delimiter  string // Delimiter for directory-like hierarchy
	MatchGlob  string // Glob pattern to match objects
	MaxResults int    // Maximum results per page
}

// GCS is a client for GCS operations
type GCS struct {
	client     *retryablehttp.Client
	baseURL    string
	logger     *slog.Logger
	bucketName string // Default bucket name, can be overridden in requests
}

// NewGCS creates a new GCS client
func NewGCS(client *retryablehttp.Client, baseURL string) *GCS {
	return &GCS{
		client:     client,
		baseURL:    baseURL,
		logger:     slog.With(slog.String("component", "storage")),
		bucketName: mavenCentralBucket, // Default to Maven Central
	}
}

// Maven-specific methods

// JARSHA1Files returns an iterator over JAR SHA1 files, filtering out certain types
func (s *GCS) JARSHA1Files(ctx context.Context, prefix string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		items := s.listItems(ctx, GCSRequestParams{
			Prefix:     prefix,
			MatchGlob:  "**/*.jar.sha1",
			MaxResults: 5000, // 5,000 is the maximum allowed by GCS API
		})

		// Wrap the items with filtering
		for item, err := range items {
			// Don't process sources, test, javadocs, scaladoc files
			if strings.HasSuffix(item, "sources.jar.sha1") ||
				strings.HasSuffix(item, "test.jar.sha1") ||
				strings.HasSuffix(item, "tests.jar.sha1") ||
				strings.HasSuffix(item, "javadoc.jar.sha1") ||
				strings.HasSuffix(item, "scaladoc.jar.sha1") {
				continue
			}

			if !yield(item, err) {
				return
			}
		}
	}
}

// TopLevelPrefixes returns an iterator over the top-level directory prefixes in Maven Central
func (s *GCS) TopLevelPrefixes(ctx context.Context) iter.Seq2[string, error] {
	return s.listPrefixes(ctx, GCSRequestParams{
		Prefix:     mavenPrefix,
		Delimiter:  "/",
		MaxResults: 10000,
	})
}

// FetchSHA1 fetches the SHA1 hash for a given item name
func (s *GCS) FetchSHA1(ctx context.Context, itemName string) (string, error) {
	data, err := s.getObject(ctx, itemName)
	if err != nil {
		return "", xerrors.Errorf("failed to get object %s: %w", itemName, err)
	}
	data = bytes.TrimSpace(data)

	// Handle empty SHA1 files
	// e.g.
	//    https://repo.maven.apache.org/maven2/org/wso2/msf4j/msf4j-swagger/2.5.2/msf4j-swagger-2.5.2.jar.sha1
	//    https://repo.maven.apache.org/maven2/org/wso2/carbon/analytics/org.wso2.carbon.permissions.rest.api/2.0.248/org.wso2.carbon.permissions.rest.api-2.0.248.jar.sha1
	if len(data) == 0 {
		return index.NotAvailable, nil
	}

	// Find a valid SHA1 hash in the content
	parts := strings.Fields(string(data))

	// Validate SHA1 as there are xxx.jar.sha1 files with additional data.
	// e.g.
	//   https://repo.maven.apache.org/maven2/aspectj/aspectjrt/1.5.2a/aspectjrt-1.5.2a.jar.sha1
	//   https://repo.maven.apache.org/maven2/xerces/xercesImpl/2.9.0/xercesImpl-2.9.0.jar.sha1
	for _, part := range parts {
		if len(part) == 40 && isHexString(part) {
			return part, nil
		}
	}

	// Record wrong SHA1 digests so we can skip them in the future
	return index.NotAvailable, nil
}

// Internal methods

// getObject fetches a single object
func (s *GCS) getObject(ctx context.Context, objectPath string) ([]byte, error) {
	url := s.baseURL + s.bucketName + "/" + objectPath
	resp, err := s.httpGet(ctx, url)
	if err != nil {
		return nil, xerrors.Errorf("http get error: %w", err)
	}
	defer resp.Body.Close()

	// Handle cases where the version directory contains a reference to a SHA1 file that doesn't actually exist
	// e.g. https://repo.maven.apache.org/maven2/com/adobe/aem/uber-jar/6.4.8.2/uber-jar-6.4.8.2-sources.jar.sha1
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // TODO: add special error
	}

	// Read the object content
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, xerrors.Errorf("can't read object %s: %w", url, err)
	}

	return data, nil
}

// listItems is a function to list items with given parameters
func (s *GCS) listItems(ctx context.Context, params GCSRequestParams) iter.Seq2[string, error] {
	return s.listObjects(ctx, params, func(result GCSListResponse) []string {
		return lo.Map(result.Items, func(item Item, _ int) string {
			return item.Name
		})
	})
}

// listPrefixes is a function to list prefixes with given parameters
func (s *GCS) listPrefixes(ctx context.Context, params GCSRequestParams) iter.Seq2[string, error] {
	return s.listObjects(ctx, params, func(result GCSListResponse) []string {
		return result.Prefixes
	})
}

// prepareListRequest prepares the HTTP request for GCS API calls
func (s *GCS) prepareListRequest(ctx context.Context, params GCSRequestParams) (string, *retryablehttp.Request, error) {
	url := s.baseURL + "storage/v1/b/" + s.bucketName + "/o/"
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return url, nil, xerrors.Errorf("unable to create a HTTP request: %w", err)
	}

	// Configure query parameters
	query := req.URL.Query()

	// Only set parameters that are specified
	if params.Prefix != "" {
		query.Set("prefix", params.Prefix)
	}
	if params.Delimiter != "" {
		query.Set("delimiter", params.Delimiter)
	}
	if params.MatchGlob != "" {
		query.Set("matchGlob", params.MatchGlob)
	}
	if params.MaxResults > 0 {
		query.Set("maxResults", fmt.Sprintf("%d", params.MaxResults))
	} else {
		query.Set("maxResults", "1000") // Default value
	}

	req.URL.RawQuery = query.Encode()

	return url, req, nil
}

// list makes the HTTP call to GCS API and returns the parsed response
func (s *GCS) list(ctx context.Context, req *retryablehttp.Request) (GCSListResponse, error) {
	resp, err := s.httpGet(ctx, req.URL.String())
	if err != nil {
		return GCSListResponse{}, xerrors.Errorf("http error: %w", err)
	}
	defer resp.Body.Close()

	var result GCSListResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return GCSListResponse{}, xerrors.Errorf("unable to parse API response: %w", err)
	}

	return result, nil
}

// httpGet performs an HTTP GET request with retry handling
func (s *GCS) httpGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, xerrors.Errorf("unable to create a HTTP request: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("http error (%s): %w", url, err)
	}
	return resp, nil
}

// listObjects is a generic function to list objects or prefixes from GCS
// T is the type of elements to return (Item or string)
func (s *GCS) listObjects(ctx context.Context, params GCSRequestParams, extractor func(GCSListResponse) []string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		// Prepare API URL and request
		_, req, err := s.prepareListRequest(ctx, params)
		if err != nil {
			s.logger.Error("Failed to prepare storage request", slog.Any("error", err))
			yield("", xerrors.Errorf("failed to prepare storage request: %w", err))
			return
		}

		// Paginate through results
		var pageToken string
		for {
			select {
			case <-ctx.Done():
				if ctx.Err() != nil {
					yield("", ctx.Err())
				}
				return
			default:
				// Update page token for pagination
				query := req.URL.Query()
				query.Set("pageToken", pageToken)
				req.URL.RawQuery = query.Encode()
			}

			// Make API call
			result, err := s.list(ctx, req)
			if err != nil {
				yield("", xerrors.Errorf("listing objects: %w", err))
				return
			}

			// Extract and yield each result using the provided extractor function
			for _, item := range extractor(result) {
				if !yield(item, nil) {
					return
				}
			}

			// Check for more pages
			if result.NextPageToken == "" {
				break
			}
			pageToken = result.NextPageToken
		}
	}
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
