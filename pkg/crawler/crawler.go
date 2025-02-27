package crawler

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"path/filepath"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/aquasecurity/trivy-java-db/pkg/fileutil"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
)

const (

	// Define the bucket name and prefix.
	bucketName  = "maven-central"
	queryPrefix = "maven2/"
)

type Crawler struct {
	dir string

	wrongSHA1Values []string
}

type Option struct {
	CacheDir string
}

func NewCrawler(opt Option) (Crawler, error) {
	indexDir := filepath.Join(opt.CacheDir, types.IndexDir)
	slog.Info("Index dir", slog.String("path", indexDir))

	//var dbc db.DB
	//dbDir := db.Dir(opt.CacheDir)
	//if db.Exists(dbDir) {
	//	var err error
	//	dbc, err = db.New(dbDir)
	//	if err != nil {
	//		return Crawler{}, xerrors.Errorf("unable to open DB: %w", err)
	//	}
	//	slog.Info("DB is used for crawler", slog.String("path", opt.CacheDir))
	//}

	return Crawler{
		dir: indexDir,
	}, nil
}

func (c *Crawler) Crawl(ctx context.Context) error {
	// Create a storage client without authentication (public bucket access).
	client, err := storage.NewClient(ctx, option.WithoutAuthentication())
	if err != nil {
		return xerrors.Errorf("unable to create storage client: %w", err)
	}
	defer client.Close()

	// Get a handle to the bucket.
	bucket := client.Bucket(bucketName)

	// Create a query with the specified prefix.
	query := &storage.Query{
		Prefix:    queryPrefix,
		MatchGlob: "**jar*",
	}
	err = query.SetAttrSelection([]string{"Name", "ContentType"})
	if err != nil {
		return xerrors.Errorf("unable to set attr selection: %w", err)
	}

	// Create an iterator to loop over the objects.
	it := bucket.Objects(ctx, query)

	// Iterate through objects using it.Next()
	var expectedSha1Name string
	var index Index
	for {
		// Get the next object.
		obj, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		} else if err != nil {
			return xerrors.Errorf("failed to iterate objects: %w", err)
		}

		// Don't check folder with index archives
		if strings.HasPrefix(obj.Name, "maven2/.index") {
			continue
		}

		if obj.Name == expectedSha1Name {
			// Retrieve the SHA1 file's content.
			sha1Content, err := retrieveObjectContent(ctx, bucket, obj.Name)
			if err != nil {
				return xerrors.Errorf("failed to retrieve content: %w", err)
			}
			expectedSha1Name = ""

			sha1 := c.decodeSha1String(obj.Name, sha1Content)
			if len(sha1) == 0 {
				continue
			}

			groupID, artifactID, version := parseObjectName(obj.Name)
			if index.GroupID != groupID || index.ArtifactID != artifactID {
				// Save previous index
				if err := c.saveIndexToFile(index); err != nil {
					return xerrors.Errorf("failed to save index to file: %w", err)
				}

				// Init index with new GroupID and ArtifactID
				index = Index{
					GroupID:     groupID,
					ArtifactID:  artifactID,
					ArchiveType: types.JarType,
				}
			}

			// Save new version + sha1
			index.Versions = append(index.Versions, types.Version{
				Version: version,
				SHA1:    sha1,
			})

			continue
		}

		// Skip unwanted JARs.
		if strings.HasSuffix(obj.Name, "sources.jar") || strings.HasSuffix(obj.Name, "test.jar") ||
			strings.HasSuffix(obj.Name, "tests.jar") || strings.HasSuffix(obj.Name, "javadoc.jar") ||
			strings.HasSuffix(obj.Name, "scaladoc.jar") {
			continue
		}
		// Filter by content type.
		if obj.ContentType != "application/java-archive" {
			continue
		}
		if expectedSha1Name != "" {
			log.Printf("Expected SHA1 not found: %s", expectedSha1Name)
		}
		expectedSha1Name = obj.Name + ".sha1"
	}

	// Save last index
	if err = c.saveIndexToFile(index); err != nil {
		return xerrors.Errorf("failed to save index to file: %w", err)
	}

	if len(c.wrongSHA1Values) > 0 {
		for _, wrongSHA1 := range c.wrongSHA1Values {
			slog.Warn("Wrong SHA1 file", slog.String("error", wrongSHA1))
		}
	}

	return nil
}

// retrieveObjectContent retrieves and returns the content of an object.
func retrieveObjectContent(ctx context.Context, bucket *storage.BucketHandle, objectName string) (string, error) {
	obj := bucket.Object(objectName)
	reader, err := obj.NewReader(ctx)
	if err != nil {
		return "", err
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// parseBucketName parses object name and returns GroupID, ArtifactID and version of jar file
func parseObjectName(bucketName string) (string, string, string) {
	bucketName = strings.TrimPrefix(bucketName, "maven2/")
	ss := strings.Split(bucketName, "/")
	groupID := strings.Join(ss[:len(ss)-3], ".")
	artifactID := ss[len(ss)-3]
	// Take version from filename
	version := strings.TrimSuffix(strings.TrimPrefix(ss[len(ss)-1], artifactID+"-"), ".jar.sha1")
	return groupID, artifactID, version
}

func (c *Crawler) decodeSha1String(objName, sha1s string) []byte {
	// there are empty xxx.jar.sha1 files. Skip them.
	// e.g. https://repo.maven.apache.org/maven2/org/wso2/msf4j/msf4j-swagger/2.5.2/msf4j-swagger-2.5.2.jar.sha1
	// https://repo.maven.apache.org/maven2/org/wso2/carbon/analytics/org.wso2.carbon.permissions.rest.api/2.0.248/org.wso2.carbon.permissions.rest.api-2.0.248.jar.sha1
	if sha1s == "" {
		return nil
	}

	// there are xxx.jar.sha1 files with additional data. e.g.:
	// https://repo.maven.apache.org/maven2/aspectj/aspectjrt/1.5.2a/aspectjrt-1.5.2a.jar.sha1
	// https://repo.maven.apache.org/maven2/xerces/xercesImpl/2.9.0/xercesImpl-2.9.0.jar.sha1
	var err error
	for _, s := range strings.Split(strings.TrimSpace(sha1s), " ") {
		var sha1 []byte
		sha1, err = hex.DecodeString(s)
		if err == nil {
			return sha1
		}
	}
	c.wrongSHA1Values = append(c.wrongSHA1Values, fmt.Sprintf("%s (%s)", objName, err))
	return nil
}

func (c *Crawler) saveIndexToFile(index Index) error {
	if len(index.Versions) == 0 {
		return nil
	}

	// Remove duplicates and save artifacts without extra suffixes.
	// e.g. `cudf-0.14-cuda10-1.jar.sha1` and `cudf-0.14.jar.sha1` => `cudf-0.14.jar.sha1`
	//  https://repo.maven.apache.org/maven2/ai/rapids/cudf/0.14/
	index.Versions = lo.Reverse(index.Versions)
	index.Versions = lo.UniqBy(index.Versions, func(v types.Version) string {
		return string(v.SHA1)
	})

	fileName := fmt.Sprintf("%s.json", index.ArtifactID)
	filePath := filepath.Join(c.dir, index.GroupID, fileName)
	if err := fileutil.WriteJSON(filePath, index); err != nil {
		return xerrors.Errorf("json write error: %w", err)
	}
	return nil
}
