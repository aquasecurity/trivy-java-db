package builder

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler"
	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy-java-db/pkg/fileutil"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	cmap "github.com/orcaman/concurrent-map/v2"
)

const updateInterval = time.Hour * 72 // 3 days

type Builder struct {
	db              db.DB
	meta            db.Client
	clock           clock.Clock
	filesLicenseMap cmap.ConcurrentMap[string, string] // cache information about license saved in licenses directory
}

func NewBuilder(db db.DB, meta db.Client) Builder {
	return Builder{
		db:              db,
		meta:            meta,
		clock:           clock.RealClock{},
		filesLicenseMap: cmap.New[string](),
	}
}

func (b *Builder) Build(cacheDir string) error {
	indexDir := filepath.Join(cacheDir, types.IndexesDir)
	licenseDir := filepath.Join(cacheDir, types.LicenseDir)

	count, err := fileutil.Count(indexDir)
	if err != nil {
		return xerrors.Errorf("count error: %w", err)
	}
	bar := pb.StartNew(count)
	defer log.Println("Build completed")
	defer bar.Finish()

	var indexes []types.Index
	if err := fileutil.Walk(indexDir, func(r io.Reader, path string) error {
		index := &crawler.Index{}
		if err := json.NewDecoder(r).Decode(index); err != nil {
			return xerrors.Errorf("failed to decode index: %w", err)
		}
		for _, ver := range index.Versions {
			indexes = append(indexes, types.Index{
				GroupID:     index.GroupID,
				ArtifactID:  index.ArtifactID,
				Version:     ver.Version,
				SHA1:        ver.SHA1,
				ArchiveType: index.ArchiveType,
				License:     b.processLicenseInformationFromCache(ver.License, licenseDir),
			})
		}
		bar.Increment()

		if len(indexes) > 1000 {
			if err = b.db.InsertIndexes(indexes); err != nil {
				return xerrors.Errorf("failed to insert index to db: %w", err)
			}
			indexes = []types.Index{}
		}
		return nil
	}); err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}

	// Insert the remaining indexes
	if err = b.db.InsertIndexes(indexes); err != nil {
		return xerrors.Errorf("failed to insert index to db: %w", err)
	}

	if err := b.db.VacuumDB(); err != nil {
		return xerrors.Errorf("fauled to vacuum db: %w", err)
	}

	// save metadata
	metaDB := db.Metadata{
		Version:    db.SchemaVersion,
		NextUpdate: b.clock.Now().UTC().Add(updateInterval),
		UpdatedAt:  b.clock.Now().UTC(),
	}
	if err := b.meta.Update(metaDB); err != nil {
		return xerrors.Errorf("failed to update metadata: %w", err)
	}

	return nil
}

// processLicenseInformationFromCache : gets cached license information by license key and updates the records to be inserted
func (b *Builder) processLicenseInformationFromCache(license, licenseDir string) string {
	var updatedLicenseList []string
	// process license information
	for _, l := range strings.Split(license, "|") {
		if val, ok := b.filesLicenseMap.Get(l); ok {
			updatedLicenseList = append(updatedLicenseList, val)
			continue
		}

		// fetch license from file and update map
		fileName := fileutil.GetLicenseFileName(licenseDir, l)
		file, err := os.Open(fileName)
		if err != nil {
			continue
		}

		defer file.Close()

		content, err := io.ReadAll(file)
		if err != nil {
			continue
		}

		contentString := strings.TrimSpace(string(content))

		b.filesLicenseMap.Set(l, contentString)

		updatedLicenseList = append(updatedLicenseList, contentString)
	}

	// precautionary check
	// return first 30 characters if license string is too long
	result := strings.Join(updatedLicenseList, "|")
	if len(result) > 30 {
		r := []rune(result)
		return string(r[:30])

	}

	return result

}
