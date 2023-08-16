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
)

const updateInterval = time.Hour * 72 // 3 days
const licenseStringLimit = 150

type Builder struct {
	db    db.DB
	meta  db.Client
	clock clock.Clock
}

func NewBuilder(db db.DB, meta db.Client) Builder {
	return Builder{
		db:    db,
		meta:  meta,
		clock: clock.RealClock{},
	}
}

func (b *Builder) Build(cacheDir string) error {
	indexDir := filepath.Join(cacheDir, types.IndexesDir)
	licenseDir := filepath.Join(cacheDir, types.LicenseDir)

	licenseFile, err := os.Open(licenseDir + types.NormalizedlicenseFileName)
	if err != nil {
		xerrors.Errorf("failed to open normalized license file: %w", err)
	}

	licenseMap := make(map[string]string)

	if err := json.NewDecoder(licenseFile).Decode(&licenseMap); err != nil {
		return xerrors.Errorf("failed to decode license file: %w", err)
	}

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
				License:     b.processLicenseInformationFromCache(ver.License, licenseDir, licenseMap),
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
func (b *Builder) processLicenseInformationFromCache(license, licenseDir string, licenseMap map[string]string) string {
	var updatedLicenseList []string
	// process license information
	for _, l := range strings.Split(license, "|") {
		if val, ok := licenseMap[l]; ok {
			val = strings.TrimSpace(val)
			updatedLicenseList = append(updatedLicenseList, val)
		}
	}

	// precautionary check
	// return first <licenseStringLimit> characters if license string is too long
	result := strings.Join(updatedLicenseList, "|")
	if len(result) > licenseStringLimit {
		r := []rune(result)
		if len(r) > licenseStringLimit {
			log.Printf("untrimmed license string: %s", result)
			return string(r[:licenseStringLimit])
		}

	}

	return result

}
