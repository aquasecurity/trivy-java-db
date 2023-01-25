package db

import (
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"golang.org/x/xerrors"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"time"
)

const (
	dbFileName     = "trivy-java.db"
	SchemaVersion  = 1
	UpdateInterval = time.Hour * 168 // 1 week
)

var (
	db    *gorm.DB
	dbDir string
)

func Init(cacheDir string) error {
	dbPath := Path(cacheDir)
	dbDir = filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}
	//open db
	var err error
	db, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		// Logger: logger.Default.LogMode(logger.Silent), // TODO disable logger????
	})
	if err != nil {
		return xerrors.Errorf("can't open db: %w", err)
	}

	err = db.AutoMigrate(types.Index{})
	if err != nil {
		return xerrors.Errorf("can't run auto migration for db: %w", err)
	}
	return nil
}

func Dir(cacheDir string) string {
	return filepath.Join(cacheDir, "java-db")
}

func Path(cacheDir string) string {
	dbPath := filepath.Join(Dir(cacheDir), dbFileName)
	return dbPath
}

//////////////////////////////////////
// functions to interaction with DB //
//////////////////////////////////////

func InsertIndexes(indexes []*types.Index) {
	db.Create(indexes)
}

func SelectIndexBySha1(sha1 string) types.Index {
	index := types.Index{}
	db.Where(&types.Index{Sha1: sha1}).First(&index)
	return index
}

func SelectIndexByArtifactIDAndGroupID(artifactID, groupID string) types.Index {
	index := types.Index{}
	db.Where(&types.Index{ArtifactID: artifactID, GroupID: groupID}).First(&index)
	return index
}

func SelectIndexesByArtifactIDAndJarType(artifactID, fileType string) []types.Index {
	var indexes []types.Index
	db.Where(&types.Index{ArtifactID: artifactID, Type: fileType}).Find(&indexes)
	return indexes
}
