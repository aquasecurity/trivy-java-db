package db

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	_ "modernc.org/sqlite"

	"github.com/aquasecurity/trivy-java-db/pkg/types"
)

const (
	dbFileName     = "trivy-java.db"
	SchemaVersion  = 1
	UpdateInterval = time.Hour * 168 // 1 week
)

type DB struct {
	client *gorm.DB
	dir    string
}

func Path(cacheDir string) string {
	dbPath := filepath.Join(cacheDir, dbFileName)
	return dbPath
}

func New(cacheDir string) (DB, error) {
	dbPath := Path(cacheDir)
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		return DB{}, xerrors.Errorf("failed to mkdir: %w", err)
	}

	// open db
	var err error
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent), // disable logger
	})
	if err != nil {
		return DB{}, xerrors.Errorf("can't open db: %w", err)
	}

	if err = db.AutoMigrate(types.Index{}); err != nil {
		return DB{}, xerrors.Errorf("can't run auto migration for db: %w", err)
	}
	return DB{
		client: db,
		dir:    dbDir,
	}, nil
}

func (db *DB) Dir() string {
	return db.dir
}

//////////////////////////////////////
// functions to interaction with DB //
//////////////////////////////////////

func (db *DB) InsertIndexes(indexes []*types.Index) error {
	if result := db.client.Create(indexes); result.Error != nil {
		return xerrors.Errorf("insert error: %w", result.Error)
	}
	return nil
}

func (db *DB) SelectIndexBySha1(sha1 string) (types.Index, error) {
	index := types.Index{}
	result := db.client.Where(&types.Index{Sha1: sha1}).First(&index)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return types.Index{}, nil
	} else if result.Error != nil {
		return types.Index{}, xerrors.Errorf("select error: %w", result.Error)
	}
	return index, nil
}

func (db *DB) SelectIndexByArtifactIDAndGroupID(artifactID, groupID string) (types.Index, error) {
	index := types.Index{}
	result := db.client.Where(&types.Index{
		ArtifactID: artifactID,
		GroupID:    groupID,
	}).First(&index)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return types.Index{}, nil
	} else if result.Error != nil {
		return types.Index{}, xerrors.Errorf("select error: %w", result.Error)
	}
	return index, nil
}

func (db *DB) SelectIndexesByArtifactIDAndFileType(artifactID string, fileType types.ArchiveType) ([]types.Index,
	error) {
	var indexes []types.Index
	result := db.client.Where(&types.Index{
		ArtifactID:  artifactID,
		ArchiveType: fileType,
	}).Find(&indexes)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, nil
	} else if result.Error != nil {
		return nil, xerrors.Errorf("select error: %w", result.Error)
	}
	return indexes, nil
}
