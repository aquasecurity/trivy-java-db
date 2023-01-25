package db

import (
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"golang.org/x/xerrors"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"sync"
)

const dbFileName = "trivy-java.db"

var (
	db    *gorm.DB
	dbDir string
	m     sync.Mutex
)

func Init(cacheDir string) error {
	dbPath := Path(cacheDir)
	dbDir = filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}
	//open db
	var err error
	db, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return xerrors.Errorf("can't open db: %w", err)
	}

	err = db.AutoMigrate(types.Index{})
	if err != nil {
		return xerrors.Errorf("can't run auto migration for db: %w", err)
	}
	m = sync.Mutex{}
	return nil
}

func InsertIndex(indexes []*types.Index) {
	db.Create(indexes)
}

func Dir(cacheDir string) string {
	return filepath.Join(cacheDir, "java-db")
}

func Path(cacheDir string) string {
	dbPath := filepath.Join(Dir(cacheDir), dbFileName)
	return dbPath
}
