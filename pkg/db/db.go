package db

import (
	"database/sql"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"golang.org/x/xerrors"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"sync"
)

const dbFileName = "trivy-java.db"

var (
	db    *sql.DB
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
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}

	err = createIndexesTable()
	if err != nil {
		return err
	}
	m = sync.Mutex{}
	return nil
}

func InsertIndex(groupID, artifactID, version, sha1 string) error {
	m.Lock()
	_, err := db.Exec("insert into indexes values ($1, $2, $3, $4)", groupID, artifactID, version, sha1)
	if err != nil {
		return err
	}
	m.Unlock()
	return nil
}

func SelectGAVbySha1(sha1 string) (types.GAV, error) {
	var groupID, artifactID, version string
	row := db.QueryRow("select GroupID, ArtifactID, Version from indexes WHERE Sha1=$1", sha1)
	err := row.Scan(&groupID, &artifactID, &version)
	if err != nil {
		return types.GAV{}, err // TODO add error
	}
	return types.GAV{groupID, artifactID, version}, nil
}

func Dir(cacheDir string) string {
	return filepath.Join(cacheDir, "java-db")
}

func Path(cacheDir string) string {
	dbPath := filepath.Join(Dir(cacheDir), dbFileName)
	return dbPath
}

func createIndexesTable() error {
	_, err := db.Exec(`drop table if exists indexes;create table indexes(GroupID String, ArtifactID String, Version String, Sha1 String);`)
	if err != nil {
		return err
	}
	return nil
}
