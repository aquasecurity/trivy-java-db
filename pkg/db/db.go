package db

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"golang.org/x/xerrors"
)

const (
	dbFileName     = "trivy-java.db"
	SchemaVersion  = 1
	UpdateInterval = time.Hour * 72 // 3 days
)

type DB struct {
	client *sql.DB
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
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return DB{}, xerrors.Errorf("can't open db: %w", err)
	}

	_, err = db.Exec("CREATE TABLE `primary_indices`(`group_id` TEXT, `artifact_id` TEXT, `version` TEXT, `sha1` BLOB UNIQUE, archive_type TEXT);")
	if err != nil {
		return DB{}, err
	}

	return DB{
		client: db,
		dir:    dbDir,
	}, nil
}

func (db *DB) Dir() string {
	return db.dir
}

func (db *DB) NormalizationDB() error {
	log.Printf("DB normalization")
	if _, err := db.client.Exec("CREATE TABLE artifacts(idx INTEGER PRIMARY KEY, group_id TEXT, artifact_id TEXT)"); err != nil {
		return xerrors.Errorf("unable to create 'artifacts' table: %w", err)
	}
	if _, err := db.client.Exec("CREATE TABLE indices(artifact_idx INTEGER, version TEXT, sha1 BLOB, archive_type TEXT)"); err != nil {
		return xerrors.Errorf("unable to create 'indices' table: %w", err)
	}

	if _, err := db.client.Exec("INSERT INTO artifacts(group_id, artifact_id) SELECT group_id, artifact_id FROM primary_indices GROUP BY group_id, artifact_id;"); err != nil {
		return xerrors.Errorf("unable to populate 'artifacts' table: %w", err)
	}
	if _, err := db.client.Exec("INSERT INTO indices(artifact_idx, version, sha1, archive_type) SELECT a.idx, i.version, i.sha1, i.archive_type FROM primary_indices i JOIN artifacts a ON i.group_id = a.group_id AND i.artifact_id = a.artifact_id;"); err != nil {
		return xerrors.Errorf("unable to populate 'indices' table: %w", err)
	}

	if _, err := db.client.Exec("CREATE INDEX artifacts_idx ON artifacts(group_id, artifact_id)"); err != nil {
		return xerrors.Errorf("unable to create 'artifacts_idx' index: %w", err)
	}
	if _, err := db.client.Exec("CREATE INDEX indices_sha1_idx ON indices(sha1)"); err != nil {
		return xerrors.Errorf("unable to create 'indices_sha1_idx' index: %w", err)
	}
	if _, err := db.client.Exec("CREATE INDEX indices_artifact_idx ON indices(artifact_idx)"); err != nil {
		return xerrors.Errorf("unable to create 'indices_artifact_idx' index: %w", err)
	}

	if _, err := db.client.Exec("DROP TABLE primary_indices"); err != nil {
		return xerrors.Errorf("unable to drop 'primary_indices' index: %w", err)
	}
	if _, err := db.client.Exec("VACUUM"); err != nil {
		return xerrors.Errorf("vacuum database error: %w", err)
	}
	log.Printf("DB has been normalized")
	return nil
}

//////////////////////////////////////
// functions to interaction with DB //
//////////////////////////////////////

func (db *DB) InsertIndexes(indexes []*types.Index) error {
	tx, err := db.client.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, i := range indexes {
		_, err := tx.Exec(`INSERT OR IGNORE INTO primary_indices(group_id, artifact_id, version, sha1, archive_type) VALUES (?, ?, ?, ?, ?)`, i.GroupID, i.ArtifactID, i.Version, i.Sha1, i.ArchiveType)
		if err != nil {
			log.Printf("%+v", i)
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) SelectIndexBySha1(sha1 string) (types.Index, error) {
	index := types.Index{}
	sha1b, err := hex.DecodeString(sha1)
	if err != nil {
		return index, xerrors.Errorf("sha1 decode error: %w", err)
	}
	row := db.client.QueryRow(`Select a.group_id, a.artifact_id, i.version, i.sha1, i.archive_type from indices i JOIN artifacts a ON a.idx = i.artifact_idx 
                                                                    where i.sha1 = ?`, sha1b)
	err = row.Scan(&index.GroupID, &index.ArtifactID, &index.Version, &index.Sha1, &index.ArchiveType)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return index, xerrors.Errorf("select index error: %w", err)
	}
	return index, nil
}

func (db *DB) SelectIndexByArtifactIDAndGroupID(artifactID, groupID string) (types.Index, error) {
	index := types.Index{}
	row := db.client.QueryRow(`Select a.group_id, a.artifact_id, i.version, i.sha1, i.archive_type from indices i JOIN artifacts a ON a.idx = i.artifact_idx 
                                                                    where a.group_id = ? AND a.artifact_id = ?`, groupID, artifactID)
	err := row.Scan(&index.GroupID, &index.ArtifactID, &index.Version, &index.Sha1, &index.ArchiveType)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return index, xerrors.Errorf("select index error: %w", err)
	}
	return index, nil
}

func (db *DB) SelectIndexesByArtifactIDAndFileType(artifactID string, fileType types.ArchiveType) ([]types.Index, error) {
	var indexes []types.Index
	rows, err := db.client.Query(`Select a.group_id, a.artifact_id, i.version, i.sha1, i.archive_type from indices i JOIN artifacts a ON a.idx = i.artifact_idx 
                                                                    where a.artifact_id = ? AND i.archive_type = ?`, artifactID, fileType)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, xerrors.Errorf("select indexes error: %w", err)
	}
	for rows.Next() {
		var index types.Index
		if err = rows.Scan(&index.GroupID, &index.ArtifactID, &index.Version, &index.Sha1, &index.ArchiveType); err != nil {
			return nil, xerrors.Errorf("scan row error: %w", err)
		}
		indexes = append(indexes, index)
	}
	return indexes, nil
}
