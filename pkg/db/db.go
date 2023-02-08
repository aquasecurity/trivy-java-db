package db

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/aquasecurity/trivy-java-db/pkg/crawler"
	"github.com/aquasecurity/trivy-java-db/pkg/metadata"
	"github.com/aquasecurity/trivy-java-db/pkg/utils"
	"io"
	"k8s.io/utils/clock"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"golang.org/x/xerrors"
)

const (
	dbFileName     = "trivy-java.db"
	schemaVersion  = 1
	updateInterval = time.Hour * 72 // 3 days
)

type DB struct {
	client *sql.DB
	dir    string
	clock  clock.Clock
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

	return DB{
		client: db,
		dir:    dbDir,
		clock:  clock.RealClock{},
	}, nil
}

func (db *DB) Init() error {
	if _, err := db.client.Exec("PRAGMA foreign_keys=true"); err != nil {
		return xerrors.Errorf("failed to enable 'foreign_keys': %w", err)
	}
	if _, err := db.client.Exec("CREATE TABLE artifacts(id INTEGER PRIMARY KEY, group_id TEXT, artifact_id TEXT)"); err != nil {
		return xerrors.Errorf("unable to create 'artifacts' table: %w", err)
	}
	if _, err := db.client.Exec("CREATE TABLE indices(artifact_id INTEGER, version TEXT, sha1 BLOB, archive_type TEXT, foreign key (artifact_id) references artifacts(id))"); err != nil {
		return xerrors.Errorf("unable to create 'indices' table: %w", err)
	}

	if _, err := db.client.Exec("CREATE UNIQUE INDEX artifacts_idx ON artifacts(group_id, artifact_id)"); err != nil {
		return xerrors.Errorf("unable to create 'artifacts_idx' index: %w", err)
	}
	if _, err := db.client.Exec("CREATE UNIQUE INDEX indices_sha1_idx ON indices(sha1)"); err != nil {
		return xerrors.Errorf("unable to create 'indices_sha1_idx' index: %w", err)
	}
	return nil
}

func (db *DB) Dir() string {
	return db.dir
}

func (db *DB) VacuumDB() error {
	if _, err := db.client.Exec("VACUUM"); err != nil {
		return xerrors.Errorf("vacuum database error: %w", err)
	}
	return nil
}

//////////////////////////////////////
// functions to interaction with DB //
//////////////////////////////////////

func (db *DB) BuildDB(meta metadata.Client) error {
	indexesDir := filepath.Join(db.dir, crawler.IndexesDir)
	var indexes []*crawler.Index
	if err := utils.FileWalk(indexesDir, func(r io.Reader, path string) error {
		index := &crawler.Index{}
		if err := json.NewDecoder(r).Decode(index); err != nil {
			return xerrors.Errorf("failed to decode index: %w", err)
		}
		indexes = append(indexes, index)
		if len(indexes) > 1000 {
			if err := db.InsertIndexes(indexes); err != nil {
				return xerrors.Errorf("failed to insert indexes to db: %w", err)
			}
			indexes = []*crawler.Index{} // clear array after saving to db
		}
		return nil
	}); err != nil {
		return xerrors.Errorf("error in indexes walk: %w", err)
	}

	if err := db.VacuumDB(); err != nil {
		return xerrors.Errorf("fauled to vacuum db: %w", err)
	}
	// Insert the remaining indexes
	if err := db.InsertIndexes(indexes); err != nil {
		return xerrors.Errorf("failed to insert indexes to db: %w", err)
	}

	// save metadata
	metaDB := metadata.Metadata{
		Version:    schemaVersion,
		NextUpdate: db.clock.Now().UTC().Add(updateInterval),
		UpdatedAt:  db.clock.Now().UTC(),
	}
	if err := meta.Update(metaDB); err != nil {
		return xerrors.Errorf("failed to update metadata: %w", err)
	}

	return nil
}

func (db *DB) InsertIndexes(indexes []*crawler.Index) error {
	tx, err := db.client.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, i := range indexes {
		_, err = tx.Exec(`INSERT INTO artifacts(group_id, artifact_id) VALUES (?, ?)  ON CONFLICT(group_id, artifact_id) DO NOTHING`, i.GroupID, i.ArtifactID)
		if err != nil {
			return xerrors.Errorf("unable to insert to 'artifacts' table: %w", err)
		}
		for _, v := range i.Versions {
			if _, err = tx.Exec(`INSERT INTO indices(artifact_id, version, sha1, archive_type) VALUES ((SELECT id FROM artifacts where group_id=? AND artifact_id=?), ?, ?, ?) ON CONFLICT(sha1) DO NOTHING`,
				i.GroupID, i.ArtifactID, v.Version, v.Sha1, i.ArchiveType); err != nil {
				return xerrors.Errorf("unable to insert to 'indices' table: %w", err)
			}
		}

	}
	return tx.Commit()
}

func (db *DB) SelectIndexBySha1(sha1 string) (Index, error) {
	index := Index{}
	sha1b, err := hex.DecodeString(sha1)
	if err != nil {
		return index, xerrors.Errorf("sha1 decode error: %w", err)
	}
	row := db.client.QueryRow(`Select a.group_id, a.artifact_id, i.version, i.sha1, i.archive_type from indices i JOIN artifacts a ON a.id = i.artifact_id
                                                                   where i.sha1 = ?`, sha1b)
	err = row.Scan(&index.GroupID, &index.ArtifactID, &index.Version, &index.Sha1, &index.ArchiveType)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return index, xerrors.Errorf("select index error: %w", err)
	}
	return index, nil
}

func (db *DB) SelectIndexByArtifactIDAndGroupID(artifactID, groupID string) (Index, error) {
	index := Index{}
	row := db.client.QueryRow(`Select a.group_id, a.artifact_id, i.version, i.sha1, i.archive_type from indices i JOIN artifacts a ON a.id = i.artifact_id
                                                                   where a.group_id = ? AND a.artifact_id = ?`, groupID, artifactID)
	err := row.Scan(&index.GroupID, &index.ArtifactID, &index.Version, &index.Sha1, &index.ArchiveType)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return index, xerrors.Errorf("select index error: %w", err)
	}
	return index, nil
}

func (db *DB) SelectIndexesByArtifactIDAndFileType(artifactID string, fileType crawler.ArchiveType) ([]Index, error) {
	var indexes []Index
	rows, err := db.client.Query(`Select a.group_id, a.artifact_id, i.version, i.sha1, i.archive_type from indices i JOIN artifacts a ON a.id = i.artifact_id
                                                                  where a.artifact_id = ? AND i.archive_type = ?`, artifactID, fileType)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, xerrors.Errorf("select indexes error: %w", err)
	}
	for rows.Next() {
		var index Index
		if err = rows.Scan(&index.GroupID, &index.ArtifactID, &index.Version, &index.Sha1, &index.ArchiveType); err != nil {
			return nil, xerrors.Errorf("scan row error: %w", err)
		}
		indexes = append(indexes, index)
	}
	return indexes, nil
}
