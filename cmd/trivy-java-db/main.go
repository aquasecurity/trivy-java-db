package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler"
	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy-java-db/pkg/metadata"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("%+v", err)
	}
}

func run() error {
	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		return err
	}

	crawl := flag.Bool("crawl", false, "crawl maven indexes and save them to files")
	build := flag.Bool("build", false, "build db from stored maven index files")
	cacheDir := flag.String("cache-dir", userCacheDir, "cache dir")
	flag.Parse()

	if !*crawl && !*build {
		return xerrors.Errorf("command not selected")
	}

	dbDir := filepath.Join(*cacheDir, "trivy-java-db")

	if *crawl {
		indexesDir := filepath.Join(dbDir, "indexes")
		log.Printf("crawl maven repository and save indexes in %s", indexesDir)
		c := crawler.NewCrawler(crawler.Option{
			Limit: 1000,
			Dir:   indexesDir,
		})
		ctx := context.Background()
		if err = c.Crawl(ctx); err != nil {
			return xerrors.Errorf("crawl error: %w", err)
		}
	}

	if *build {
		log.Printf("The database directory: %s", dbDir)
		meta := metadata.New(dbDir)
		dbc, err := db.New(dbDir, meta)
		if err != nil {
			return xerrors.Errorf("db create error: %w", err)
		}
		if err = dbc.Init(); err != nil {
			return xerrors.Errorf("db init error: %w", err)
		}
		if err = dbc.BuildDB(); err != nil {
			return xerrors.Errorf("insert indexes to db error: %w", err)
		}
	}

	return nil
}
