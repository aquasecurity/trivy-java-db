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

	cacheDir := flag.String("cache-dir", userCacheDir, "cache dir")
	flag.Parse()

	dbDir := filepath.Join(*cacheDir, "trivy-java-db")
	log.Printf("The database directory: %s", dbDir)

	dbc, err := db.New(dbDir)
	if err != nil {
		return xerrors.Errorf("db create error: %w", err)
	}
	if err = dbc.Init(); err != nil {
		return xerrors.Errorf("db init error: %w", err)
	}
	meta := metadata.New(dbDir)

	c := crawler.NewCrawler(dbc, meta, crawler.Option{
		Limit: 1000,
	})

	ctx := context.Background()
	if err = c.Crawl(ctx); err != nil {
		return xerrors.Errorf("crawl error: %w", err)
	}

	return nil
}
