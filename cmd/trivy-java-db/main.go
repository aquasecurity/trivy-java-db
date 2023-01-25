package main

import (
	"context"
	"github.com/aquasecurity/trivy-java-db/metadata"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler"
	"github.com/aquasecurity/trivy-java-db/pkg/db"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("%+v", err)
	}
}

func run() error {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return err
	}

	dbDir := filepath.Join(cacheDir, "trivy-java-db")

	if err = db.Init(dbDir); err != nil {
		return xerrors.Errorf("db init error: %w", err)
	}
	metadata.Init(dbDir)

	ctx := context.Background()
	c := crawler.NewCrawler(crawler.Option{
		Limit: 1000,
	})
	if err = c.Crawl(ctx); err != nil {
		return xerrors.Errorf("crawl error: %w", err)
	}

	return nil
}
