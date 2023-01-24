package main

import (
	"context"
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

	if err = db.Init(filepath.Join(cacheDir, "trivy-java-db")); err != nil {
		return xerrors.Errorf("db init error: %w", err)
	}

	ctx := context.Background()
	c := crawler.NewCrawler(crawler.Option{
		Limit: 1000,
	})
	if err = c.Crawl(ctx); err != nil {
		return xerrors.Errorf("crawl error: %w", err)
	}

	return nil
}
