package main

import (
	"context"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/crawler"
	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy-java-db/pkg/metadata"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("%+v", err)
	}
}

var (
	// Used for flags.
	cacheDir string
	limit    int

	rootCmd = &cobra.Command{
		Use:   "trivy-java-db",
		Short: "Build Java DB to store maven indexes",
	}
	crawlCmd = &cobra.Command{
		Use:   "crawl",
		Short: "Crawl maven indexes and save them into files",
		RunE: func(cmd *cobra.Command, args []string) error {
			return crawl(cmd.Context())
		},
	}
	buildCmd = &cobra.Command{
		Use:   "build",
		Short: "Build Java DB",
		RunE: func(cmd *cobra.Command, args []string) error {
			return build()
		},
	}
)

func init() {
	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		log.Fatal(err)
	}

	rootCmd.PersistentFlags().StringVar(&cacheDir, "cache-dir", userCacheDir, "config file (default is $HOME/.cobra.yaml)")
	rootCmd.PersistentFlags().IntVar(&limit, "limit", 1000, "max parallelism")

	rootCmd.AddCommand(crawlCmd)
	rootCmd.AddCommand(buildCmd)
}

func crawl(ctx context.Context) error {
	indexesDir := filepath.Join(cacheDir, "trivy-java-db", "indexes")
	log.Printf("crawl maven repository and save indexes in %s", indexesDir)
	c := crawler.NewCrawler(crawler.Option{
		Limit: int64(limit),
		Dir:   indexesDir,
	})
	if err := c.Crawl(ctx); err != nil {
		return xerrors.Errorf("crawl error: %w", err)
	}
	return nil
}

func build() error {
	dbDir := filepath.Join(cacheDir, "trivy-java-db")
	log.Printf("Database directory: %s", dbDir)
	dbc, err := db.New(dbDir)
	if err != nil {
		return xerrors.Errorf("db create error: %w", err)
	}
	if err = dbc.Init(); err != nil {
		return xerrors.Errorf("db init error: %w", err)
	}
	meta := metadata.New(dbDir)
	if err = dbc.BuildDB(meta); err != nil {
		return xerrors.Errorf("insert indexes to db error: %w", err)
	}
	return nil
}
