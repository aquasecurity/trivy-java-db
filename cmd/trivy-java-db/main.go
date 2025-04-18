package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/builder"
	"github.com/aquasecurity/trivy-java-db/pkg/crawler"
	"github.com/aquasecurity/trivy-java-db/pkg/db"

	_ "modernc.org/sqlite"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		slog.Error(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}
}

var (
	// Used for flags.
	cacheDir   string
	indexDir   string
	limit      int
	shardCount int

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
		panic(err)
	}

	rootCmd.PersistentFlags().StringVar(&cacheDir, "cache-dir", filepath.Join(userCacheDir, "trivy-java-db"),
		"cache dir")
	rootCmd.PersistentFlags().StringVar(&indexDir, "index-dir", filepath.Join(userCacheDir, "maven-index"),
		"index repo dir")
	rootCmd.PersistentFlags().IntVar(&limit, "limit", 300, "max parallelism")
	crawlCmd.Flags().IntVar(&shardCount, "shards", 256, "number of shards")

	rootCmd.AddCommand(crawlCmd)
	rootCmd.AddCommand(buildCmd)

	slog.SetLogLoggerLevel(slog.LevelInfo) // TODO: add --debug
}

func crawl(ctx context.Context) error {
	c, err := crawler.NewCrawler(crawler.Option{
		Limit:    limit,
		Shard:    shardCount,
		CacheDir: cacheDir,
		IndexDir: filepath.Join(indexDir, "central"),
	})
	if err != nil {
		return xerrors.Errorf("unable to create new Crawler: %w", err)
	}
	if err := c.Crawl(ctx); err != nil {
		return xerrors.Errorf("crawl error: %w", err)
	}
	return nil
}

func build() error {
	dbDir := db.Dir(cacheDir)
	slog.Info("Database", slog.String("path", dbDir))

	exist := db.Exists(dbDir)
	if exist {
		slog.Info("Updating the existing database")
	} else {
		slog.Info("Creating a new database")
	}

	dbc, err := db.New(dbDir)
	if err != nil {
		return xerrors.Errorf("db create error: %w", err)
	}
	if !exist {
		if err = dbc.Init(); err != nil {
			return xerrors.Errorf("db init error: %w", err)
		}
	}

	indexDir := filepath.Join(indexDir, "central")
	meta := db.NewMetadata(dbDir)
	b := builder.NewBuilder(dbc, meta)
	if err = b.Build(indexDir); err != nil {
		return xerrors.Errorf("db build error: %w", err)
	}
	return nil
}
