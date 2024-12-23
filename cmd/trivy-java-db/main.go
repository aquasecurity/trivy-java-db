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
		panic(err)
	}

	rootCmd.PersistentFlags().StringVar(&cacheDir, "cache-dir", filepath.Join(userCacheDir, "trivy-java-db"),
		"cache dir")
	rootCmd.PersistentFlags().IntVar(&limit, "limit", 300, "max parallelism")

	rootCmd.AddCommand(crawlCmd)
	rootCmd.AddCommand(buildCmd)

	slog.SetLogLoggerLevel(slog.LevelInfo) // TODO: add --debug
}

func crawl(ctx context.Context) error {
	opt := crawler.Option{
		Limit:    int64(limit),
		CacheDir: cacheDir,
	}

	dbDir := db.Dir(cacheDir)
	if db.Exists(dbDir) {
		t, err := db.GetMetadataUpdatedAt(dbDir)
		if err != nil {
			return xerrors.Errorf("unable to get metadata UpdatedAt time: %w", err)
		}
		// Decrease the date by one day to offset the time of database creation
		opt.LastUpdate = t.AddDate(0, 0, -1)
		slog.Info("Using 'UpdatedAt' field to skip already added artifacts",
			slog.String("date", fmt.Sprintf("%d-%d-%d", opt.LastUpdate.Year(), opt.LastUpdate.Month(), opt.LastUpdate.Day())))
	}

	c := crawler.NewCrawler(opt)

	if err := c.Crawl(ctx); err != nil {
		return xerrors.Errorf("crawl error: %w", err)
	}
	return nil
}

func build() error {
	dbDir := db.Dir(cacheDir)
	slog.Info("Database", slog.String("path", dbDir))
	dbc, err := db.New(dbDir)
	if err != nil {
		return xerrors.Errorf("db create error: %w", err)
	}
	if !db.Exists(dbDir) {
		if err = dbc.Init(); err != nil {
			return xerrors.Errorf("db init error: %w", err)
		}
	}

	meta := db.NewMetadata(dbDir)
	b := builder.NewBuilder(dbc, meta)
	if err = b.Build(cacheDir); err != nil {
		return xerrors.Errorf("db build error: %w", err)
	}
	return nil
}
