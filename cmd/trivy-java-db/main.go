package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-java-db/pkg/builder"
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
	indexDir string

	rootCmd = &cobra.Command{
		Use:   "trivy-java-db",
		Short: "Build Java DB to store maven indexes",
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

	rootCmd.AddCommand(buildCmd)

	slog.SetLogLoggerLevel(slog.LevelInfo) // TODO: add --debug
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

	centralIndexDir := filepath.Join(indexDir, "central")
	meta := db.NewMetadata(dbDir)
	b := builder.NewBuilder(dbc, meta)
	if err = b.Build(centralIndexDir); err != nil {
		return xerrors.Errorf("db build error: %w", err)
	}
	return nil
}
