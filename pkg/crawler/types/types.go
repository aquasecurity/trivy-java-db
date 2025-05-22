package types

import "context"

// Source defines an interface for retrieving Maven artifact records
type Source interface {
	// Read streams artifact records to the provided channel
	Read(ctx context.Context, recordCh chan<- Record) error

	// Processed returns the number of processed records
	Processed() int

	// Failed returns the number of failed records
	Failed() int
}

// Record represents a Maven artifact index with SHA1 hash
type Record struct {
	GroupID    string
	ArtifactID string
	Version    string
	Classifier string
	SHA1       string
}
