package db

import (
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"os"
)

func InitTmpDB(indexes []*types.Index) (string, error) {
	tempDir, err := os.MkdirTemp("", "test-java-db")
	if err != nil {
		return "", err
	}
	err = Init(tempDir)
	if err != nil {
		return "", err
	}
	if len(indexes) > 0 {
		InsertIndexes(indexes)
	}
	return tempDir, nil
}
