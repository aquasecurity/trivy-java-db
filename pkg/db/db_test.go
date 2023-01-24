package db

import "testing"

func TestInsertIndex(t *testing.T) {
	Init("/home/dmitriy/.cache/trivy")
	InsertIndex("g", "a", "v", "sha")
}

func TestSelectGAVbySha1(t *testing.T) {
	Init("/home/dmitriy/.cache/trivy")
	SelectGAVbySha1("15b45667fc8a2eaffb43ab0bbc5f1f349e055780")
}
