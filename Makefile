LDFLAGS=-ldflags "-s -w"
GO_SRCS := $(shell find . -name *.go)

.PHONY: test
test:
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: build
build: trivy-java-db

trivy-java-db: $(GO_SRCS)
	go build $(LDFLAGS) ./cmd/trivy-java-db

.PHONY: db-build
db-build: cache/*

cache/*: trivy-java-db
	./trivy-java-db -cache-dir ./cache

.PHONY: db-compress
db-compress: cache/*
	tar cvzf cache/trivy-java-db/javadb.tar.gz -C cache/trivy-java-db/ trivy-java.db metadata.json

.PHONY: clean
clean:
	rm -rf cache/
