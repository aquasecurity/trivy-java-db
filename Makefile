LDFLAGS=-ldflags "-s -w"
GO_SRCS := $(shell find . -name *.go)
MAVEN_INDEX_DIR ?= $(HOME)/.cache/maven-index

.PHONY: test
test:
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: build
build: trivy-java-db

trivy-java-db: $(GO_SRCS)
	go build $(LDFLAGS) ./cmd/trivy-java-db

.PHONY: db-build
db-build: trivy-java-db
	./trivy-java-db --cache-dir ./cache --index-dir $(MAVEN_INDEX_DIR) build

.PHONY: db-compress
db-compress: cache/*
	tar cvzf cache/db/javadb.tar.gz -C cache/db/ trivy-java.db metadata.json

.PHONY: clean
clean:
	rm -rf cache/
