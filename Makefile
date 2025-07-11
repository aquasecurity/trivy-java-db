LDFLAGS=-ldflags "-s -w"
GO_SRCS := $(shell find . -name *.go)
CACHE_DIR ?= ./cache

.PHONY: test
test:
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: build
build: trivy-java-db

trivy-java-db: $(GO_SRCS)
	go build $(LDFLAGS) ./cmd/trivy-java-db

.PHONY: db-build
db-build: trivy-java-db
ifdef MAVEN_INDEX_DIR
	./trivy-java-db --cache-dir $(CACHE_DIR) --index-dir $(MAVEN_INDEX_DIR) build
else
	./trivy-java-db --cache-dir $(CACHE_DIR) build
endif

.PHONY: db-compress
db-compress: $(CACHE_DIR)/*
	tar cvzf $(CACHE_DIR)/db/javadb.tar.gz -C $(CACHE_DIR)/db/ trivy-java.db metadata.json

.PHONY: clean
clean:
	rm -rf $(CACHE_DIR)/
