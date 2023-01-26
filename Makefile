LDFLAGS=-ldflags "-s -w"

.PHONY: test
test:
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: build
build:
	go build $(LDFLAGS) ./cmd/trivy-java-db

.PHONY: db-build
db-build: trivy-java-db
	TRIVY_JAVA_DB_CACHE=./cache ./trivy-java-db

.PHONY: db-compress
db-compress: cache/trivy-java-db/java-db/trivy-java.db cache/trivy-java-db/java-db/metadata.json
	tar cvzf cache/trivy-java-db/java-db/db.tar.gz -C cache/trivy-java-db/java-db/ trivy-java.db metadata.json