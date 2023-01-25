LDFLAGS=-ldflags "-s -w"

.PHONY: test
test:
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: build
build:
	go build $(LDFLAGS) ./cmd/trivy-java-db