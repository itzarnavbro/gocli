.PHONY: build test race lint vuln run docker-build docker-run docker-test clean

build:
	go build -trimpath -ldflags="-s -w" -o bin/app ./cmd/app

test:
	go vet ./...
	go test -count=1 ./...

race:
	go test -race -count=1 ./...

lint:
	golangci-lint run

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

run:
	DB_PATH=./app.db TOTP_ENC_KEY=$${TOTP_ENC_KEY:?set TOTP_ENC_KEY (64 hex chars)} go run ./cmd/app

docker-build:
	docker compose build

docker-run:
	docker compose run --rm app

docker-test:
	docker compose --profile test run --rm test

clean:
	rm -rf bin app.db app.db-wal app.db-shm