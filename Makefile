GO ?= go
export GOCACHE ?= $(CURDIR)/.cache/go-build
export GOMODCACHE ?= $(CURDIR)/.cache/go-mod
IMAGE ?= cmtc:dev

.PHONY: test build image lab-up lab-test lab-evidence lab-down
test:
	$(GO) test -race ./...
	$(GO) vet ./...
build:
	$(GO) build -trimpath -o bin/cmtc ./cmd/cmtc
image:
	docker build -t $(IMAGE) .
lab-up:
	CMTC_IMAGE=$(IMAGE) bash scripts/lab/up.sh
lab-test:
	bash scripts/lab/test.sh
lab-evidence:
	bash scripts/lab/evidence.sh
lab-down:
	bash scripts/lab/down.sh
