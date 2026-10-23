GO ?= go
export GOCACHE ?= $(CURDIR)/.cache/go-build
export GOMODCACHE ?= $(CURDIR)/.cache/go-mod
IMAGE ?= cmtc:dev
CAPTURE_IMAGE ?= cmtc-capture:dev

.PHONY: test build image capture-image lab-up lab-test lab-evidence lab-capture lab-down
test:
	$(GO) test -race ./...
	$(GO) vet ./...
build:
	$(GO) build -trimpath -o bin/cmtc ./cmd/cmtc
image:
	docker build -t $(IMAGE) .
capture-image:
	docker build -f scripts/capture/Dockerfile -t $(CAPTURE_IMAGE) .
lab-up:
	CMTC_IMAGE=$(IMAGE) bash scripts/lab/up.sh
lab-test:
	bash scripts/lab/test.sh
lab-evidence:
	bash scripts/lab/evidence.sh
lab-capture:
	CMTC_CAPTURE_IMAGE=$(CAPTURE_IMAGE) bash scripts/lab/capture.sh
lab-down:
	bash scripts/lab/down.sh
