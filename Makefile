GO_FILES?=$$(find . -name '*.go' |grep -v vendor)
TAG?=stendler-$$(git rev-parse --verify HEAD --short)
SQUASH?=false
VERSION?=0.1.8

default: lint vet build test

.PHONY: test
test: goimportscheck
	go test -v . .

.PHONY: testacc
testacc: goimportscheck
	go test -count=1 -v . -run="TestAcc" -timeout 20m

.PHONY: build
build:
	docker build -t gitlab-registry.tubit.tu-berlin.de/stendler/faas-policy-provider:$(TAG) . --squash=${SQUASH}

.PHONY: build-local
build-local:
	go build --ldflags "-s -w \
        -X github.com/PEng2020-Subject3/faas-policy-provider/version.GitCommitSHA=${GIT_COMMIT_SHA} \
        -X \"github.com/PEng2020-Subject3/faas-policy-provider/version.GitCommitMessage=${GIT_COMMIT_MESSAGE}\" \
        -X github.com/PEng2020-Subject3/faas-policy-provider/version.Version=${VERSION}" \
        -o faas-policy-provider .

.PHONY: up-local
up: build
	docker stack deploy policy-provider --compose-file ./docker-compose.yml

.PHONY: push
push:
	docker tag gitlab-registry.tubit.tu-berlin.de/stendler/faas-policy-provider:${TAG} gitlab-registry.tubit.tu-berlin.de/stendler/faas-policy-provider:${VERSION}
	docker push gitlab-registry.tubit.tu-berlin.de/stendler/faas-policy-provider:${VERSION}

.PHONY: release
release:
	go get github.com/goreleaser/goreleaser; \
	goreleaser; \

.PHONY: clean
clean:
	rm -rf pkg/

.PHONY: goimports
goimports:
	goimports -w $(GO_FILES)

.PHONY: goimportscheck
goimportscheck:
	@sh -c "'$(CURDIR)/scripts/goimportscheck.sh'"

.PHONY: vet
vet:
	@echo "go vet ."
	@go vet $$(go list ./... | grep -v vendor/ | grep -v examples/) ; if [ $$? -eq 1 ]; then \
		echo ""; \
		echo "Vet found suspicious constructs. Please check the reported constructs"; \
		echo "and fix them if necessary before submitting the code for review."; \
		exit 1; \
	fi

.PHONY: lint
lint:
	@echo "golint ."
	@golint -set_exit_status $$(go list ./... | grep -v vendor/) ; if [ $$? -eq 1 ]; then \
		echo ""; \
		echo "Lint found errors in the source code. Please check the reported errors"; \
		echo "and fix them if necessary before submitting the code for review."; \
		exit 1; \
	fi