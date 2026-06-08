IMAGE ?= kentbull/interop-verifier
VERSION ?= 1.0.0

.PHONY: sync check test build clean docker-build docker-run docker-push publish-pypi

sync:
	uv sync --dev

check:
	uv run python -m compileall src tests
	uv run pytest -q

test:
	uv run pytest -q

build: clean
	uv build
	uv run twine check dist/*

clean:
	rm -rf build dist *.egg-info

docker-build:
	docker build -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

docker-run:
	docker run --rm $(IMAGE):$(VERSION) version

docker-push:
	docker push $(IMAGE):$(VERSION)
	docker push $(IMAGE):latest

publish-pypi: build
	uv run twine upload dist/*
