.PHONY: build clean test nodejs bundler web

CARGO_FLAGS ?= --dev

build: nodejs

clean:
	@rm -rf pkg

nodejs web: clean
	wasm-pack -q build $(CARGO_FLAGS) --target $@ -d pkg
	@rm pkg/.gitignore pkg/package.json
	@cp pkg/* ../languages/js/oso/src/
	@mkdir -p ../languages/js/oso/dist/src
	@cp pkg/* ../languages/js/oso/dist/src/

bundler: clean
	wasm-pack -q build $(CARGO_FLAGS) --target $@ -d pkg
	@rm pkg/.gitignore pkg/package.json
	@mkdir -p ../languages/js/oso/dist/bundler
	@cp pkg/* ../languages/js/oso/dist/bundler/

test:
	wasm-pack test --node
