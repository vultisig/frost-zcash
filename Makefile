.PHONY: build-rust build-go build-linux-amd64 build-linux-arm64 test-rust test-go test-wasm test test-all docker-keygen docker-sign clean

build-rust:
	cargo build --release -p frozt-lib

build-go: build-rust
	mkdir -p go-frozt/includes/darwin go-frozt/includes/linux-amd64 go-frozt/includes/linux-arm64
	@if [ "$$(uname)" = "Darwin" ]; then \
		cp target/release/libfroztlib.dylib go-frozt/includes/darwin/; \
	else \
		ARCH=$$(uname -m); \
		if [ "$$ARCH" = "x86_64" ]; then \
			cp target/release/libfroztlib.so go-frozt/includes/linux-amd64/; \
		elif [ "$$ARCH" = "aarch64" ]; then \
			cp target/release/libfroztlib.so go-frozt/includes/linux-arm64/; \
		fi; \
	fi
	cp frozt-lib/include/frozt-lib.h go-frozt/includes/
	cd go-frozt && go build ./...

build-linux-amd64:
	cargo build --release -p frozt-lib --target x86_64-unknown-linux-gnu
	mkdir -p go-frozt/includes/linux-amd64
	cp target/x86_64-unknown-linux-gnu/release/libfroztlib.so go-frozt/includes/linux-amd64/
	cp frozt-lib/include/frozt-lib.h go-frozt/includes/

build-linux-arm64:
	cargo build --release -p frozt-lib --target aarch64-unknown-linux-gnu
	mkdir -p go-frozt/includes/linux-arm64
	cp target/aarch64-unknown-linux-gnu/release/libfroztlib.so go-frozt/includes/linux-arm64/
	cp frozt-lib/include/frozt-lib.h go-frozt/includes/

test-rust:
	cargo test -p frozt-lib

test-go: build-go
	cd go-frozt && go test -v ./...

test-wasm:
	cd frozt-wasm && wasm-pack test --node

test: test-rust test-go

test-all: test-rust test-go test-wasm

docker-keygen:
	cd poc-frozt && ./scripts/run-keygen.sh $(SESSION)

docker-sign:
	cd poc-frozt && ./scripts/run-sign.sh $(SESSION) "$(MESSAGE)" "$(SIGNERS)"

clean:
	cargo clean
	rm -f go-frozt/includes/darwin/libfroztlib.dylib
	rm -f go-frozt/includes/linux-amd64/libfroztlib.so
	rm -f go-frozt/includes/linux-arm64/libfroztlib.so
