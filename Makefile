.PHONY: build-rust build-go test-rust test-go test docker-keygen docker-sign clean

build-rust:
	cargo build --release -p frost-lib

build-go: build-rust
	mkdir -p go-frost/includes/darwin go-frost/includes/linux
	@if [ "$$(uname)" = "Darwin" ]; then \
		cp target/release/libfrostlib.dylib go-frost/includes/darwin/; \
	else \
		cp target/release/libfrostlib.so go-frost/includes/linux/; \
	fi
	cp frost-lib/include/frost-lib.h go-frost/includes/
	cd go-frost && go build ./...

test-rust:
	cargo test -p frost-lib

test-go: build-go
	cd go-frost && go test -v ./...

test: test-rust test-go

docker-keygen:
	cd poc-frost && ./scripts/run-keygen.sh $(SESSION)

docker-sign:
	cd poc-frost && ./scripts/run-sign.sh $(SESSION) "$(MESSAGE)" "$(SIGNERS)"

clean:
	cargo clean
	rm -f go-frost/includes/darwin/libfrostlib.dylib
	rm -f go-frost/includes/linux/libfrostlib.so
