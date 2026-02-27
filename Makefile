.PHONY: build-rust build-go test-rust test-go test docker-keygen docker-sign clean

build-rust:
	cargo build --release -p frozt-lib

build-go: build-rust
	mkdir -p go-frozt/includes/darwin go-frozt/includes/linux
	@if [ "$$(uname)" = "Darwin" ]; then \
		cp target/release/libfroztlib.dylib go-frozt/includes/darwin/; \
	else \
		cp target/release/libfroztlib.so go-frozt/includes/linux/; \
	fi
	cp frozt-lib/include/frozt-lib.h go-frozt/includes/
	cd go-frozt && go build ./...

test-rust:
	cargo test -p frozt-lib

test-go: build-go
	cd go-frozt && go test -v ./...

test: test-rust test-go

docker-keygen:
	cd poc-frozt && ./scripts/run-keygen.sh $(SESSION)

docker-sign:
	cd poc-frozt && ./scripts/run-sign.sh $(SESSION) "$(MESSAGE)" "$(SIGNERS)"

clean:
	cargo clean
	rm -f go-frozt/includes/darwin/libfroztlib.dylib
	rm -f go-frozt/includes/linux/libfroztlib.so
