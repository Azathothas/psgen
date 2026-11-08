BIN := target/x86_64-unknown-linux-musl/release/psgen

.PHONY: build test measure clean

build:
	cargo build --release --target x86_64-unknown-linux-musl

test: build
	mkdir -p target/release
	cp $(BIN) target/release/psgen
	sh tests/smoke.sh

measure: build
	mkdir -p target/release
	cp $(BIN) target/release/psgen
	python3 bench/measure.py

clean:
	cargo clean
	rm -rf dist
