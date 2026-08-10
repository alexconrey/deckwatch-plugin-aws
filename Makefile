WASM_TARGET := wasm32-unknown-unknown
OUT  := target/$(WASM_TARGET)/release/deckwatch_plugin_aws.wasm
DIST := dist/plugin.wasm

.PHONY: build test clean

build:
	cargo build --release --target $(WASM_TARGET)
	mkdir -p dist
	cp $(OUT) $(DIST)
	@echo "artifact: $(DIST) ($$(wc -c < $(DIST)) bytes)"

test:
	cargo test --target $$(rustc -vV | sed -n 's/host: //p')

clean:
	cargo clean
	rm -f $(DIST)
