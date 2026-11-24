WASM_TARGET := wasm32-unknown-unknown
OUT  := target/$(WASM_TARGET)/release/deckwatch_plugin_aws.wasm
DIST := dist/plugin.wasm

MOTO_ENDPOINT ?= http://localhost:5000

.PHONY: build test integration clean

build:
	cargo build --release --target $(WASM_TARGET)
	mkdir -p dist
	cp $(OUT) $(DIST)
	@echo "artifact: $(DIST) ($$(wc -c < $(DIST)) bytes)"

test:
	cargo test --target $$(rustc -vV | sed -n 's/host: //p')

# Requires a moto server: docker run --rm -p 5000:5000 motoserver/moto:5.2.6
integration: build
	cd integration && MOTO_ENDPOINT=$(MOTO_ENDPOINT) \
		cargo test --target $$(rustc -vV | sed -n 's/host: //p')

clean:
	cargo clean
	cd integration && cargo clean
	rm -f $(DIST)
