cargo build --release --target wasm32-unknown-unknown --package auth_canister
candid-extractor target/wasm32-unknown-unknown/release/auth_canister.wasm > src/auth_canister.did