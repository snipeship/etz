# Installation

`etz` can be installed via Cargo, Homebrew, prebuilt binaries, or from source.

## Cargo

```bash
cargo install etz
```

## Homebrew

```bash
brew tap snipeship/tap
brew install snipeship/tap/etz
```

## Prebuilt binaries

```bash
curl -LO https://github.com/snipeship/etz/releases/latest/download/etz-<version>-<target>.tar.gz
tar -xzf etz-<version>-<target>.tar.gz
install -m 0755 etz /usr/local/bin/etz
```

## Build from source

Requirements:
- Rust 1.85+
- Git

```bash
git clone https://github.com/snipeship/etz.git
cd etz
cargo build --release
./target/release/etz --help
```
