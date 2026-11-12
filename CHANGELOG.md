## v2.0.0 (2026-11-12)

### BREAKING CHANGE

- configuration moves from modules/config.lua to a TOML file;
the Docker CLI wrappers (nfs.sh, nfs_decode.sh) and the -K/-G/-D/-L options
are removed.

### Feat

- rewrite NFS in Rust: server, web generator and CLI
