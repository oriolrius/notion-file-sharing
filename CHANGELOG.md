## v2.1.0 (2026-11-12)

### Feat

- **release**: CLI binaries for x86_64 and i686 with glibc

## v2.0.1 (2026-11-12)

### Fix

- **web**: show validation errors in Catalan

## v2.0.0 (2026-11-12)

### BREAKING CHANGE

- configuration moves from modules/config.lua to a TOML file;
the Docker CLI wrappers (nfs.sh, nfs_decode.sh) and the -K/-G/-D/-L options
are removed.

### Feat

- rewrite NFS in Rust: server, web generator and CLI
