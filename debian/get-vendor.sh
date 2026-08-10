#!/bin/sh
# Populate debian/vendor so the package builds with no network access
# (Debian buildds are offline). Re-run when dependencies change.
set -eu
cd "$(dirname "$0")/.."
# Vendor from scratch: cargo vendor does not restore files that are missing
# from an existing tree, so an incremental run cannot repair a pruned crate.
rm -rf debian/vendor
cargo vendor --versioned-dirs debian/vendor >/dev/null
echo "vendored into debian/vendor:"
ls debian/vendor
