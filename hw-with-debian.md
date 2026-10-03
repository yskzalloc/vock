# When using --mode hw, ensure that `--kernel-src` and `--vmlinux` are set correctly.

Example environment: Debian 13 (Trixie) backports kernel.
```
  My running kernel
    7.1.3+deb13-amd64
          │
          ▼
  Binary package
    linux-image-7.1.3+deb13-amd64
    Version: 7.1.3-1~bpo13+1
          │
          ▼
  Debian kernel source
    linux 7.1.3-1~bpo13+1
          │
          ├── linux_7.1.3.orig.tar.xz        ✓ SHA256 matched
          │
          ├── linux_7.1.3-1~bpo13+1.debian.tar.xz ✓ SHA256 matched
          │
          └── linux_7.1.3-1~bpo13+1.dsc
          │
          ▼
    dpkg-source -x
          │
          ▼
    linux-7.1.3/
```

## `--vmlinux`: Path to the my debian vmlinux file with debug symbols

```
$ sudo tee -a /etc/apt/sources.list.d/debian-debug.sources <<'EOF'

Types: deb
URIs: https://deb.debian.org/debian-debug
Suites: trixie-backports-debug
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF

$ sudo apt update
```

```
# Install debug symbol kernel
$ apt search linux-image-7.1.*-amd64-dbg

linux-image-7.1.3+deb13-amd64-dbg/stable-backports,now 7.1.3-1~bpo13+1 amd64 [installed]
  Linux 7.1.3 for 64-bit PCs (debug symbols)
```

## `--kernel-src`: Path to the debian kernel source directory

```
$ dpkg-query -W linux-image-$(uname -r)
linux-image-7.1.3+deb13-amd64	7.1.3-1~bpo13+1


$ dpkg -s linux-image-$(uname -r) | grep -E '^(Package|Version|Source):'
Package: linux-image-7.1.3+deb13-amd64
Source: linux-signed-amd64 (7.1.3+1~bpo13+1)
Version: 7.1.3-1~bpo13+1


$ KVER=$(uname -r)
PKGVER=$(dpkg-query -W -f='${Version}' linux-image-$KVER)
 
echo "$PKGVER"
bash:  : command not found
7.1.3-1~bpo13+1
```

Go to `https://snapshot.debian.org/package/linux/7.1.3-1~bpo13+1/`
```
wget 'https://snapshot.debian.org/archive/debian-debug/20260704T211259Z/pool/main/l/linux/linux_7.1.3.orig.tar.xz'
wget 'https://snapshot.debian.org/archive/debian/20260721T202111Z/pool/main/l/linux/linux_7.1.3-1~bpo13%2B1.debian.tar.xz'
wget 'https://snapshot.debian.org/archive/debian/20260721T202111Z/pool/main/l/linux/linux_7.1.3-1~bpo13%2B1.dsc'

$ grep -A20 '^Checksums-Sha256:' linux_7.1.3-1~bpo13+1.dsc
Checksums-Sha256:
 61cdf2ccda33d046aa9fcd40a130bfddd03a3c8b2379fc08925f0efe7f69a32c 161574724 linux_7.1.3.orig.tar.xz
 872e488d0c26a36a716cfb3fb174f09ba39f557a336f5add08329cf084276d33 1470044 linux_7.1.3-1~bpo13+1.debian.tar.xz
Files:
 e67e4ddf89ee17b48f70e04defc1fb25 161574724 linux_7.1.3.orig.tar.xz
 3fa810a3f4ba178a93ea03dc2a55a2cf 1470044 linux_7.1.3-1~bpo13+1.debian.tar.xz

$ sha256sum linux_7.1.3.orig.tar.xz linux_7.1.3-1~bpo13+1.debian.tar.xz
61cdf2ccda33d046aa9fcd40a130bfddd03a3c8b2379fc08925f0efe7f69a32c  linux_7.1.3.orig.tar.xz
872e488d0c26a36a716cfb3fb174f09ba39f557a336f5add08329cf084276d33  linux_7.1.3-1~bpo13+1.debian.tar.xz
```
