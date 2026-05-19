#!/bin/bash
# fuzz.sh — Aggressive KASAN bug hunting via vock fuzz
#
# Usage:
#   ./fuzz.sh              # default: ~/net kernel
#   ./fuzz.sh ~/net        # custom kernel path
#
# Target: xts(aes) decrypt — exercises crypto subsystem write paths
#   (skcipher_walk, aes_decrypt, xts_crypt, af_alg, crypto_skcipher_*)
#
# NOTE: KASAN kernels take 60-90s to boot. Be patient.

KERNEL_DIR="${1:-$HOME/net}"
VOCK_DIR="$(cd "$(dirname "$0")" && pwd)"
PROCS=8

echo "=== vock fuzz — KASAN Bug Hunter ==="
echo "Kernel:  $KERNEL_DIR"
echo "Target:  xts(aes) decrypt"
echo "Workers: $PROCS"
echo ""

if [ ! -f "$KERNEL_DIR/Makefile" ]; then
    echo "ERROR: $KERNEL_DIR is not a kernel tree"; exit 1
fi

# Build KASAN+KCOV+CRYPTO kernel if needed
cd "$KERNEL_DIR"
if ! grep -q "CONFIG_KASAN=y" .config 2>/dev/null || \
   ! grep -q "CONFIG_CRYPTO_XTS=y" .config 2>/dev/null; then
    echo "[*] Building KASAN kernel with vng..."
    vng --configitem CONFIG_KASAN=y \
        --configitem CONFIG_KASAN_GENERIC=y \
        --configitem CONFIG_KCOV=y \
        --configitem CONFIG_KCOV_INSTRUMENT_ALL=y \
        --configitem CONFIG_CRYPTO=y \
        --configitem CONFIG_CRYPTO_XTS=y \
        --configitem CONFIG_CRYPTO_AES=y \
        --configitem CONFIG_CRYPTO_USER_API=y \
        --configitem CONFIG_CRYPTO_USER_API_SKCIPHER=y \
        --configitem CONFIG_DEBUG_KERNEL=y \
        --configitem CONFIG_DEBUG_INFO=y \
        --configitem CONFIG_DEBUG_INFO_BTF=y \
        --configitem CONFIG_FRAME_WARN=4096 \
        --build LLVM=-21
    echo "[✓] Kernel built"
fi

echo "[✓] KASAN kernel ready"
echo "[*] Booting VM (KASAN kernels take ~60-90s to boot)..."
echo ""

# Write inner script
INNER=$(mktemp /tmp/vock_fuzz_XXXXXX.sh)
cat > "$INNER" << 'INNEREOF'
#!/bin/bash
set -e
cd VOCK_DIR_PLACEHOLDER
make CC=clang DEBUG_INFO_BTF=0 -s 2>/dev/null || make CC=gcc DEBUG_INFO_BTF=0 -s

# ─── Crypto setup (encrypt, not traced) ──────────────────────────────────────
dd if=/dev/urandom of=/tmp/block.img bs=64K count=64 2>/dev/null
printf "ThisIsA64ByteSecretKeyForAES256XTSModeWhichRequires512BitsOfData" > /tmp/key.bin
kcapi-enc -c "xts(aes)" -e -i /tmp/block.img -o /tmp/block.enc \
  --iv 00000000000000000000000000000000 --keyfd 3 3</tmp/key.bin

# Decrypt script (this is what vock will fuzz)
cat > /tmp/dec.sh << 'DEC'
#!/bin/sh
kcapi-enc -d -c "xts(aes)" -i /tmp/block.enc -o /tmp/block.dec \
  --iv 00000000000000000000000000000000 --keyfd 3 3</tmp/key.bin
DEC
chmod +x /tmp/dec.sh

echo ""
echo "=== Step 1: Verify mutations (3 iterations) ==="
echo ""

rm -f trace.syz fuzz_0.log trace_0.log
./vock fuzz -repeat=3 --mode kcov /bin/sh /tmp/dec.sh 2>&1 | grep "\[fuzz\]"

# Verify baseline
if [ ! -f trace.syz ]; then
    echo "FAIL: trace.syz not created."
    exit 1
fi
BASELINE_HASH=$(sha1sum trace.syz | cut -d' ' -f1)
BASELINE_LINES=$(wc -l < trace.syz)
echo "[✓] Baseline: $BASELINE_LINES syscalls (sha1: $BASELINE_HASH)"

# Verify mutations
if [ ! -f trace_0.log ]; then
    echo "FAIL: trace_0.log not created."
    exit 1
fi
CORPUS_HASH=$(grep -v "^#" trace_0.log | sha1sum | cut -d' ' -f1)
if [ "$BASELINE_HASH" = "$CORPUS_HASH" ]; then
    echo "FAIL: Corpus identical to baseline. Mutations broken!"
    exit 1
fi
echo "[✓] Mutations verified"

if [ -f fuzz_0.log ]; then
    NOVEL=$(awk 'NR>1{sum+=$4}END{print sum}' fuzz_0.log)
    echo "[✓] Novel PCs: $NOVEL"
    cat fuzz_0.log
fi

echo ""
echo "=== Step 2: Full fuzzing (PROCS_PLACEHOLDER workers) ==="
echo "=== Target: xts(aes) decrypt ==="
echo "=== Watching dmesg for KASAN/BUG ==="
echo ""

rm -f fuzz_*.log trace_*.log
./vock fuzz -procs=PROCS_PLACEHOLDER --mode kcov /bin/sh /tmp/dec.sh &
PID=$!

# Monitor dmesg for KASAN
(
    sleep 10
    ITER=0
    while kill -0 $PID 2>/dev/null; do
        ITER=$((ITER+1))
        BUGS=$(dmesg 2>/dev/null | grep -c "BUG: KASAN" || true)
        if [ "$BUGS" -gt 0 ]; then
            echo ""
            echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            echo "!!! KASAN BUG FOUND after ~$((ITER*2))s !!!"
            echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            dmesg | grep -B2 -A20 "BUG: KASAN" | head -50
            dmesg > VOCK_DIR_PLACEHOLDER/dmesg_full.txt
            kill $PID 2>/dev/null
            break
        fi
        if [ $((ITER % 15)) -eq 0 ]; then
            TOTAL_NOVEL=0
            for f in fuzz_*.log; do
                [ -f "$f" ] && TOTAL_NOVEL=$((TOTAL_NOVEL + $(awk 'NR>1{sum+=$4}END{print sum+0}' "$f")))
            done
            echo "[status] $((ITER*2))s elapsed, novel=$TOTAL_NOVEL, bugs=$BUGS"
        fi
        sleep 2
    done
) &

wait $PID 2>/dev/null || true
wait 2>/dev/null

echo ""
echo "=== Results ==="
ls -la fuzz_*.log trace_*.log 2>/dev/null
echo ""
echo "Kernel bugs:"
dmesg | grep -c "BUG:" 2>/dev/null || echo "0"
dmesg | grep "BUG:\|Call Trace:\|RIP:" 2>/dev/null | head -10
dmesg > VOCK_DIR_PLACEHOLDER/dmesg_full.txt
INNEREOF

# Patch placeholders
sed -i "s|VOCK_DIR_PLACEHOLDER|$VOCK_DIR|g" "$INNER"
sed -i "s|PROCS_PLACEHOLDER|$PROCS|g" "$INNER"
chmod +x "$INNER"

cd "$KERNEL_DIR"
vng --rw -- "$INNER"
rm -f "$INNER"
