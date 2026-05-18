#!/bin/bash
# fuzz.sh — Aggressive KASAN bug hunting via vock fuzz
#
# Usage:
#   ./fuzz.sh              # default: ~/net kernel
#   ./fuzz.sh ~/net        # custom kernel path
#
# NOTE: KASAN kernels take 60-90s to boot. Be patient.

KERNEL_DIR="${1:-$HOME/net}"
VOCK_DIR="$(cd "$(dirname "$0")" && pwd)"
PROCS=8

echo "=== vock fuzz — KASAN Bug Hunter ==="
echo "Kernel:  $KERNEL_DIR"
echo "Workers: $PROCS"
echo ""

if [ ! -f "$KERNEL_DIR/Makefile" ]; then
    echo "ERROR: $KERNEL_DIR is not a kernel tree"; exit 1
fi

# Build KASAN+KCOV+NET kernel if needed
cd "$KERNEL_DIR"
if ! grep -q "CONFIG_KASAN=y" .config 2>/dev/null || \
   ! grep -q "CONFIG_VETH=y" .config 2>/dev/null; then
    echo "[*] Building KASAN kernel with vng..."
    vng --configitem CONFIG_KASAN=y \
        --configitem CONFIG_KASAN_GENERIC=y \
        --configitem CONFIG_KCOV=y \
        --configitem CONFIG_KCOV_INSTRUMENT_ALL=y \
        --configitem CONFIG_NAMESPACES=y \
        --configitem CONFIG_USER_NS=y \
        --configitem CONFIG_NET_NS=y \
        --configitem CONFIG_PID_NS=y \
        --configitem CONFIG_VETH=y \
        --configitem CONFIG_DUMMY=y \
        --configitem CONFIG_BRIDGE=y \
        --configitem CONFIG_TUN=y \
        --configitem CONFIG_DEBUG_KERNEL=y \
        --configitem CONFIG_DEBUG_INFO=y \
        --configitem CONFIG_FRAME_WARN=4096 \
        --build LLVM=-21
    echo "[✓] Kernel built"
fi

echo "[✓] KASAN kernel ready"
echo "[*] Booting VM (KASAN kernels take ~60-90s to boot)..."
echo ""

# Write inner script
INNER=$(mktemp /tmp/vock_fuzz_XXXXXX.sh)
cat > "$INNER" << INNEREOF
#!/bin/bash
set -e
cd $VOCK_DIR
make CC=clang DEBUG_INFO_BTF=0 -s 2>/dev/null || make CC=gcc DEBUG_INFO_BTF=0 -s

echo ""
echo "=== Step 1: Verify mutations work (3 trial iterations) ==="
echo ""

# Run 3 iterations to verify mutations are happening
# --mode hw for kvm guest machine not working for critical bug
rm -f trace.syz fuzz_0.log trace_0.log
./vock fuzz -repeat=3 --mode kcov /usr/bin/unshare --user --map-root-user --net --pid --fork sh -c "ip link add veth0 type veth peer name veth1 && ip addr add 10.0.0.1/24 dev veth0 && ip link set veth0 up && ip link del veth0" 2>&1 | grep "\[fuzz\]"

# Verify baseline was captured
if [ ! -f trace.syz ]; then
    echo "FAIL: trace.syz not created. Baseline capture failed."
    exit 1
fi
BASELINE_HASH=\$(sha1sum trace.syz | cut -d' ' -f1)
BASELINE_LINES=\$(wc -l < trace.syz)
echo "[✓] Baseline: \$BASELINE_LINES syscalls (sha1: \$BASELINE_HASH)"

# Verify corpus was produced
if [ ! -f trace_0.log ]; then
    echo "FAIL: trace_0.log not created. No corpus produced."
    exit 1
fi
CORPUS_LINES=\$(wc -l < trace_0.log)
echo "[✓] Corpus: \$CORPUS_LINES lines"

# Verify mutations differ from baseline
CORPUS_HASH=\$(grep -v "^#" trace_0.log | sha1sum | cut -d' ' -f1)
if [ "\$BASELINE_HASH" = "\$CORPUS_HASH" ]; then
    echo "FAIL: Corpus is identical to baseline. Mutations not working!"
    echo "  baseline sha1: \$BASELINE_HASH"
    echo "  corpus sha1:   \$CORPUS_HASH"
    diff <(head -10 trace.syz) <(grep -v "^#" trace_0.log | head -10)
    exit 1
fi
echo "[✓] Mutations verified (corpus differs from baseline)"

# Verify fuzz.log has scores
if [ ! -f fuzz_0.log ]; then
    echo "FAIL: fuzz_0.log not created."
    exit 1
fi
NOVEL=\$(awk 'NR>1{sum+=\$4}END{print sum}' fuzz_0.log)
echo "[✓] Total novel PCs: \$NOVEL"
cat fuzz_0.log

echo ""
echo "=== Step 2: Full fuzzing ($PROCS workers, infinite) ==="
echo "=== Watching dmesg for KASAN/BUG ==="
echo ""

# Now run the real fuzzer
rm -f fuzz_*.log trace_*.log
./vock fuzz -procs=$PROCS --mode kcov /usr/bin/unshare --user --map-root-user --net --pid --fork sh -c "ip link add veth0 type veth peer name veth1 && ip addr add 10.0.0.1/24 dev veth0 && ip link set veth0 up && ip link del veth0" &
PID=\$!

# Monitor dmesg
(
    sleep 10
    ITER=0
    while kill -0 \$PID 2>/dev/null; do
        ITER=\$((ITER+1))
        BUGS=\$(dmesg 2>/dev/null | grep -c "BUG: KASAN" || true)
        if [ "\$BUGS" -gt 0 ]; then
            echo ""
            echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            echo "!!! KASAN BUG FOUND after ~\$((ITER*2))s !!!"
            echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            dmesg | grep -B2 -A20 "BUG: KASAN" | head -50
            dmesg > $VOCK_DIR/dmesg_full.txt
            kill \$PID 2>/dev/null
            break
        fi
        # Periodic status
        if [ \$((ITER % 15)) -eq 0 ]; then
            TOTAL_NOVEL=0
            for f in fuzz_*.log; do
                [ -f "\$f" ] && TOTAL_NOVEL=\$((TOTAL_NOVEL + \$(awk 'NR>1{sum+=\$4}END{print sum+0}' "\$f")))
            done
            echo "[status] \$((ITER*2))s elapsed, novel_total=\$TOTAL_NOVEL, bugs=\$BUGS"
        fi
        sleep 2
    done
) &

wait \$PID 2>/dev/null || true
wait 2>/dev/null

echo ""
echo "=== Results ==="
echo "Worker logs:"
ls -la fuzz_*.log trace_*.log 2>/dev/null
echo ""
echo "Kernel bugs:"
dmesg | grep -c "BUG:" 2>/dev/null || echo "0"
dmesg | grep "BUG:\|Call Trace:\|RIP:" 2>/dev/null | head -10
dmesg > $VOCK_DIR/dmesg_full.txt
INNEREOF
chmod +x "$INNER"

cd "$KERNEL_DIR"
vng --rw -- "$INNER"
rm -f "$INNER"
