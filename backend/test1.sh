#!/bin/bash
# Static Control Flow Analysis for SIMH Tape Binaries
# Focus on executable code that references crypto constants

set -e

BINARY="${1:-}"
ARCH="${2:-arm64}"

if [ -z "$BINARY" ] || [ ! -f "$BINARY" ]; then
    echo "Usage: $0 <binary> [architecture]"
    echo "Example: $0 P_2_S_5.bin arm64"
    exit 1
fi

# Step 1: Find executable segments
echo "[1] Analyzing binary structure..."
echo

FILE_TYPE=$(file "$BINARY")
FILE_SIZE=$(stat -f%z "$BINARY" 2>/dev/null || stat -c%s "$BINARY" 2>/dev/null)
echo "  Type: $FILE_TYPE"
echo "  Size: $FILE_SIZE bytes"
echo

# Find crypto patterns
echo "[2] Locating crypto constants..."
echo
CRYPTO_PATTERNS=$(binwalk "$BINARY" 2>/dev/null | grep -iE "sha256|aes.*s-box" | grep -v "Checksum" || true)

declare -A CRYPTO_MAP
if [ -n "$CRYPTO_PATTERNS" ]; then
    while IFS= read -r line; do
        offset=$(echo "$line" | awk '{print $2}' | sed 's/0x//')
        type=$(echo "$line" | grep -oiE "sha256|aes" | head -1 | tr '[:lower:]' '[:upper:]')
        if [ -n "$offset" ] && [ -n "$type" ]; then
            CRYPTO_MAP[$offset]=$type
            echo "  ✓ $type at 0x$offset"
        fi
    done <<<"$CRYPTO_PATTERNS"
else
    echo "  ⚠ No crypto patterns found"
fi
echo

# Step 3: Full function analysis with radare2
echo "[3] Analyzing all functions..."
echo

R2_CMD="r2 -q -a arm -b 64"

# Get complete function list with addresses
echo "  Running deep analysis (this may take a moment)..."
FUNC_ANALYSIS=$($R2_CMD -c "aaa; afll" "$BINARY" 2>/dev/null)

# Count functions
FUNC_COUNT=$(echo "$FUNC_ANALYSIS" | grep -c "^0x" || echo "0")
echo "  Found: $FUNC_COUNT functions"
echo

if [ "$FUNC_COUNT" -eq 0 ]; then
    echo "  ⚠ No functions detected via standard analysis"
    echo "  Attempting aggressive analysis..."
    echo

    # Try aggressive analysis
    FUNC_ANALYSIS=$($R2_CMD -c "e anal.hasnext=true; aaa; aac; afr; afl" "$BINARY" 2>/dev/null)
    FUNC_COUNT=$(echo "$FUNC_ANALYSIS" | wc -l)
    echo "  Found: $FUNC_COUNT functions (aggressive mode)"
    echo
fi

# Step 4: Analyze functions that reference crypto data
if [ ${#CRYPTO_MAP[@]} -gt 0 ]; then
    echo "[4] Finding functions that access crypto constants..."
    echo

    for crypto_offset in "${!CRYPTO_MAP[@]}"; do
        crypto_type="${CRYPTO_MAP[$crypto_offset]}"

        # Find cross-references
        XREFS=$($R2_CMD -c "aaa; axt 0x$crypto_offset" "$BINARY" 2>/dev/null || true)

        if [ -n "$XREFS" ]; then
            echo "  [+] Found cross-references:"
            echo "$XREFS" | head -20 | sed 's/^/      /'
            echo

            # Extract function addresses from xrefs
            FUNC_ADDRS=$(echo "$XREFS" | grep -oE "0x[0-9a-f]+" | head -1)

            for func_addr in $FUNC_ADDRS; do
                echo "  ┌─ Function at $func_addr"
                echo "  │"

                # Get function info
                FUNC_INFO=$($R2_CMD -c "aaa; afi @ $func_addr" "$BINARY" 2>/dev/null || true)

                if [ -n "$FUNC_INFO" ]; then
                    echo "$FUNC_INFO" | grep -E "name|size|type|cc" | sed 's/^/  │  /'
                    echo "  │"

                    # Get control flow graph info
                    echo "  ├─ Control Flow:"
                    CFG=$($R2_CMD -c "aaa; afb @ $func_addr" "$BINARY" 2>/dev/null | head -10)
                    echo "$CFG" | sed 's/^/  │    /'
                    echo "  │"

                    # Show disassembly with focus on crypto access
                    echo "  ├─ Disassembly (first 40 instructions):"
                    DISASM=$($R2_CMD -c "aaa; s $func_addr; pd 40" "$BINARY" 2>/dev/null)
                    echo "$DISASM" | grep -A 2 -B 2 "0x$crypto_offset\|adrp\|ldr.*x[0-9]\|bl\|ret" | head -50 | sed 's/^/  │    /'
                    echo "  │"

                    # Save full disassembly
                    OUTFILE="control_flow_${func_addr#0x}_${crypto_type}.txt"
                    {
                        echo "Function: $func_addr accessing $crypto_type at 0x$crypto_offset"
                        echo "═══════════════════════════════════════════════════════"
                        echo
                        echo "FUNCTION INFO:"
                        echo "$FUNC_INFO"
                        echo
                        echo "CONTROL FLOW BLOCKS:"
                        $R2_CMD -c "aaa; afb @ $func_addr" "$BINARY" 2>/dev/null
                        echo
                        echo "FULL DISASSEMBLY:"
                        $R2_CMD -c "aaa; s $func_addr; pdf" "$BINARY" 2>/dev/null
                        echo
                        echo "CALL GRAPH:"
                        $R2_CMD -c "aaa; agc @ $func_addr" "$BINARY" 2>/dev/null || echo "N/A"
                    } >"$OUTFILE"
                    echo "  └─ 💾 Full analysis saved: $OUTFILE"
                    echo
                fi
            done
        else
            echo "  [-] No direct cross-references found"
            echo "  [*] Searching for potential callers in nearby functions..."
            echo

            # Calculate search range
            offset_dec=$((16#$crypto_offset))
            start_offset=$((offset_dec - 32768))
            end_offset=$((offset_dec + 8192))
            [ $start_offset -lt 0 ] && start_offset=0

            # Find functions in range
            NEARBY_FUNCS=$(echo "$FUNC_ANALYSIS" | awk -v start=$(printf "0x%x" $start_offset) -v end=$(printf "0x%x" $end_offset) '
                $1 >= start && $1 <= end {print $1, $3, $4}
            ' | head -10)

            if [ -n "$NEARBY_FUNCS" ]; then
                echo "  [+] Functions near crypto data:"
                echo "$NEARBY_FUNCS" | while read addr size name; do
                    distance=$((offset_dec - 16#${addr#0x}))
                    printf "      • %s %-20s [%6d bytes] (%+d from crypto)\n" "$addr" "$name" "$size" "$distance"
                done
                echo

                # Analyze each nearby function
                echo "$NEARBY_FUNCS" | head -3 | while read addr size name; do
                    echo "  ┌─ Analyzing $addr ($name)"
                    echo "  │"

                    # Check for page references (ARM64 ADRP pattern)
                    PAGE_ADDR=$((16#$crypto_offset & ~0xFFF))
                    PAGE_HEX=$(printf "%x" $PAGE_ADDR)

                    DISASM=$($R2_CMD -c "aaa; s $addr; pd $((size / 4))" "$BINARY" 2>/dev/null)

                    # Look for ADRP loading crypto page
                    ADRP_HITS=$(echo "$DISASM" | grep -i "adrp.*0x$PAGE_HEX" | head -5)

                    if [ -n "$ADRP_HITS" ]; then
                        echo "  │  ✓ LIKELY ACCESSES CRYPTO DATA (ADRP to page 0x$PAGE_HEX)"
                        echo "  │"
                        echo "$ADRP_HITS" | sed 's/^/  │    /'
                        echo "  │"

                        # Show surrounding context
                        echo "  │  Context (with branches/calls):"
                        echo "$DISASM" | grep -E "adrp|add.*0x|ldr|bl|b\.|ret" | head -20 | sed 's/^/  │    /'
                    else
                        echo "  │  No obvious crypto access pattern"
                    fi
                    echo "  └─"
                    echo
                done
            else
                echo "  [-] No functions found near crypto data"
            fi
        fi
        echo
    done
fi

# Step 5: Analyze largest functions (likely crypto implementations)
echo "[5] Largest functions (potential crypto/hash implementations)..."
echo

echo "$FUNC_ANALYSIS" | grep "^0x" | sort -t' ' -k3 -rn | head -15 | while read addr blocks size name rest; do
    # Skip tiny functions
    [ "$size" -lt 500 ] && continue

    printf "  %-12s %-25s %8d bytes\n" "$addr" "$name" "$size"

    # Quick check: does this function call interesting crypto-related symbols?
    CALLS=$($R2_CMD -c "aaa; s $addr; pdf~call" "$BINARY" 2>/dev/null | head -10)
    if echo "$CALLS" | grep -qiE "sha|aes|crypt|hash|hmac|cipher"; then
        echo "    → Contains crypto-related calls:"
        echo "$CALLS" | grep -iE "sha|aes|crypt|hash|hmac|cipher" | sed 's/^/      /' | head -3
    fi
done
echo

# Step 6: Generate control flow graphs for top candidates
echo "[6] Generating control flow visualizations..."
echo

TOP_FUNCS=$(echo "$FUNC_ANALYSIS" | grep "^0x" | sort -t' ' -k3 -rn | head -5 | awk '{print $1}')

for func in $TOP_FUNCS; do
    outfile="cfg_${func#0x}.dot"
    echo "  • $func → $outfile"

    $R2_CMD -c "aaa; s $func; agfd" "$BINARY" 2>/dev/null >"$outfile" || true

    # If dot is available, render to PNG
    if command -v dot &>/dev/null; then
        dot -Tpng "$outfile" -o "cfg_${func#0x}.png" 2>/dev/null &&
            echo "    ✓ PNG: cfg_${func#0x}.png"
    fi
done
echo

# Step 7: Create summary report
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  SUMMARY & MANUAL ANALYSIS GUIDE"
echo "╚════════════════════════════════════════════════════════════╝"
echo

if [ ${#CRYPTO_MAP[@]} -gt 0 ]; then
    echo "✓ Crypto Constants Found:"
    for offset in "${!CRYPTO_MAP[@]}"; do
        echo "  • ${CRYPTO_MAP[$offset]} at 0x$offset"
    done
    echo
fi

echo "✓ Generated Files:"
ls -1 control_flow_*.txt cfg_*.dot cfg_*.png 2>/dev/null | sed 's/^/  • /' || echo "  (none)"
echo
# Step 8: Try to identify crypto function patterns
echo "[7] Pattern-based crypto function detection..."
echo

echo "  Searching for common crypto patterns in code..."
# Look for functions that have multiple rounds/loops (crypto algorithms)
$R2_CMD -c "
    aaa
    /c and w15, w15, 0xf
    /c cmp w15, 0x3f
    /c eor v
" "$BINARY" 2>/dev/null | head -20 | sed 's/^/    /' || echo "    (no patterns found)"
