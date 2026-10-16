#!/bin/bash
set -euo pipefail

# Single-master mode is used by pipeline/build.py
compile_master() {
    local source="$1" variant="$2" opt="$3" oracle="$4" compiler="$5"
    shift 5
    local common_flags=()
    case "$source" in
        corpus/pairs/p0[1-9].c|corpus/pairs/p1[0-2].c) ;;
        *) echo "Compilation requires a corpus source p01.c through p12.c" >&2; return 1 ;;
    esac
    [[ "$variant" == 0 || "$variant" == 1 ]] || return 1
    [[ "$opt" == O0 || "$opt" == O2 ]] || return 1
    while [[ $# -gt 0 && "$1" != -- ]]; do
        common_flags+=("$1")
        shift
    done
    [[ $# -gt 0 ]] || return 1
    shift
    "$compiler" "${common_flags[@]}" "-DVARIANT_FIXED=$variant" "-$opt" \
        "$source" "$@" -o "$oracle"
}

if [[ "${1:-}" == --master ]]; then
    shift
    [[ $# -ge 6 ]] || { echo "Missing --master arguments" >&2; exit 1; }
    compile_master "$@"
    exit
fi
[[ $# == 0 ]] || { echo "Unknown build arguments" >&2; exit 1; }

PROJECT_ROOT="$(pwd)"

# The standalone default builds the pilot; pipeline/build.py selects either split.
CODE_DIR="corpus/pairs"
SOURCES=()
for pair in {01,08}; do
    SOURCES+=("$CODE_DIR/p$pair.c")
done

# Directories
ORACLE_DIR="build/oracle"
RETAINED_DIR="build/retained"
STRIPPED_DIR="build/stripped"

for dir in "$ORACLE_DIR" "$RETAINED_DIR" "$STRIPPED_DIR"; do
    mkdir -p "$dir"
done

for source in "${SOURCES[@]}"; do
    if [ ! -f "$source" ]; then
        echo "Source file '$source' not found" >&2
        exit 1
    fi

    basename_src=$(basename "$source" .c)

    for variant in 0 1; do
        for opt in "O0" "O2"; do
            filename="${basename_src}_v${variant}_${opt}"

            oracle_path="$ORACLE_DIR/$filename"
            retained_path="$RETAINED_DIR/$filename"
            stripped_path="$STRIPPED_DIR/$filename"

            echo "Building Oracle: $filename (VARIANT_FIXED=$variant, -$opt)"

            # 1. Compile Oracle with exact validated flags
            compile_master "$source" "$variant" "$opt" "$oracle_path" gcc-15 \
              -std=c11 \
              -Wall \
              -Wextra \
              -g \
              -gdwarf-5 \
              -fno-stack-protector \
              -U_FORTIFY_SOURCE \
              -D_FORTIFY_SOURCE=0 \
              -fcf-protection=none \
              -fno-pie \
              "-fdebug-prefix-map=$PROJECT_ROOT=/experiment" \
              "-ffile-prefix-map=$PROJECT_ROOT=/experiment" \
              -- \
              -no-pie \
              -Wl,-z,noexecstack

            # 2. Derive Retained artifact from Oracle
            cp -- "$oracle_path" "$retained_path"
            objcopy --strip-debug "$retained_path"

            # 3. Derive Stripped artifact from Oracle
            cp -- "$retained_path" "$stripped_path"
            strip --strip-all "$stripped_path"

        done
    done
done

echo "Done! Artifacts generated. Use pipeline/build.py to verify invariants."
