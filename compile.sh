#!/bin/bash
set -e

PROJECT_ROOT="$(pwd)"

# Loop through 12 pair files
CODE_DIR="corpus/pairs"
SOURCES=()
for pair in {01..12}; do
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
        echo "Warning: Source file '$source' not found, skipping."
        continue
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
            gcc-15 \
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
              "-DVARIANT_FIXED=$variant" \
              "-$opt" \
              "$source" \
              -no-pie \
              -Wl,-z,noexecstack \
              -o "$oracle_path"

            # 2. Derive Retained artifact from Oracle
            cp -- "$oracle_path" "$retained_path"
            objcopy --strip-debug "$retained_path"

            # 3. Derive Stripped artifact from Oracle
            cp -- "$oracle_path" "$stripped_path"
            strip --strip-all "$stripped_path"

        done
    done
done

echo "Done! All artifacts successfully generated and verified."
