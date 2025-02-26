#!/bin/bash
# Script to build and run the IPTC profile fuzzers

set -e

# Directory for corpus and findings
CORPUS_DIR="./iptc_corpus"
FINDINGS_DIR="./iptc_findings"

# Create directories if they don't exist
mkdir -p "$CORPUS_DIR"
mkdir -p "$FINDINGS_DIR"

# Get ImageMagick include paths
MAGICK_INCLUDE_PATH=$(pkg-config --cflags-only-I MagickWand || echo "-I/usr/local/include/ImageMagick -I/usr/include/ImageMagick")
MAGICK_LIB_PATH=$(pkg-config --libs-only-L MagickWand || echo "-L/usr/local/lib -L/usr/lib")
MAGICK_LIBS=$(pkg-config --libs MagickWand || echo "-lMagickWand-7.Q16HDRI -lMagickCore-7.Q16HDRI")

# If pkg-config fails, try to find the headers manually
if [[ "$MAGICK_INCLUDE_PATH" != *"-I"* ]]; then
    echo "pkg-config failed to find ImageMagick headers, trying common locations..."
    
    # Check common locations for ImageMagick headers
    for dir in \
        "/usr/include/ImageMagick" \
        "/usr/local/include/ImageMagick" \
        "/opt/homebrew/include/ImageMagick" \
        "/usr/include/ImageMagick-7" \
        "/usr/local/include/ImageMagick-7" \
        "/opt/homebrew/include/ImageMagick-7" \
        "../" \
        "../../" \
        "../../../"
    do
        if [ -d "$dir" ]; then
            MAGICK_INCLUDE_PATH="-I$dir"
            echo "Found ImageMagick headers at $dir"
            break
        fi
    done
fi

echo "Using ImageMagick include path: $MAGICK_INCLUDE_PATH"
echo "Using ImageMagick lib path: $MAGICK_LIB_PATH"
echo "Using ImageMagick libs: $MAGICK_LIBS"

# Build the fuzzers
echo "Building IPTC profile fuzzers..."

# Basic fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address,undefined $MAGICK_INCLUDE_PATH \
    iptc_profile_fuzzer.cc \
    -o iptc_profile_fuzzer \
    $MAGICK_LIB_PATH $MAGICK_LIBS -lz -lm -lpthread

# Advanced fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address,undefined $MAGICK_INCLUDE_PATH \
    iptc_profile_advanced_fuzzer.cc \
    -o iptc_profile_advanced_fuzzer \
    $MAGICK_LIB_PATH $MAGICK_LIBS -lz -lm -lpthread

# Build the corpus generator
clang++ -g -O1 -DBUILD_MAIN $MAGICK_INCLUDE_PATH \
    iptc_profile_advanced_fuzzer.cc \
    -o iptc_corpus_generator \
    $MAGICK_LIB_PATH $MAGICK_LIBS -lz -lm -lpthread

echo "Generating initial corpus..."
./iptc_corpus_generator "$CORPUS_DIR"

echo "Running basic IPTC profile fuzzer..."
./iptc_profile_fuzzer -max_len=65536 -dict=dictionaries/iptc.dict "$CORPUS_DIR" "$FINDINGS_DIR" -jobs=4 -workers=4

echo "Running advanced IPTC profile fuzzer..."
./iptc_profile_advanced_fuzzer -max_len=65536 -dict=dictionaries/iptc.dict "$CORPUS_DIR" "$FINDINGS_DIR" -jobs=4 -workers=4

echo "Fuzzing complete. Check $FINDINGS_DIR for any crashes." 