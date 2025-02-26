#!/bin/bash
# Script to build and run the IPTC profile fuzzers

set -e

# Directory for corpus and findings
CORPUS_DIR="./iptc_corpus"
FINDINGS_DIR="./iptc_findings"

# Create directories if they don't exist
mkdir -p "$CORPUS_DIR"
mkdir -p "$FINDINGS_DIR"

# Build the fuzzers
echo "Building IPTC profile fuzzers..."

# Basic fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address,undefined \
    -I.. \
    -I../Magick++ \
    -I../MagickCore \
    -I../MagickWand \
    iptc_profile_fuzzer.cc \
    -o iptc_profile_fuzzer \
    -L../MagickWand/.libs -L../MagickCore/.libs -L../Magick++/.libs \
    -lMagickWand -lMagickCore -lMagick++-7.Q16HDRI -lz -lm -lpthread

# Advanced fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address,undefined \
    -I.. \
    -I../Magick++ \
    -I../MagickCore \
    -I../MagickWand \
    iptc_profile_advanced_fuzzer.cc \
    -o iptc_profile_advanced_fuzzer \
    -L../MagickWand/.libs -L../MagickCore/.libs -L../Magick++/.libs \
    -lMagickWand -lMagickCore -lMagick++-7.Q16HDRI -lz -lm -lpthread

# Build the corpus generator
clang++ -g -O1 -DBUILD_MAIN \
    -I.. \
    -I../Magick++ \
    -I../MagickCore \
    -I../MagickWand \
    iptc_profile_advanced_fuzzer.cc \
    -o iptc_corpus_generator \
    -L../MagickWand/.libs -L../MagickCore/.libs -L../Magick++/.libs \
    -lMagickWand -lMagickCore -lMagick++-7.Q16HDRI -lz -lm -lpthread

echo "Generating initial corpus..."
./iptc_corpus_generator "$CORPUS_DIR"

echo "Running basic IPTC profile fuzzer..."
./iptc_profile_fuzzer -max_len=65536 -dict=dictionaries/iptc.dict "$CORPUS_DIR" "$FINDINGS_DIR" -jobs=4 -workers=4

echo "Running advanced IPTC profile fuzzer..."
./iptc_profile_advanced_fuzzer -max_len=65536 -dict=dictionaries/iptc.dict "$CORPUS_DIR" "$FINDINGS_DIR" -jobs=4 -workers=4

echo "Fuzzing complete. Check $FINDINGS_DIR for any crashes." 