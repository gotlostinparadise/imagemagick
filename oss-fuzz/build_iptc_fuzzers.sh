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
    -I../Magick++/lib \
    -I../MagickCore \
    -I../MagickWand \
    -DMAGICKCORE_QUANTUM_DEPTH=16 \
    -DMAGICKCORE_HDRI_ENABLE=1 \
    iptc_profile_fuzzer.cc \
    -o iptc_profile_fuzzer \
    -L../MagickWand/.libs -L../MagickCore/.libs -L../Magick++/lib/.libs \
    -lMagickWand-7.Q16HDRI -lMagickCore-7.Q16HDRI -lMagick++-7.Q16HDRI -lz -lm -lpthread

# Advanced fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address,undefined \
    -I.. \
    -I../Magick++/lib \
    -I../MagickCore \
    -I../MagickWand \
    -DMAGICKCORE_QUANTUM_DEPTH=16 \
    -DMAGICKCORE_HDRI_ENABLE=1 \
    iptc_profile_advanced_fuzzer.cc \
    -o iptc_profile_advanced_fuzzer \
    -L../MagickWand/.libs -L../MagickCore/.libs -L../Magick++/lib/.libs \
    -lMagickWand-7.Q16HDRI -lMagickCore-7.Q16HDRI -lMagick++-7.Q16HDRI -lz -lm -lpthread

# Build the corpus generator
clang++ -g -O1 -DBUILD_MAIN \
    -I.. \
    -I../Magick++/lib \
    -I../MagickCore \
    -I../MagickWand \
    -DMAGICKCORE_QUANTUM_DEPTH=16 \
    -DMAGICKCORE_HDRI_ENABLE=1 \
    iptc_profile_advanced_fuzzer.cc \
    -o iptc_corpus_generator \
    -L../MagickWand/.libs -L../MagickCore/.libs -L../Magick++/lib/.libs \
    -lMagickWand-7.Q16HDRI -lMagickCore-7.Q16HDRI -lMagick++-7.Q16HDRI -lz -lm -lpthread

# Create wrapper scripts
echo "Creating wrapper scripts..."

# Wrapper for corpus generator
cat > run_corpus_generator.sh << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LD_LIBRARY_PATH="$SCRIPT_DIR/../MagickWand/.libs:$SCRIPT_DIR/../MagickCore/.libs:$SCRIPT_DIR/../Magick++/lib/.libs"
"$SCRIPT_DIR/iptc_corpus_generator" "$@"
EOF
chmod +x run_corpus_generator.sh

# Wrapper for basic fuzzer
cat > run_basic_fuzzer.sh << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LD_LIBRARY_PATH="$SCRIPT_DIR/../MagickWand/.libs:$SCRIPT_DIR/../MagickCore/.libs:$SCRIPT_DIR/../Magick++/lib/.libs"
"$SCRIPT_DIR/iptc_profile_fuzzer" "$@"
EOF
chmod +x run_basic_fuzzer.sh

# Wrapper for advanced fuzzer
cat > run_advanced_fuzzer.sh << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LD_LIBRARY_PATH="$SCRIPT_DIR/../MagickWand/.libs:$SCRIPT_DIR/../MagickCore/.libs:$SCRIPT_DIR/../Magick++/lib/.libs"
"$SCRIPT_DIR/iptc_profile_advanced_fuzzer" "$@"
EOF
chmod +x run_advanced_fuzzer.sh

echo "Generating initial corpus..."
./run_corpus_generator.sh "$CORPUS_DIR"

echo "Running basic IPTC profile fuzzer..."
./run_basic_fuzzer.sh -max_len=65536 -dict=dictionaries/iptc.dict "$CORPUS_DIR" "$FINDINGS_DIR" -jobs=4 -workers=4

echo "Running advanced IPTC profile fuzzer..."
./run_advanced_fuzzer.sh -max_len=65536 -dict=dictionaries/iptc.dict "$CORPUS_DIR" "$FINDINGS_DIR" -jobs=4 -workers=4

echo "Fuzzing complete. Check $FINDINGS_DIR for any crashes." 