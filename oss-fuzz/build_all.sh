#!/bin/bash
# Script to build IPTC profile fuzzers using system-installed ImageMagick

set -e

# Check if ImageMagick libraries are installed
if [ ! -f "/usr/local/lib/libMagickWand-7.Q16HDRI.so.10" ] || \
   [ ! -f "/usr/local/lib/libMagickCore-7.Q16HDRI.so.10" ] || \
   [ ! -f "/usr/local/lib/libMagick++-7.Q16HDRI.so.10" ]; then
    echo "Error: ImageMagick libraries not found in /usr/local/lib."
    echo "Please ensure ImageMagick is properly installed."
    exit 1
fi

# Directory for corpus and findings
CORPUS_DIR="./iptc_corpus"
FINDINGS_DIR="./iptc_findings"

# Create directories if they don't exist
mkdir -p "$CORPUS_DIR"
mkdir -p "$FINDINGS_DIR"

# Create dictionaries directory if it doesn't exist
mkdir -p dictionaries

# Build the fuzzers
echo "Building IPTC profile fuzzers..."

# Create a simple encoder_format.h if it doesn't exist
if [ ! -f "encoder_format.h" ]; then
    echo "Creating encoder_format.h..."
    cat > encoder_format.h << 'EOF'
/*
  Simple encoder format class for fuzzing
*/
#ifndef ENCODER_FORMAT_H
#define ENCODER_FORMAT_H

#include <string>

class EncoderFormat {
public:
    EncoderFormat() : format_("") {}
    void set(const std::string& format) { format_ = format; }
    std::string get() const { return format_; }
private:
    std::string format_;
};

#endif // ENCODER_FORMAT_H
EOF
fi

# Basic fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address,undefined \
    -I/usr/local/include/ImageMagick-7 \
    iptc_profile_fuzzer.cc \
    -o iptc_profile_fuzzer \
    -L/usr/local/lib \
    -lMagickWand-7.Q16HDRI -lMagickCore-7.Q16HDRI -lMagick++-7.Q16HDRI -lz -lm -lpthread

# Advanced fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address,undefined \
    -I/usr/local/include/ImageMagick-7 \
    iptc_profile_advanced_fuzzer.cc \
    -o iptc_profile_advanced_fuzzer \
    -L/usr/local/lib \
    -lMagickWand-7.Q16HDRI -lMagickCore-7.Q16HDRI -lMagick++-7.Q16HDRI -lz -lm -lpthread

# Build the corpus generator
clang++ -g -O1 -DBUILD_MAIN \
    -I/usr/local/include/ImageMagick-7 \
    iptc_profile_advanced_fuzzer.cc \
    -o iptc_corpus_generator \
    -L/usr/local/lib \
    -lMagickWand-7.Q16HDRI -lMagickCore-7.Q16HDRI -lMagick++-7.Q16HDRI -lz -lm -lpthread

# Create wrapper scripts
echo "Creating wrapper scripts..."

# Wrapper for corpus generator
cat > run_corpus_generator.sh << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"
"$SCRIPT_DIR/iptc_corpus_generator" "$@"
EOF
chmod +x run_corpus_generator.sh

# Wrapper for basic fuzzer
cat > run_basic_fuzzer.sh << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"
"$SCRIPT_DIR/iptc_profile_fuzzer" "$@"
EOF
chmod +x run_basic_fuzzer.sh

# Wrapper for advanced fuzzer
cat > run_advanced_fuzzer.sh << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"
"$SCRIPT_DIR/iptc_profile_advanced_fuzzer" "$@"
EOF
chmod +x run_advanced_fuzzer.sh

echo "Generating initial corpus..."
./run_corpus_generator.sh "$CORPUS_DIR"

echo "Running basic IPTC profile fuzzer..."
./run_basic_fuzzer.sh -max_len=65536 "$CORPUS_DIR" "$FINDINGS_DIR" -jobs=4 -workers=4

echo "Running advanced IPTC profile fuzzer..."
./run_advanced_fuzzer.sh -max_len=65536 "$CORPUS_DIR" "$FINDINGS_DIR" -jobs=4 -workers=4

echo "Fuzzing complete. Check $FINDINGS_DIR for any crashes." 