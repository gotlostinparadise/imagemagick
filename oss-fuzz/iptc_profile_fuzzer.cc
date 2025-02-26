/*
  Copyright @ 2023 ImageMagick Studio LLC, a non-profit organization
  dedicated to making software imaging solutions freely available.

  You may not use this file except in compliance with the License.  You may
  obtain a copy of the License at

    https://imagemagick.org/script/license.php

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Fuzzer for IPTC profile parsing in ImageMagick.
*/

#include <cstdint>
#include <cstring>
#include <iostream>

#include <Magick++/Blob.h>
#include <Magick++/Image.h>
#include <Magick++/Exception.h>

#include "utils.cc"

// Minimum size for a valid IPTC profile
#define MIN_IPTC_SIZE 8

// Maximum size for our generated IPTC profile
#define MAX_IPTC_SIZE 65536

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (IsInvalidSize(Size, MIN_IPTC_SIZE) || Size > MAX_IPTC_SIZE) {
    return 0;
  }

  try {
    // Create a minimal valid image
    Magick::Image image(Magick::Geometry(10, 10), Magick::Color("white"));
    
    // Create a blob with the fuzzed data
    Magick::Blob iptcBlob(Data, Size);
    
    // Set the IPTC profile with the fuzzed data
    image.profile("iptc", iptcBlob);
    
    // Now try to access the profile to trigger the parsing code
    try {
      Magick::Blob outputBlob;
      image.write(&outputBlob, "TIFF");
      
      // Create a new image from the output and read its IPTC profile
      Magick::Image newImage;
      newImage.read(outputBlob);
      
      // Get the IPTC profile to ensure it's processed
      Magick::Blob iptcProfile = newImage.profile("iptc");
    } catch (Magick::Exception &e) {
      // Ignore exceptions during write/read operations
    }
    
    // Test the identify functionality which processes IPTC profiles
    try {
      // Redirect stdout to avoid cluttering the output
      std::streambuf* oldCout = std::cout.rdbuf();
      std::cout.rdbuf(nullptr);
      
      // Instead of using identify(), which might not be available,
      // we'll use other methods that will process the IPTC profile
      std::string attributes = image.attribute("IPTC:*");
      
      // Get image properties which will process profiles
      image.fileName();
      image.format();
      image.size();
      
      // Restore stdout
      std::cout.rdbuf(oldCout);
    } catch (Magick::Exception &e) {
      // Ignore exceptions during identify
    }
  } catch (Magick::Exception &e) {
    // Ignore any exceptions
  }
  
  return 0;
}

// Helper function to create specially crafted IPTC profiles for corpus generation
extern "C" void GenerateIPTCTestCase(const char* filename) {
  // Basic IPTC profile structure:
  // 0x1c (sentinel) + dataset + record + length (2 bytes) + data
  
  uint8_t iptcData[1024];
  size_t offset = 0;
  
  // Add a valid IPTC record
  iptcData[offset++] = 0x1c;  // Sentinel
  iptcData[offset++] = 0x02;  // Dataset
  iptcData[offset++] = 0x05;  // Record (Image Name)
  
  // Length (16-bit, big endian)
  const char* testString = "Test Image Name";
  size_t stringLen = strlen(testString);
  iptcData[offset++] = (stringLen >> 8) & 0xFF;
  iptcData[offset++] = stringLen & 0xFF;
  
  // Copy the string data
  memcpy(iptcData + offset, testString, stringLen);
  offset += stringLen;
  
  // Add another record with maximum allowed length
  iptcData[offset++] = 0x1c;  // Sentinel
  iptcData[offset++] = 0x02;  // Dataset
  iptcData[offset++] = 0x78;  // Record (Caption)
  
  // Set a large length to test boundary conditions
  size_t largeLen = 256;
  iptcData[offset++] = (largeLen >> 8) & 0xFF;
  iptcData[offset++] = largeLen & 0xFF;
  
  // Fill with pattern data
  for (size_t i = 0; i < largeLen; i++) {
    iptcData[offset++] = 'A' + (i % 26);
  }
  
  // Create an image and set the IPTC profile
  try {
    Magick::Image image(Magick::Geometry(10, 10), Magick::Color("white"));
    Magick::Blob iptcBlob(iptcData, offset);
    image.profile("iptc", iptcBlob);
    image.write(filename);
  } catch (Magick::Exception &e) {
    std::cerr << "Error generating test case: " << e.what() << std::endl;
  }
}

#ifdef BUILD_MAIN
int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <output_file>" << std::endl;
    return 1;
  }
  
  GenerateIPTCTestCase(argv[1]);
  return 0;
}
#endif 