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

  Advanced fuzzer for IPTC profile parsing in ImageMagick.
  This fuzzer specifically targets the vulnerabilities identified in the
  IPTC profile parsing code, including:
  - Buffer overflows in CopyMagickString
  - Integer overflows in length calculations
  - Memory allocation issues
  - Malformed IPTC data structures
*/

#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>
#include <algorithm>
#include <random>

#include <Magick++/Blob.h>
#include <Magick++/Image.h>
#include <Magick++/Exception.h>

#include "utils.cc"

// Minimum size for a valid IPTC profile
#define MIN_IPTC_SIZE 8

// Maximum size for our generated IPTC profile
#define MAX_IPTC_SIZE 65536

// IPTC record sentinel value
#define IPTC_SENTINEL 0x1c

// Structure to hold IPTC record information
struct IPTCRecord {
    uint8_t dataset;
    uint8_t record;
    uint16_t length;
    std::vector<uint8_t> data;
};

// Function to create a malformed IPTC profile based on the input data
static std::vector<uint8_t> CreateMalformedIPTCProfile(const uint8_t *Data, size_t Size) {
    std::vector<uint8_t> iptcProfile;
    
    // Use the first few bytes to determine how many records to create
    size_t numRecords = (Size > 0) ? (Data[0] % 10) + 1 : 1;
    size_t dataOffset = 1;
    
    for (size_t i = 0; i < numRecords && dataOffset < Size; i++) {
        // Always start with the sentinel
        iptcProfile.push_back(IPTC_SENTINEL);
        
        // Dataset (use input data or default to 2)
        uint8_t dataset = (dataOffset < Size) ? Data[dataOffset++] : 2;
        iptcProfile.push_back(dataset);
        
        // Record (use input data or default to a valid record type)
        uint8_t record = (dataOffset < Size) ? Data[dataOffset++] : 5;
        iptcProfile.push_back(record);
        
        // Length calculation - this is where we can introduce malformations
        uint16_t length = 0;
        if (dataOffset + 1 < Size) {
            length = (static_cast<uint16_t>(Data[dataOffset]) << 8) | Data[dataOffset + 1];
            dataOffset += 2;
        } else if (dataOffset < Size) {
            length = Data[dataOffset++];
        }
        
        // Test case: Extremely large length to test integer overflow
        if (i == 0 && Size > 4) {
            // Use a large length value based on the input data
            if (Data[3] % 4 == 0) {
                length = 0xFFFF;  // Maximum 16-bit value
            } else if (Data[3] % 4 == 1) {
                length = 0xFFF0;  // Near maximum
            } else if (Data[3] % 4 == 2) {
                length = 0x7FFF;  // Half maximum
            }
        }
        
        // Add the length bytes (big endian)
        iptcProfile.push_back((length >> 8) & 0xFF);
        iptcProfile.push_back(length & 0xFF);
        
        // Add data bytes
        size_t actualLength = std::min(static_cast<size_t>(length), Size - dataOffset);
        for (size_t j = 0; j < actualLength && dataOffset < Size; j++) {
            iptcProfile.push_back(Data[dataOffset++]);
        }
        
        // If we don't have enough input data, pad with pattern
        if (actualLength < length) {
            for (size_t j = actualLength; j < length; j++) {
                iptcProfile.push_back('A' + (j % 26));
            }
        }
    }
    
    // Test case: Add malformed records without proper structure
    if (Size > 5 && Data[4] % 4 == 0) {
        // Add a sentinel without proper record structure
        iptcProfile.push_back(IPTC_SENTINEL);
        
        // Add some random bytes
        for (size_t i = 0; i < 10 && dataOffset < Size; i++) {
            iptcProfile.push_back(Data[dataOffset++]);
        }
    }
    
    // Test case: Add a record with length that exceeds the actual data
    if (Size > 6 && Data[5] % 4 == 1) {
        iptcProfile.push_back(IPTC_SENTINEL);
        iptcProfile.push_back(2);  // Dataset
        iptcProfile.push_back(5);  // Record
        
        // Length that exceeds the remaining data
        uint16_t excessLength = 1000;
        iptcProfile.push_back((excessLength >> 8) & 0xFF);
        iptcProfile.push_back(excessLength & 0xFF);
        
        // Add some data, but less than the specified length
        for (size_t i = 0; i < 20 && dataOffset < Size; i++) {
            iptcProfile.push_back(Data[dataOffset++]);
        }
    }
    
    // Test case: Add a record with zero length but with data
    if (Size > 7 && Data[6] % 4 == 2) {
        iptcProfile.push_back(IPTC_SENTINEL);
        iptcProfile.push_back(2);  // Dataset
        iptcProfile.push_back(5);  // Record
        
        // Zero length
        iptcProfile.push_back(0);
        iptcProfile.push_back(0);
        
        // Add data despite zero length
        for (size_t i = 0; i < 10 && dataOffset < Size; i++) {
            iptcProfile.push_back(Data[dataOffset++]);
        }
    }
    
    // Test case: Add multiple consecutive sentinels
    if (Size > 8 && Data[7] % 4 == 3) {
        for (int i = 0; i < 5; i++) {
            iptcProfile.push_back(IPTC_SENTINEL);
        }
        
        // Add some random bytes
        for (size_t i = 0; i < 10 && dataOffset < Size; i++) {
            iptcProfile.push_back(Data[dataOffset++]);
        }
    }
    
    return iptcProfile;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (IsInvalidSize(Size, MIN_IPTC_SIZE) || Size > MAX_IPTC_SIZE) {
        return 0;
    }

    try {
        // Create a minimal valid image
        Magick::Image image(Magick::Geometry(10, 10), Magick::Color("white"));
        
        // Create a malformed IPTC profile based on the input data
        std::vector<uint8_t> iptcProfile = CreateMalformedIPTCProfile(Data, Size);
        
        // Create a blob with the malformed IPTC data
        Magick::Blob iptcBlob(iptcProfile.data(), iptcProfile.size());
        
        // Set the IPTC profile with the malformed data
        image.profile("iptc", iptcBlob);
        
        // Test 1: Write the image to a blob and read it back
        try {
            Magick::Blob outputBlob;
            image.write(&outputBlob, "TIFF");
            
            Magick::Image newImage;
            newImage.read(outputBlob);
            
            // Get the IPTC profile to ensure it's processed
            Magick::Blob retrievedProfile = newImage.profile("iptc");
        } catch (Magick::Exception &e) {
            // Ignore exceptions during write/read operations
        }
        
        // Test 2: Use the identify functionality which processes IPTC profiles
        try {
            // Redirect stdout to avoid cluttering the output
            std::streambuf* oldCout = std::cout.rdbuf();
            std::cout.rdbuf(nullptr);
            
            // Call identify which will process the IPTC profile
            image.identify();
            
            // Restore stdout
            std::cout.rdbuf(oldCout);
        } catch (Magick::Exception &e) {
            // Ignore exceptions during identify
        }
        
        // Test 3: Clone the image to trigger profile copying
        try {
            Magick::Image clonedImage = image;
            
            // Modify the cloned image to ensure deep copy
            clonedImage.resize(Magick::Geometry(20, 20));
            
            // Get the IPTC profile from the cloned image
            Magick::Blob clonedProfile = clonedImage.profile("iptc");
        } catch (Magick::Exception &e) {
            // Ignore exceptions during cloning
        }
        
        // Test 4: Set multiple profiles to test memory management
        try {
            // Create a second profile
            Magick::Blob exifBlob(Data, Size);
            image.profile("exif", exifBlob);
            
            // Now remove the IPTC profile
            image.profile("iptc", Magick::Blob());
            
            // And add it back
            image.profile("iptc", iptcBlob);
        } catch (Magick::Exception &e) {
            // Ignore exceptions
        }
        
    } catch (Magick::Exception &e) {
        // Ignore any exceptions
    }
    
    return 0;
}

// Helper function to create specially crafted IPTC profiles for corpus generation
extern "C" void GenerateIPTCTestCases(const char* directory) {
    std::vector<std::vector<uint8_t>> testCases;
    
    // Test case 1: Basic valid IPTC profile
    {
        std::vector<uint8_t> iptcData;
        
        // Add a valid IPTC record
        iptcData.push_back(0x1c);  // Sentinel
        iptcData.push_back(0x02);  // Dataset
        iptcData.push_back(0x05);  // Record (Image Name)
        
        // Length (16-bit, big endian)
        const char* testString = "Test Image Name";
        size_t stringLen = strlen(testString);
        iptcData.push_back((stringLen >> 8) & 0xFF);
        iptcData.push_back(stringLen & 0xFF);
        
        // Copy the string data
        for (size_t i = 0; i < stringLen; i++) {
            iptcData.push_back(testString[i]);
        }
        
        testCases.push_back(iptcData);
    }
    
    // Test case 2: IPTC profile with maximum length field
    {
        std::vector<uint8_t> iptcData;
        
        iptcData.push_back(0x1c);  // Sentinel
        iptcData.push_back(0x02);  // Dataset
        iptcData.push_back(0x78);  // Record (Caption)
        
        // Set maximum length
        uint16_t maxLen = 0xFFFF;
        iptcData.push_back((maxLen >> 8) & 0xFF);
        iptcData.push_back(maxLen & 0xFF);
        
        // Add some data (not the full length)
        for (size_t i = 0; i < 1000; i++) {
            iptcData.push_back('A' + (i % 26));
        }
        
        testCases.push_back(iptcData);
    }
    
    // Test case 3: IPTC profile with multiple records
    {
        std::vector<uint8_t> iptcData;
        
        // Record 1
        iptcData.push_back(0x1c);
        iptcData.push_back(0x02);
        iptcData.push_back(0x05);  // Image Name
        
        const char* name = "Test Name";
        size_t nameLen = strlen(name);
        iptcData.push_back((nameLen >> 8) & 0xFF);
        iptcData.push_back(nameLen & 0xFF);
        
        for (size_t i = 0; i < nameLen; i++) {
            iptcData.push_back(name[i]);
        }
        
        // Record 2
        iptcData.push_back(0x1c);
        iptcData.push_back(0x02);
        iptcData.push_back(0x78);  // Caption
        
        const char* caption = "Test Caption";
        size_t captionLen = strlen(caption);
        iptcData.push_back((captionLen >> 8) & 0xFF);
        iptcData.push_back(captionLen & 0xFF);
        
        for (size_t i = 0; i < captionLen; i++) {
            iptcData.push_back(caption[i]);
        }
        
        testCases.push_back(iptcData);
    }
    
    // Test case 4: Malformed IPTC profile with missing data
    {
        std::vector<uint8_t> iptcData;
        
        iptcData.push_back(0x1c);
        iptcData.push_back(0x02);
        iptcData.push_back(0x05);
        
        // Length larger than actual data
        uint16_t declaredLen = 100;
        iptcData.push_back((declaredLen >> 8) & 0xFF);
        iptcData.push_back(declaredLen & 0xFF);
        
        // Only provide 10 bytes
        for (size_t i = 0; i < 10; i++) {
            iptcData.push_back('X');
        }
        
        testCases.push_back(iptcData);
    }
    
    // Test case 5: IPTC profile with invalid sentinel
    {
        std::vector<uint8_t> iptcData;
        
        iptcData.push_back(0x1d);  // Invalid sentinel
        iptcData.push_back(0x02);
        iptcData.push_back(0x05);
        
        uint16_t len = 10;
        iptcData.push_back((len >> 8) & 0xFF);
        iptcData.push_back(len & 0xFF);
        
        for (size_t i = 0; i < len; i++) {
            iptcData.push_back('Y');
        }
        
        testCases.push_back(iptcData);
    }
    
    // Test case 6: IPTC profile with zero length but data follows
    {
        std::vector<uint8_t> iptcData;
        
        iptcData.push_back(0x1c);
        iptcData.push_back(0x02);
        iptcData.push_back(0x05);
        
        // Zero length
        iptcData.push_back(0x00);
        iptcData.push_back(0x00);
        
        // Data that should be ignored
        for (size_t i = 0; i < 10; i++) {
            iptcData.push_back('Z');
        }
        
        testCases.push_back(iptcData);
    }
    
    // Test case 7: Multiple consecutive sentinels
    {
        std::vector<uint8_t> iptcData;
        
        for (int i = 0; i < 5; i++) {
            iptcData.push_back(0x1c);
        }
        
        // Add some data after the sentinels
        for (size_t i = 0; i < 10; i++) {
            iptcData.push_back('A' + i);
        }
        
        testCases.push_back(iptcData);
    }
    
    // Test case 8: Near SIZE_MAX length to test integer overflow
    {
        std::vector<uint8_t> iptcData;
        
        iptcData.push_back(0x1c);
        iptcData.push_back(0x02);
        iptcData.push_back(0x05);
        
        // Length close to SIZE_MAX
        iptcData.push_back(0xFF);
        iptcData.push_back(0xFF);
        
        // Add some data
        for (size_t i = 0; i < 20; i++) {
            iptcData.push_back('O');
        }
        
        testCases.push_back(iptcData);
    }
    
    // Write test cases to files
    for (size_t i = 0; i < testCases.size(); i++) {
        try {
            char filename[256];
            snprintf(filename, sizeof(filename), "%s/iptc_test_case_%zu.tiff", directory, i + 1);
            
            Magick::Image image(Magick::Geometry(10, 10), Magick::Color("white"));
            Magick::Blob iptcBlob(testCases[i].data(), testCases[i].size());
            image.profile("iptc", iptcBlob);
            image.write(filename);
            
            std::cout << "Generated test case: " << filename << std::endl;
        } catch (Magick::Exception &e) {
            std::cerr << "Error generating test case " << i + 1 << ": " << e.what() << std::endl;
        }
    }
}

#ifdef BUILD_MAIN
int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <output_directory>" << std::endl;
        return 1;
    }
    
    GenerateIPTCTestCases(argv[1]);
    return 0;
}
#endif 