/*
  Copyright @ 2018 ImageMagick Studio LLC, a non-profit organization
  dedicated to making software imaging solutions freely available.

  You may not use this file except in compliance with the License.  You may
  obtain a copy of the License at

    https://imagemagick.org/script/license.php

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include <Magick++/Functions.h>
#include <Magick++/ResourceLimits.h>
// SecurityPolicy is only available in ImageMagick 7
#include <Magick++/SecurityPolicy.h>

#ifndef FUZZ_MAX_SIZE
#define FUZZ_MAX_SIZE 2048
#endif

static bool IsInvalidSize(const size_t size,const size_t min = 1)
{
  if (size < min)
    return(true);
  if (size > 8192)
    return(true);
  return(false);
}

class FuzzingInitializer
{
public:
  FuzzingInitializer()
  {
    // Disable SIMD in jpeg turbo.
    (void) putenv(const_cast<char *>("JSIMD_FORCENONE=1"));

    Magick::InitializeMagick((const char *) NULL);
    
    // SecurityPolicy methods are only available in ImageMagick 7
    Magick::SecurityPolicy::anonymousCacheMemoryMap();
    Magick::SecurityPolicy::anonymousSystemMemoryMap();
    Magick::SecurityPolicy::maxMemoryRequest(128000000);
    
    Magick::ResourceLimits::memory(1000000000);
    Magick::ResourceLimits::map(500000000);
    Magick::ResourceLimits::width(FUZZ_MAX_SIZE);
    Magick::ResourceLimits::height(FUZZ_MAX_SIZE);
    Magick::ResourceLimits::listLength(16);
  }
};

FuzzingInitializer fuzzingInitializer;

#if defined(BUILD_MAIN)
#include "encoder_format.h"

EncoderFormat encoderFormat;

#define FUZZ_ENCODER encoderFormat.get()
#endif
