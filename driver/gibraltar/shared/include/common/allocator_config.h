// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
//
// This file and all technical concepts, proprietary knowledge, algorithms and
// intellectual property rights it contains (collectively the "Confidential Information"),
// are the sole propriety information of Cisco and shall remain at Cisco's ownership.
// You shall not disclose the Confidential Information to any third party and you
// shall use it solely in connection with operating and/or maintaining of Cisco's
// products and pursuant to the terms and conditions of the license agreement you
// entered into with Cisco.
//
// THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
// IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// END_LEGAL

#ifndef __ALLOCATOR_CONFIG_H__
#define __ALLOCATOR_CONFIG_H__

#include <stddef.h>

namespace silicon_one
{

/// @brief Central allocator based on system malloc/free.
class malloc_allocator;

/// @brief cache_line implements memory caching mechanism per memory chunk size.
template <typename _BaseAllocator>
class cache_line;

/// @brief Allocator traits used to configure the allocator.
class allocator_traits
{
public:
    /// @brief Type of central allocator to be used by the allocator.
    using central_allocator = malloc_allocator;

    /// @brief Max object size for which we do memory caching.
    static constexpr size_t CACHE_LINE_MAX_OBJECT_SIZE = 1024;

    /// @brief Cache line object granularity expressed as logarithm.
    static constexpr size_t CACHE_LINE_LOG_OBJECT_GRANULARITY = 3;

    /// @brief Max number of chunks to keep in a cache line.
    ///
    /// When cache line has more than CACHE_LINE_MAX_SIZE chunks, it will
    /// start to give back the memory to the central allocator.
    static constexpr size_t CACHE_LINE_MAX_SIZE = 2000;

    /// @brief Min number of chunks to release per cache line.
    ///
    /// cache_line won't give back less than
    /// CACHE_LINE_MIN_CHUNKS_TO_RELEASE to the central allocator.
    static constexpr size_t CACHE_LINE_MIN_CHUNKS_TO_RELEASE = 100;
};

} // namespace silicon_one

#endif
