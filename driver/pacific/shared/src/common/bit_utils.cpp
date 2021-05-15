// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "common/bit_utils.h"
#include <algorithm>
#include <stddef.h>

namespace silicon_one
{

namespace bit_utils
{

void
set_bits(uint64_t* target, size_t msb, size_t lsb, const uint64_t* val)
{
    size_t bytes_offset = lsb / BITS_IN_UINT64;
    target += bytes_offset;

    size_t bits_to_write = msb - lsb + 1, offset = lsb % BITS_IN_UINT64, val_offset = 0;

    while (bits_to_write > 0) {
        size_t iteration_bits_to_write = std::min({bits_to_write, BITS_IN_UINT64 - offset, BITS_IN_UINT64 - val_offset});
        uint64_t tmp = get_bits(*val, val_offset + iteration_bits_to_write - 1, val_offset);
        tmp = set_bits(*target, offset + iteration_bits_to_write - 1, offset, tmp);
        *target = tmp;
        bits_to_write -= iteration_bits_to_write;
        offset += iteration_bits_to_write;
        if (offset == BITS_IN_UINT64) {
            offset = 0;
            target++;
        }
        val_offset += iteration_bits_to_write;
        if (val_offset == BITS_IN_UINT64) {
            val_offset = 0;
            val++;
        }
    }
}

void
get_bits(const uint64_t* source, size_t msb, size_t lsb, uint64_t* out_val)
{
    size_t bytes_offset = lsb / BITS_IN_UINT64;
    source += bytes_offset;
    size_t out_val_offset = 0, bits_to_get = msb - lsb + 1, offset = lsb % BITS_IN_UINT64;

    while (bits_to_get > 0) {
        size_t iteration_bits_to_read = std::min({bits_to_get, BITS_IN_UINT64 - offset, BITS_IN_UINT64 - out_val_offset});
        uint64_t tmp = get_bits(*source, offset + iteration_bits_to_read - 1, offset);
        tmp = set_bits(*out_val, out_val_offset + iteration_bits_to_read - 1, out_val_offset, tmp);
        *out_val = tmp;
        bits_to_get -= iteration_bits_to_read;
        offset += iteration_bits_to_read;
        if (offset == BITS_IN_UINT64) {
            offset = 0;
            source++;
        }
        out_val_offset += iteration_bits_to_read;
        if (out_val_offset == BITS_IN_UINT64) {
            out_val_offset = 0;
            out_val++;
        }
    }
}

} // namespace bit_utils

} // namespace silicon_one
