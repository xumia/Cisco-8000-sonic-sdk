// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "lpm_common.h"
#include "common/math_utils.h"
#include <stdio.h>

using namespace std;

namespace silicon_one
{

lpm_key_t
common_key(const lpm_key_t& key1, const lpm_key_t& key2)
{
    size_t w1 = key1.get_width();
    size_t w2 = key2.get_width();
    size_t min_width = min(w1, w2);

    lpm_key_t aligned_key1 = key1 >> (w1 - min_width);
    lpm_key_t aligned_key2 = key2 >> (w2 - min_width);
    lpm_key_t diff = aligned_key2 ^ aligned_key1;

    lpm_key_t key = aligned_key2 >> diff.get_minimal_width();

    return key;
}

lpm_bucket_index_t
comp_hw_index(lpm_bucket_index_t hw_index)
{
    return hw_index ^ 0x1;
}

bool
are_hw_indices_paired(lpm_bucket_index_t hw_index1, lpm_bucket_index_t hw_index2)
{
    return (hw_index1 ^ hw_index2) == 0x1;
}

bool
is_wide_key(const lpm_key_t& key)
{
    if (key.get_width() == 0) {
        return false;
    }

    // Long and short entries are distinguished by the MSB
    // If MSB is 0 - short; 1 - long
    return key.bit_from_msb(0);
}

lpm_key_t
encode_lpm_key(const lpm_key_t& key)
{
    bool is_ipv6 = key.bit_from_msb(0);
    if (is_ipv6) {
        return key;
    }

    constexpr size_t BROKEN_V4_BIT_NUMBER = 20;
    constexpr size_t V4_KEY_LEN = 45; /* v4/v6: 1'b, VRF: 11'b, IP[31:20]: 12'b, 0: 1'b, IP[19:0]: 20'b */
    constexpr size_t BITS_ABOVE_BROKEN_BIT = V4_KEY_LEN - (BROKEN_V4_BIT_NUMBER + 1); /* IP = {BITS_ABOVE_BROKEN_BIT, 0, xxxx} */

    const size_t width = key.get_width();

    if (width <= BITS_ABOVE_BROKEN_BIT) {
        return key;
    }

    lpm_key_t encoded_key(key);
    encoded_key = lpm_key_t(0, width + 1);
    encoded_key.set_bits_from_msb(0 /* offset */, BITS_ABOVE_BROKEN_BIT, key.bits_from_msb(0 /* offset */, BITS_ABOVE_BROKEN_BIT));
    encoded_key.set_bits_from_msb(BITS_ABOVE_BROKEN_BIT /* offset */, 1 /* width */, 0 /* value */);
    encoded_key.set_bits_from_msb(BITS_ABOVE_BROKEN_BIT + 1,
                                  width - BITS_ABOVE_BROKEN_BIT,
                                  key.bits_from_msb(BITS_ABOVE_BROKEN_BIT, width - BITS_ABOVE_BROKEN_BIT));
    return encoded_key;
}

lpm_key_t
decode_lpm_key(const lpm_key_t& key)
{
    bool is_ipv6 = key.bit_from_msb(0);
    if (is_ipv6) {
        return key;
    }

    constexpr size_t BROKEN_V4_BIT_NUMBER = 20;
    constexpr size_t V4_KEY_LEN = 45; /* v4/v6: 1'b, VRF: 11'b, IP[31:20]: 12'b, 0: 1'b, IP[19:0]: 20'b */
    constexpr size_t BITS_ABOVE_BROKEN_BIT = V4_KEY_LEN - (BROKEN_V4_BIT_NUMBER + 1); /* IP = {BITS_ABOVE_BROKEN_BIT, 0, xxxx} */

    const size_t width = key.get_width();

    if (width <= BITS_ABOVE_BROKEN_BIT) {
        return key;
    }

    lpm_key_t decoded_key(key);
    decoded_key = lpm_key_t(0, width - 1);
    decoded_key.set_bits_from_msb(0 /* offset */, BITS_ABOVE_BROKEN_BIT, key.bits_from_msb(0 /* offset */, BITS_ABOVE_BROKEN_BIT));
    decoded_key.set_bits_from_msb(BITS_ABOVE_BROKEN_BIT,
                                  width - BITS_ABOVE_BROKEN_BIT,
                                  key.bits_from_msb(BITS_ABOVE_BROKEN_BIT + 1, width - BITS_ABOVE_BROKEN_BIT));
    return decoded_key;
}

} // namespace silicon_one
