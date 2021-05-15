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

#include "hw_tables/em_common.h"
#include "common/logger.h"
#include "crc_divisors.h"

#include <cmath>

namespace silicon_one
{

namespace em
{

bit_vector
generate_pseudo_rc5(size_t key_width, size_t bank_idx)
{
    static const uint8_t BASE = 251;
    static const uint8_t VAL = 89;
    static const size_t MAX_KEY_WIDTH_IN_BYTES = 256;
    uint8_t buff[MAX_KEY_WIDTH_IN_BYTES];

    size_t rc5_width = key_width * 2;
    size_t rc5_width_in_bytes = (size_t)(ceil(((double)rc5_width) / 8));

    dassert_crit(MAX_KEY_WIDTH_IN_BYTES > rc5_width_in_bytes);

    for (size_t i = 0; i < rc5_width_in_bytes; ++i) {
        size_t byte_val = ((i + 5) * (bank_idx + 7) * VAL) % BASE;
        buff[i] = (uint8_t)byte_val;
    }

    // bit_vector resizes itself according to MSB. Therefore, we create one temprary and then copy only relevant bits
    bit_vector tmp(rc5_width_in_bytes, buff, rc5_width);
    return tmp.bits(rc5_width - 1, 0);
}

void
generate_default_hasher_params(size_t key_width, size_t bank_idx, hasher_params& out_params)
{
    hash_bv_t long_crc_div = get_long_non_primitive_crc_divisor(key_width);
    hash_bv_t short_crc_div = get_short_crc_divisor(key_width);
    if (!long_crc_div.get_width() || !short_crc_div.get_width()) {
        log_err(TABLES, "Could not find CRC divisors for length: %zd", key_width);
        dassert_crit(false);
    }
    out_params.rc5_parameter = generate_pseudo_rc5(key_width, bank_idx);
    out_params.long_crc_div = long_crc_div;
    out_params.short_crc_div = short_crc_div;
    out_params.long_crc_init = em::hash_bv_t(0, out_params.long_crc_div.get_width() - 1);
    out_params.short_crc_init = em::hash_bv_t(0, out_params.short_crc_div.get_width() - 1);
    out_params.short_crc_init.negate();
}

} // namespace em

} // namespace silicon_one
