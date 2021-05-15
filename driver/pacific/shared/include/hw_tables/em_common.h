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

#ifndef __LEABA_EM_COMMON_H__
#define __LEABA_EM_COMMON_H__

#include "common/bit_vector.h"

/// @file Common definitions for hw_tables/em classes

namespace silicon_one
{

namespace em
{
typedef bit_vector384_t key_t;
typedef bit_vector192_t payload_t;

typedef key_t hash_bv_t;

/// @brief Struct holding EM hasher parameters.
struct hasher_params {
    bit_vector rc5_parameter; ///< RC5 parameter.
    hash_bv_t long_crc_div;   ///< Long CRC divisor.
    hash_bv_t long_crc_init;  ///< Long initial vector.
    hash_bv_t short_crc_div;  ///< Short CRC divisor.
    hash_bv_t short_crc_init; ///< Short initial vector.
};

/// @brief Temporary helper to generate RC5 substitute.
bit_vector generate_pseudo_rc5(size_t key_width, size_t bank_idx);

/// @brief Generates hasher parameters with default values that can be used with #em_hasher.
void generate_default_hasher_params(size_t key_width, size_t bank_idx, hasher_params& out_params);

} // namespace em

} // namespace silicon_one

#endif // __LEABA_EM_COMMON_H__
