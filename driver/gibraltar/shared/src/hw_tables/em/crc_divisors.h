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

#ifndef __CRC_DIVISORS_H__
#define __CRC_DIVISORS_H__

#include "common/bit_vector.h"
#include "hw_tables/em_common.h"

#include <stddef.h>

/// @file Provide CRC divisor polynoms for Exact Match hash functions.
/// CRC divisors are hard coded into Pacific HW, to be used in HW hashers.
/// This file contains exact replications of the hard coded values.
/// During CRC calculation, two polynoms are needed: long (key length) and short (half key length).
/// Moreover, HW supports two configurations of long polynoms: primitive and non-primitive, maintaining two sets.
/// There is only one set of short polynoms.

namespace silicon_one
{

/// @brief Returns CRC polynom from long primitive set.
///
/// @param[in]  key_width       key width for CRC calculation.
///
/// @retval     bitvector representation of the divisor's coefficients.
em::hash_bv_t get_long_primitive_crc_divisor(size_t key_width);

/// @brief Returns CRC polynom from long non-primitive set.
///
/// @param[in]  key_width       key width for CRC calculation.
///
/// @retval     bitvector representation of the divisor's coefficients.
em::hash_bv_t get_long_non_primitive_crc_divisor(size_t key_width);

/// @brief Returns CRC polynom from short set.
///
/// @param[in]  key_width       key width for CRC calculation.
///
/// @retval     bitvector representation of the divisor's coefficients.
em::hash_bv_t get_short_crc_divisor(size_t key_width);

} // namespace silicon_one

#endif // __CRC_DIVISORS_H__
