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

#ifndef __NPL_GENERIC_DATA_STRUCTS_H__
#define __NPL_GENERIC_DATA_STRUCTS_H__

#include <stdint.h>
#include "common/bit_vector.h"
using silicon_one::bit_vector;
using silicon_one::bit_vector64_t;
using silicon_one::bit_vector128_t;
using silicon_one::bit_vector192_t;
using silicon_one::bit_vector384_t;
#include <vector>

namespace silicon_one
{

struct table_generic_entry_t { // TODO should we split to EM and SRAM (key size)?

    bit_vector key;
    bit_vector payload;

    table_generic_entry_t();
    table_generic_entry_t(size_t key_size, size_t payload_size);
};

struct ternary_table_generic_entry_t { // TODO should we add another for LPM?

    bit_vector key;
    bit_vector mask;
    bit_vector payload;

    ternary_table_generic_entry_t();
    ternary_table_generic_entry_t(size_t key_size, size_t payload_size);
};

std::vector<ternary_table_generic_entry_t> conjunct_lines(const std::vector<ternary_table_generic_entry_t>& vec1,
                                                          const std::vector<ternary_table_generic_entry_t>& vec2);
}

#endif
