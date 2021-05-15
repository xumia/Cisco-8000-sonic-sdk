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

#include "nplapi_translator/npl_generic_data_structs.h"

using namespace silicon_one;

ternary_table_generic_entry_t::ternary_table_generic_entry_t()
{
}

ternary_table_generic_entry_t::ternary_table_generic_entry_t(size_t key_size, size_t payload_size)
    : key(0, key_size), mask(0, key_size), payload(0, payload_size)
{
}

table_generic_entry_t::table_generic_entry_t()
{
}

table_generic_entry_t::table_generic_entry_t(size_t key_size, size_t payload_size) : key(0, key_size), payload(0, payload_size)
{
}

std::vector<ternary_table_generic_entry_t>
silicon_one::conjunct_lines(const std::vector<ternary_table_generic_entry_t>& vec1,
                                         const std::vector<ternary_table_generic_entry_t>& vec2)
{
    std::vector<ternary_table_generic_entry_t> result;
    for (const ternary_table_generic_entry_t& entry1 : vec1) {
        for (const ternary_table_generic_entry_t& entry2 : vec2) {
            bit_vector shared_mask = entry1.mask & entry2.mask;

            if ((entry1.key & shared_mask) == (entry2.key & shared_mask)) {
                ternary_table_generic_entry_t current_entry
                    = ternary_table_generic_entry_t(entry1.key.get_width(), entry1.payload.get_width());
                current_entry.key = (entry1.key & entry1.mask) | (entry2.key & entry2.mask);
                current_entry.mask = entry1.mask | entry2.mask;
                current_entry.payload = entry1.payload | entry2.payload;
                result.push_back(current_entry);
            }
        }
    }
    return result;
}
