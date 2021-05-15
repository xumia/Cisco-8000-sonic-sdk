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

#ifndef __COUNTER_ALLOCATION_H__
#define __COUNTER_ALLOCATION_H__

#include <sstream>

#include "api/types/la_common_types.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class counter_logical_bank;
class counter_manager;
class la_meter_set_statistical_impl;

// Bank entry allocation holds the data needed to access
// the physical-entries in a single logical-bank
class counter_allocation
{
    friend class counter_logical_bank;
    friend class counter_manager;
    friend class la_meter_set_statistical_impl;

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    counter_allocation() : set_size((size_t)-1), num_of_ifgs(size_t(-1)), base_row_index((size_t)-1), phys_bank_index((size_t)-1)
    {
        ifg.slice = (la_slice_id_t)-1;
        ifg.ifg = (la_ifg_id_t)-1;
    }

    ~counter_allocation() = default;

    // Return the ID of the first bank in the allocation
    size_t get_bank_id() const
    {
        return phys_bank_index;
    }

    // Return the first IFG associated with the allocation
    la_slice_ifg get_ifg() const
    {
        return ifg;
    }

    // Return the number of IFGs covered by the allocation
    size_t get_num_of_ifgs() const
    {
        return num_of_ifgs;
    }

    // Return if the Id is valid
    bool valid() const
    {
        return (phys_bank_index != ((size_t)-1));
    }

    // Return the index of the first bank entry in the set
    size_t get_index() const
    {
        return base_row_index;
    }

    std::string to_string() const
    {
        std::stringstream ss;

        ss << "counter_allocation: set_size=" << set_size << " slice=" << ifg.slice << " ifg=" << ifg.ifg
           << " num_of_ifgs=" << num_of_ifgs << " base_row_index=" << base_row_index << " phys_bank_index=" << phys_bank_index;

        return ss.str();
    }

private:
    size_t set_size;                // Number of sub-counters
    la_slice_ifg ifg;               // First IFG associated with the user of the counter
    size_t num_of_ifgs;             // Number of consequtive IFGs included in the allocation
    size_t base_row_index;          // Offset-in-bank of the first sub-counter
    size_t phys_bank_index;         // First physical-bank where the allocation resides
    counter_logical_bank_wptr bank; // Logical-bank where the allocation resides

    counter_allocation(size_t _set_size, la_slice_ifg _ifg, size_t _num_of_ifgs)
        : set_size(_set_size), ifg(_ifg), num_of_ifgs(size_t(_num_of_ifgs)), base_row_index((size_t)-1)
    {
    }
};

} // namespace silicon_one

#endif // __COUNTER_ALLOCATION_H__
