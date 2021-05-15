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

#ifndef __CUD_RANGE_MANAGER_H__
#define __CUD_RANGE_MANAGER_H__

#include <array>

#include "api/types/la_common_types.h"
#include "common/la_status.h"
#include "common/ranged_index_generator.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_device_impl;

class cud_range_manager
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    cud_range_manager() = default;
    //////////////////////////////
public:
    explicit cud_range_manager(const la_device_impl_wptr& device, la_slice_id_t slice);
    ~cud_range_manager() = default;
    la_status initialize();
    la_status destroy();

    /// @brief Allocate a CUD index.
    la_status allocate(bool is_wide, uint64_t& out_cud_entry_index);

    /// @brief Release a CUD index.
    la_status release(uint64_t cud_entry_index);

private:
    enum {
        // MC copy ID is compound of {range, entry}
        NUM_ENTRY_BITS = 7,
        NUM_RANGE_BITS = 6,
        ENTRY_MASK = (1 << NUM_ENTRY_BITS) - 1,
        RANGE_MASK = (1 << NUM_RANGE_BITS) - 1,

        NUM_MC_COPY_IDS_PER_SLICE = (1 << (NUM_ENTRY_BITS + NUM_RANGE_BITS)),
        NUM_CUD_RANGES = (1 << NUM_RANGE_BITS),
        NUM_ENTRIES_IN_CUD_RANGE = NUM_MC_COPY_IDS_PER_SLICE / NUM_CUD_RANGES,

        NUM_ENTRIES_PER_WIDE_CUD = 2,
    };

    // Parent device
    la_device_impl_wptr m_device;

    // Slice managed by this object
    la_slice_id_t m_slice;

    // is-initialized flag
    bool m_is_initialized;

    // Index generators for each region
    std::array<ranged_index_generator, NUM_CUD_RANGES> m_index_gen;

    // Indication of whether a range is being used
    std::array<bool, NUM_CUD_RANGES> m_is_used;

    // Indication of whether a range is used for wide entries
    std::array<bool, NUM_CUD_RANGES> m_is_wide;

private:
    // Helper functions for configuring device tables
    la_status configure_mc_cud_is_wide_entry(size_t range, bool is_wide);
    la_status release_mc_cud_is_wide_entry(size_t range);
    uint64_t make_cud_entry_index(size_t range, uint64_t id);
};

} // namespace silicon_one

#endif // __CUD_RANGE_MANAGER_H__
