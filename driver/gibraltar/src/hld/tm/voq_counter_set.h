// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __VOQ_COUNTER_SET_H__
#define __VOQ_COUNTER_SET_H__

#include "api/tm/la_voq_set.h"
#include "api/types/la_object.h"
#include "api/types/la_system_types.h"
#include "api/types/la_tm_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "ifg_use_count.h"
#include "system/counter_manager.h"

namespace silicon_one
{

class la_device_impl;

class voq_counter_set
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Defines the VOQ-counter-set size.
    enum {
        NUM_VOQ_SET_BITS = 6,                      ///< Number of masked LSBs to group VOQs to 1 voq-counter-set.
        NUM_VOQS_IN_SET = (1 << NUM_VOQ_SET_BITS), ///< Number of VOQ-s.
    };

    explicit voq_counter_set(const la_device_impl_wptr& device);
    ~voq_counter_set();

    la_status destroy();

    la_status register_voq_counter_set_user(la_voq_set::voq_counter_type_e type,
                                            size_t group_size,
                                            la_voq_gid_t base_voq_id,
                                            size_t voq_set_size,
                                            size_t counter_set_size);
    la_status deregister_voq_counter_set_user(la_voq_gid_t base_voq_id, size_t voq_set_size);
    la_voq_gid_t get_voq_msbs() const;
    size_t get_group_size() const;
    la_voq_set::voq_counter_type_e get_type() const;
    uint64_t get_registered_voq_counter_set_users() const;
    la_status read(la_voq_gid_t base_voq_id,
                   size_t counter_index,
                   bool force_update,
                   bool clear_on_read,
                   size_t& out_packets,
                   size_t& out_bytes);
    la_status read(la_voq_gid_t base_voq_id,
                   la_slice_id_t slice_id,
                   size_t counter_index,
                   bool force_update,
                   bool clear_on_read,
                   size_t& out_packets,
                   size_t& out_bytes);

    /// @brief Get device that owns this voq_counter_set.
    ///
    /// Device returned is the same one used for creating this object.
    ///
    /// @return     #silicon_one::la_device* that created this object.
    const la_device* get_device() const;

private:
    size_t get_base_counter_offset(size_t base_voq);

    // Containing device
    la_device_impl_wptr m_device;

    // IFG use count
    ifg_use_count_uptr m_ifg_use_count;

    // Number of sub-counters
    size_t m_num_physical_counters;

    // Physical counter descriptors per slice.
    std::array<counter_allocation, ASIC_MAX_SLICES_PER_DEVICE_NUM> m_allocations;

    // VOQ ID
    la_voq_gid_t m_voq_msbs;

    // Group size
    size_t m_group_size;

    // Counter type
    la_voq_set::voq_counter_type_e m_type;

    // Track VOQ sets allocated in the 64 VOQ block
    uint64_t m_voq_counter_set_users;

    // Per slice packet/byte counter cache.
    struct per_slice_counter_cache {
        bool is_valid;
        std::vector<size_t> cached_packets;
        std::vector<size_t> cached_bytes;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(per_slice_counter_cache)

    // Cached counters per slice.
    std::array<per_slice_counter_cache, ASIC_MAX_SLICES_PER_DEVICE_NUM> m_counter_cache;

    // Helper functions for writing to QoS mapping tables
    la_status update_counters_voq_block_map_table();

    // Helper function to calculate total number of counters for 64 VOQs
    la_status validate_num_counters(la_voq_set::voq_counter_type_e type,
                                    size_t group_size,
                                    size_t voq_set_size,
                                    size_t counter_set_size);

    // Helper functions
    la_status validate_params(la_voq_set::voq_counter_type_e type, size_t group_size, size_t voq_set_size, size_t counter_set_size);

    la_status update_voq_sets_alloced(la_voq_gid_t base_voq_id, size_t set_size, bool alloc);

    la_status add_ifg(la_slice_ifg ifg);
    la_status remove_ifg(la_slice_ifg ifg);

    la_status add_voq_counter_set(la_voq_set::voq_counter_type_e type,
                                  size_t group_size,
                                  la_voq_gid_t base_voq_id,
                                  size_t voq_set_size,
                                  size_t counter_set_size);
    la_status remove_voq_counter_set();

    voq_counter_set() = default; // For serialization purposes only.
};                               // class voq_counter_set

} // namespace silicon_one

#endif // __VOQ_COUNTER_SET_H__
