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

#ifndef __COUNTER_MANAGER_H__
#define __COUNTER_MANAGER_H__

#include <bitset>
#include <set>
#include <vector>

#include "api/types/la_common_types.h"
#include "common/allocator_wrapper.h"
#include "counter_logical_bank.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_device_impl;
class resource_monitor;

using resource_monitor_sptr = std::shared_ptr<resource_monitor>;

static const std::vector<counter_user_group_vec> counter_user_groups[COUNTER_DIRECTION_NUM] = {
    {
        // COUNTER_DIRECTION_INGRESS = 0
        {COUNTER_USER_TYPE_L2_AC_PORT, COUNTER_USER_TYPE_L3_AC_PORT, COUNTER_USER_TYPE_L2_PWE_PORT},  // GROUP_A
        {COUNTER_USER_TYPE_TUNNEL, COUNTER_USER_TYPE_SVI_OR_ADJACENCY, COUNTER_USER_TYPE_MPLS_DECAP}, // GROUP_B
        {COUNTER_USER_TYPE_DROP,
         COUNTER_USER_TYPE_TRAP,
         COUNTER_USER_TYPE_SEC_ACE,
         COUNTER_USER_TYPE_BFD,
         COUNTER_USER_TYPE_VNI},                          // GROUP_C
        {COUNTER_USER_TYPE_VOQ},                          // GROUP_D
        {COUNTER_USER_TYPE_METER, COUNTER_USER_TYPE_QOS}, // GROUP_E
    },
    {
        // COUNTER_DIRECTION_EGRESS = 1
        {COUNTER_USER_TYPE_L2_AC_PORT, COUNTER_USER_TYPE_L3_AC_PORT, COUNTER_USER_TYPE_DROP}, // GROUP_A
        {COUNTER_USER_TYPE_TUNNEL,
         COUNTER_USER_TYPE_SVI_OR_ADJACENCY,
         COUNTER_USER_TYPE_MPLS_NH,
         COUNTER_USER_TYPE_MPLS_GLOBAL,
         COUNTER_USER_TYPE_L2_MIRROR},                                                                      // GROUP_B
        {COUNTER_USER_TYPE_QOS, COUNTER_USER_TYPE_TRAP, COUNTER_USER_TYPE_ERSPAN},                          // GROUP_C
        {COUNTER_USER_TYPE_SEC_ACE, COUNTER_USER_TYPE_VNI, COUNTER_USER_TYPE_SR_DM, COUNTER_USER_TYPE_MCG}, // GROUP_D
        {},                                                                                                 // GROUP_E
    },
};

class counter_manager
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    counter_manager() = default;
    //////////////////////////////

public:
    enum {
        COUNTER_BANK_BASE = 0,
        METER_BANK_BASE = 96,                // Banks 96-108 has both meter entries and counter entries
        NUM_OF_BANKS = 108,                  // Total number of banks
        NUM_OF_RX_BANKS = 60,                // Number of banks allocated to RxPP's
        NUM_MCG_BANK_PROFILES_PER_SLICE = 4, // Max number of banks which can be allocated for MCG counters per slice
    };

    enum class bank_type_e {
        COUNTER_BANK,
        METER_BANK,
    };

    explicit counter_manager(const la_device_impl_wptr& device);
    ~counter_manager();

    // @brief Allocate physical counters
    //
    // @param[in]  is_slice_pair              Counter is used in a slice-pair table
    // @param[in]  direction                  Either ingress or egress
    // @param[in]  set_size                   Number of sub-counters
    // @param[in]  ifg                        IFG
    // @param[in]  num_of_ifgs                Number of consequtive IFGs included in the counter
    // @param[in]  user_type                  Intended use of the counter
    // @param[out] out_counter_allocation     Allocated counter.
    //
    la_status allocate(bool is_slice_pair,
                       counter_direction_e direction,
                       size_t set_size,
                       la_slice_ifg ifg,
                       size_t num_of_ifgs,
                       counter_user_type_e user_type,
                       counter_allocation& out_counter_allocation);

    // Release previously allocated counters
    void release(counter_user_type_e user_type, const counter_allocation& allocation);

    // Read a single allocation
    void read_counter(const counter_allocation& allocation,
                      size_t sub_counter_index,
                      bool force_update,
                      bool clear_on_read,
                      uint64_t& out_bytes_count,
                      uint64_t& out_packet_count);

    void read_counter_ifg(const counter_allocation& allocation,
                          la_slice_ifg ifg,
                          size_t sub_counter_index,
                          bool force_update,
                          bool clear_on_read,
                          uint64_t& out_bytes_count,
                          uint64_t& out_packet_count);
    // Read a single allocation of color-aware counters
    void read_meter(const counter_allocation& allocation,
                    size_t sub_counter_index,
                    la_qos_color_e color,
                    bool force_update,
                    bool clear_on_read,
                    uint64_t& out_bytes_count,
                    uint64_t& out_packet_count);

    void read_meter_ifg(const counter_allocation& allocation,
                        la_slice_ifg ifg,
                        size_t sub_counter_index,
                        la_qos_color_e color,
                        uint64_t& out_bytes_count,
                        uint64_t& out_packet_count);

    /// @brief Set resource monitor.
    ///
    /// @param[in]  resource_monitor           Resource monitor to attach.
    void set_resource_monitor(const resource_monitor_sptr& monitor);

    /// @brief Get attached resource monitor
    ///
    /// @param[out]  out_resource_monitor           Resource monitor to attach.
    void get_resource_monitor(resource_monitor_sptr& out_monitor);

    /// @brief Retrieve the number of used banks.
    ///
    /// @retval Current number of used banks.
    size_t size() const;

    /// @brief Retrieve the number of banks.
    ///
    /// @retval Number of banks.
    size_t max_size() const;

    /// @brief Get device that owns this object.
    ///
    /// @return     #silicon_one::la_device* that owns this object.
    const la_device* get_device() const;

    /// @brief Read all bank max counters and update physical entries caches with result.
    ///
    /// @retval LA_STATUS_SUCCESS      Command completed successfully.
    /// @retval LA_STATUS_EUNKNOWN     An unknown error occurred.
    la_status refresh_max_counters();

    // Get logical banks managed by this counter manager
    la_status get_logical_banks(std::set<const counter_logical_bank*>& out_banks) const;

    // Get MCG counter bank profile
    la_status get_mcg_bank_profile(size_t bank_index, la_slice_id_t slice, size_t& out_mcg_bank_profile) const;

private:
    // Containing device
    la_device_impl_wptr m_device;

    // Is-busy flags of the physical banks. 0:=free, 1:=in-use
    std::bitset<NUM_OF_BANKS> m_busy_phys_banks;

    // List of bank that are being used.
    std::set<counter_logical_bank_wptr> m_logical_banks;

    // Monitor for the banks utilization
    resource_monitor_sptr m_resource_monitor;

    // Network slices on the device, for efficient bank allocation
    size_t m_num_of_network_slices;

    // Mapping between physical bank id to it's logical bank if found. nullptr otherwise
    std::array<counter_logical_bank_sptr, NUM_OF_BANKS> m_banks;

    // Mapping between 2 bits MCG counter bank profile to 7 bits counter bank per slice
    size_t m_mcg_bank_profiles[ASIC_MAX_SLICES_PER_DEVICE_NUM][NUM_MCG_BANK_PROFILES_PER_SLICE];

private:
    // Allocate a new bank with the given attributes
    counter_logical_bank_wptr get_new_bank(bool is_slice_pair,
                                           la_slice_id_t slice,
                                           counter_direction_e direction,
                                           counter_user_type_e user_type);

    // Release the given bank
    void release_bank(const counter_logical_bank_wptr& bank);

    // Get Counter user group for the given counter_user_type_e
    void get_counter_user_group(counter_user_type_e user_type,
                                counter_direction_e direction,
                                counter_user_group_vec& out_user_group);

    // Check if the given bank matches the given attributes
    bool check_bank_match(const counter_logical_bank_wcptr& bank,
                          bool is_slice_pair,
                          la_slice_id_t slice,
                          counter_direction_e direction,
                          counter_user_type_e user_type);

    // Try to find place for the given allocation in the given bank
    bool bank_allocate(const counter_logical_bank_wptr& bank, counter_user_type_e user_type, counter_allocation& in_out_allocation);

    // Helper function to allocate_* API functions
    la_status do_allocate(bool is_slice_pair,
                          counter_direction_e direction,
                          counter_user_type_e user_type,
                          counter_allocation& in_out_allocation);

    // Get the number of network slices in the device
    size_t get_num_of_network_slices();

    bool is_meter_bank_user(counter_direction_e direction, counter_user_type_e type);
    // Reads and clears max counters and updates SW shadow
    // special handling for bank0 due to HW errata
    la_status read_and_clear_max_counters(bool is_bank0);

    // Adds/removes the MCG counter bank_index to/from m_mcg_bank_profiles
    la_status add_bank_to_mcg_bank_profiles(size_t bank_index, la_slice_id_t slice, size_t& out_mcg_bank_profile);
    la_status remove_bank_from_mcg_bank_profiles(size_t bank_index, la_slice_id_t slice);

    // Create LA_STATUS_INFO_ERESOURCE for counters bank resource
    la_status create_e_resource_status_with_counter_info(counter_user_type_e user_type, la_slice_id_t slice, la_ifg_id_t ifg) const;
};

} // namespace silicon_one

#endif // __COUNTER_MANAGER_H__
