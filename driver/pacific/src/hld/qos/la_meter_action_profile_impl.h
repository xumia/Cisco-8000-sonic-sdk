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

#ifndef __LA_METER_ACTION_PROFILE_IMPL_H__
#define __LA_METER_ACTION_PROFILE_IMPL_H__

#include <map>

#include "api/qos/la_meter_action_profile.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "ifg_use_count.h"

namespace silicon_one
{

class la_device_impl;

class la_meter_action_profile_impl : public la_meter_action_profile, public dependency_listener
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_meter_action_profile_impl(const la_device_impl_wptr& device);
    ~la_meter_action_profile_impl() override;
    la_status initialize(la_object_id_t oid);
    la_status destroy();

    enum {
        NUM_EXACT_METER_ACTION_PROFILE_PER_IFG = (1 << 2),
        NUM_STATISTICAL_METER_ACTION_PROFILE_PER_BANK = (1 << 2),
    };

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Slice management helpers
    la_status add_ifg(la_slice_ifg ifg);
    la_status remove_ifg(la_slice_ifg ifg);

    // la_meter_action_profile API-s
    virtual la_status set_action(la_qos_color_e meter_color,
                                 la_qos_color_e rate_limiter_color,
                                 bool drop_enable,
                                 bool mark_ecn,
                                 la_qos_color_e packet_color,
                                 la_qos_color_e rx_cgm_color) override;

    virtual la_status get_action(la_qos_color_e meter_color,
                                 la_qos_color_e rate_limiter_color,
                                 bool& out_drop_enable,
                                 bool& out_mark_ecn,
                                 la_qos_color_e& out_packet_color,
                                 la_qos_color_e& out_rx_cgm_color) const override;

    la_status get_allocation_in_exact_bank(la_slice_ifg slice_ifg, uint64_t& out_index) const;
    la_status get_allocation_in_statistical_banks(uint64_t& out_index) const;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    la_status attach_statistical_meter();
    la_status detach_statistical_meter();

private:
    static constexpr size_t INVALID_INDEX = (size_t)-1;

    // Profile properties
    struct per_color_pair_properties {
        bool drop_enable;
        bool mark_ecn;
        la_qos_color_e packet_color;
        la_qos_color_e rx_cgm_color;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(per_color_pair_properties)

    struct allocation_data {
        uint64_t profile_index = INVALID_INDEX;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(allocation_data)

    struct stat_bank_allocation_data : allocation_data {
        size_t use_count = 0;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(stat_bank_allocation_data)

    // first in pair is the meter color, second is global
    using meter_rate_limiter_color_pair = std::pair<la_qos_color_e, la_qos_color_e>;
    using color_properties_map = std::map<meter_rate_limiter_color_pair, per_color_pair_properties>;
    color_properties_map m_action_profile_properties_map;

    allocation_data m_exact_meters_allocation[NUM_IFGS_PER_DEVICE];
    stat_bank_allocation_data m_stat_bank_data;

    // Containing device
    la_device_impl_wptr m_device;

    /// Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    /// IFG manager
    ifg_use_count_uptr m_ifg_use_count;

private:
    // exact_meter_decision_table managment
    la_status exact_meter_decision_mapping_table_configure_entry(la_slice_ifg ifg,
                                                                 const meter_rate_limiter_color_pair& color_pair,
                                                                 const per_color_pair_properties& properties);
    la_status exact_meter_decision_mapping_table_erase_entry(la_slice_ifg ifg, const meter_rate_limiter_color_pair& color_pair);

    // Statistical meter profile tables
    la_status statistical_meter_decision_mapping_table_configure_all_banks(const meter_rate_limiter_color_pair& color_pair,
                                                                           const per_color_pair_properties& properties);
    la_status statistical_meter_decision_mapping_table_erase_all_banks(const meter_rate_limiter_color_pair& color_pair);

    la_status statistical_meter_decision_mapping_table_configure_entry(size_t bank_index,
                                                                       const meter_rate_limiter_color_pair& color_pair,
                                                                       const per_color_pair_properties& properties);
    la_status statistical_meter_decision_mapping_table_erase_entry(size_t bank_index,
                                                                   const meter_rate_limiter_color_pair& color_pair);

    template <typename _Key, typename _Payload>
    void populate_meter_decision_mapping_table_key_payload(la_qos_color_e meter_result_color,
                                                           per_color_pair_properties properties,
                                                           allocation_data data,
                                                           _Key& key,
                                                           _Payload& payload) const;

    bool is_allocated_in_exact_bank(la_slice_ifg slice_ifg) const;
    bool is_allocated_in_statistical_banks() const;

    la_meter_action_profile_impl() = default; // For serialization purposes only.
};

} // namespace silicon_one

#endif //  __LA_METER_ACTION_PROFILE_IMPL_H__
