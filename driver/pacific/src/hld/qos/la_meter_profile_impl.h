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

#ifndef __LA_METER_PROFILE_IMPL_H__
#define __LA_METER_PROFILE_IMPL_H__

#include <map>

#include "api/qos/la_meter_profile.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "ifg_use_count.h"

namespace silicon_one
{

class la_device_impl;

class la_meter_profile_impl : public la_meter_profile, public dependency_listener
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_meter_profile_impl(const la_device_impl_wptr& device,
                                   type_e meter_type,
                                   meter_measure_mode_e meter_measure_mode,
                                   meter_rate_mode_e meter_rate_mode,
                                   color_awareness_mode_e color_awareness_mode);
    ~la_meter_profile_impl() override;
    la_status initialize(la_object_id_t oid);
    la_status destroy();

    enum {
        NUM_EXACT_METER_PROFILES_PER_IFG = (1 << 4),
        NUM_STATISTICAL_METER_PROFILES_PER_BANK = (1 << 4),
        BURST_SIZE_WIDTH = 18,
        TOKEN_RESOLUTION = 64,
        TOKEN_PARTS = (1 << 5) - 1,
        CBS_RESOLUTION = 1024,
        EBS_OR_PBS_RESOLUTION = 1024,
    };

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // Slice management helpers
    la_status add_ifg(la_slice_ifg ifg);
    la_status remove_ifg(la_slice_ifg ifg);

    // la_meter_profile API-s
    la_status set_meter_measure_mode(meter_measure_mode_e meter_measure_mode) override;
    la_status get_meter_measure_mode(meter_measure_mode_e& out_meter_measure_mode) const override;
    la_status set_meter_rate_mode(meter_rate_mode_e meter_rate_mode) override;
    la_status get_meter_rate_mode(meter_rate_mode_e& out_meter_rate_mode) const override;
    la_status set_color_awareness_mode(color_awareness_mode_e color_awareness_mode) override;
    la_status get_color_awareness_mode(color_awareness_mode_e& out_color_awareness_mode) const override;
    la_status set_cascade_mode(cascade_mode_e cascade_mode) override;
    la_status get_cascade_mode(cascade_mode_e& out_cascade_mode) const override;
    la_status set_cbs(la_uint64_t cbs) override;
    la_status get_cbs(la_uint64_t& out_cbs) const override;
    la_status set_ebs_or_pbs(la_uint64_t ebs_or_pbs) override;
    la_status get_ebs_or_pbs(la_uint64_t& out_ebs_or_pbs) const override;
    la_status set_cbs(la_slice_ifg ifg, la_uint64_t cbs) override;
    la_status get_cbs(la_slice_ifg ifg, la_uint64_t& out_cbs) const override;
    la_status set_ebs_or_pbs(la_slice_ifg ifg, la_uint64_t ebs_or_pbs) override;
    la_status get_ebs_or_pbs(la_slice_ifg ifg, la_uint64_t& out_ebs_or_pbs) const override;
    type_e get_type() const override;

    la_status get_allocation_in_exact_bank(la_slice_ifg slice_ifg, uint64_t& out_index) const;
    la_status get_allocation_in_statistical_banks(uint64_t& out_index) const;

    la_status attach_statistical_meter();
    la_status detach_statistical_meter();

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

private:
    static constexpr size_t INVALID_INDEX = (size_t)-1;

    struct allocation_data {
        la_uint64_t cbs = 0;
        la_uint64_t ebs_or_pbs = 0;
        uint64_t profile_index = INVALID_INDEX;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(allocation_data)

    struct stat_bank_allocation_data : allocation_data {
        size_t use_count = 0;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(stat_bank_allocation_data)

    allocation_data m_ifg_data[NUM_IFGS_PER_DEVICE];
    stat_bank_allocation_data m_stat_bank_data;

    // Containing device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Profile properties
    type_e m_type;
    meter_measure_mode_e m_measure_mode;
    meter_rate_mode_e m_rate_mode;
    color_awareness_mode_e m_color_awareness;
    cascade_mode_e m_cascade_mode;

    // IFG manager
    ifg_use_count_uptr m_ifg_use_count;

private:
    // exact_meter_decision_table managment
    la_status exact_meter_profile_table_configure_entry(la_slice_ifg ifg);
    la_status exact_meter_profile_table_erase_entry(la_slice_ifg ifg);

    // Statistical meter profile tables
    la_status configure_statistical_meter_tables_entries();
    la_status erase_statistical_meter_tables_entries();
    la_status statistical_meter_profile_table_configure_entries(size_t bank_index);
    la_status statistical_meter_profile_table_erase_entries(size_t bank_index);
    // the is_cascade property of the statistical meters is written in the distributed meter profiles.
    la_status distributed_meter_profile_table_configure_entries(size_t bank_index);
    la_status distributed_meter_profile_table_erase_entries(size_t bank_index);

    template <typename _Key, typename _Payload>
    void populate_meter_profile_table_key_payload(size_t bank_index, allocation_data data, _Key& key, _Payload& payload) const;

    bool is_allocated_in_exact_bank(la_slice_ifg slice_ifg) const;
    bool is_allocated_in_statistical_banks() const;

    la_meter_profile_impl() = default; // For serialization purposes only.
};

} // namespace silicon_one

#endif //  __LA_METER_PROFILE_IMPL_H__
