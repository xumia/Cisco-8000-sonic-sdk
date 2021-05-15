// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_RX_CGM_SQ_PROFILE_IMPL_H__
#define __LA_RX_CGM_SQ_PROFILE_IMPL_H__

#include <map>

#include "api/cgm/la_rx_cgm_sq_profile.h"
#include "common/allocator_wrapper.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "ifg_use_count.h"

namespace silicon_one
{

class la_rx_cgm_sq_profile_impl : public la_rx_cgm_sq_profile
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_rx_cgm_sq_profile_impl(const la_device_impl_wptr& device);
    virtual ~la_rx_cgm_sq_profile_impl() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, bool is_default);
    la_status destroy();

    // Inherited API-s
    la_status set_thresholds(const la_rx_cgm_sq_profile_thresholds& thresholds) override;
    la_status get_thresholds(la_rx_cgm_sq_profile_thresholds& out_thresholds) const override;
    la_status set_rx_cgm_policy(const la_rx_cgm_policy_status& status,
                                bool flow_control,
                                bool drop_yellow,
                                bool drop_green,
                                bool fc_trig) override;
    la_status get_rx_cgm_policy(const la_rx_cgm_policy_status& status,
                                bool& out_flow_control,
                                bool& out_drop_yellow,
                                bool& out_drop_green,
                                bool& out_fc_trig) const override;
    la_status set_pfc_headroom_timer(std::chrono::nanoseconds time) override;
    la_status set_pfc_headroom_threshold(la_uint_t threshold) override;
    la_status get_pfc_headroom_value(la_uint_t& out_value) const override;

    // Get internal ID for debug purposes.
    la_uint_t get_internal_id(la_slice_id_t slice) const;

    // Allocation APIs. No-op if default profile.
    la_status add_ifg(la_slice_ifg ifg);
    la_status remove_ifg(la_slice_ifg ifg);

    bool is_default() const;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

private:
    la_status validate_thresholds(const la_rx_cgm_sq_profile_thresholds& thresholds);
    la_status validate_profile_status(const la_rx_cgm_policy_status& status);

    la_status set_slice_thresholds(la_slice_id_t slice, const la_rx_cgm_sq_profile_thresholds& threhsolds);
    la_status set_slice_policy(la_slice_id_t slice,
                               const la_rx_cgm_policy_status& status,
                               bool flow_control,
                               bool drop_yellow,
                               bool drop_green,
                               bool fc_trig);
    la_status set_slice_hr_value(la_slice_id_t slice, la_uint_t hr_value);

    la_status configure_default_policy_mapping();

    // Device this RXCGM SQ profile belongs to
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid;

    // Internal profile ID per slice
    std::array<la_uint_t, ASIC_MAX_SLICES_PER_DEVICE_NUM> m_profile_id;

    // Is this the default profile
    bool m_is_default;

    // Profile thresholds
    la_rx_cgm_sq_profile_thresholds m_thresholds;

    // Use count per IFG
    ifg_use_count_uptr m_ifg_use_count;

    struct policy_less_op {
        bool operator()(const la_rx_cgm_policy_status& lhs, const la_rx_cgm_policy_status& rhs) const
        {
            return std::tie(lhs.counter_a_region, lhs.sq_group_region, lhs.sq_profile_region)
                   < std::tie(rhs.counter_a_region, rhs.sq_group_region, rhs.sq_profile_region);
        };
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(policy_less_op)

    struct pfc_action {
        bool flow_control;
        bool drop_yellow;
        bool drop_green;
        bool fc_trig;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(pfc_action)

    // Maps status to three boolean values representing flow_control, drop_yellow and drop_green
    map_alloc<la_rx_cgm_policy_status, pfc_action, policy_less_op> m_rx_cgm_policy_map;

    // HR value
    la_uint_t m_hr_timer_or_threshold_value;

    la_rx_cgm_sq_profile_impl() = default; // For serialization only.
};
}

#endif
