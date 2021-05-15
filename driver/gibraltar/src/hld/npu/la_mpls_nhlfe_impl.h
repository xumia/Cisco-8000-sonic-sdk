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

#ifndef __LA_MPLS_NHLFE_IMPL_H__
#define __LA_MPLS_NHLFE_IMPL_H__

#include "api/npu/la_mpls_nhlfe.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

class la_mpls_nhlfe_impl : public la_mpls_nhlfe, public dependency_listener
{
    /////////Serialization///////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_mpls_nhlfe_impl() = default;
    /////////////////////////////////
public:
    explicit la_mpls_nhlfe_impl(const la_device_impl_wptr& device);
    ~la_mpls_nhlfe_impl() override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_mpls_nhlfe API's
    la_mpls_action_e get_action() const override;
    la_mpls_label get_label() const override;
    la_mpls_label get_merge_point_label() const override;
    const la_l3_destination* get_destination() const override;
    const la_system_port* get_destination_system_port() const override;

    // la_mpls_nhlfe_impl API's
    la_status initialize_swap(la_object_id_t oid, const la_l3_destination_wcptr& l3_destination, la_mpls_label label);
    la_status initialize_php(la_object_id_t oid, const la_l3_destination_wcptr& l3_destination);
    la_status initialize_tunnel_protection(la_object_id_t oid,
                                           const la_l3_destination_wcptr& l3_destination,
                                           la_mpls_label te_label,
                                           la_mpls_label mp_label);
    la_status initialize_l2_adjacency(la_object_id_t oid, const la_prefix_object_wcptr& prefix, const la_system_port_wcptr& dsp);
    la_status destroy();

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    // Resolution API helpers
    la_status instantiate(resolution_step_e prev_step);
    la_status uninstantiate(resolution_step_e prev_step);
    destination_id get_destination_id(resolution_step_e prev_step) const;

private:
    // Resolution API helpers
    // General functions
    resolution_step_e get_next_resolution_step(resolution_step_e prev_step) const;

    // Containing device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID; // Entry type
    la_mpls_action_e m_action;

    // Destination
    la_l3_destination_wcptr m_l3_destination;

    // Label for SWAP entries
    la_mpls_label m_label;

    // MP Label for TUNNEL_PROTECTION entries
    la_mpls_label m_mp_label;

    // DSP for L2 ADJ
    la_system_port_base_wcptr m_dsp;

    // SPA for L2 ADJ
    la_spa_port_base_wcptr m_spa;

    // Resolution related data
    struct resolution_data {
        resolution_data();
        la_uint_t users_for_step[RESOLUTION_STEP_LAST];
    } m_resolution_data;
    CEREAL_SUPPORT_PRIVATE_CLASS(resolution_data)
};

} // namespace silicon_one

#endif // __LA_MPLS_NHLFE_IMPL_H__
