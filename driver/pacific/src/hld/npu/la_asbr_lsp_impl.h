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

#ifndef __LA_ASBR_LSP_IMPL_H__
#define __LA_ASBR_LSP_IMPL_H__

#include "api/npu/la_asbr_lsp.h"
#include "api/npu/la_next_hop.h"
#include "api/npu/la_prefix_object.h"
#include "api/types/la_mpls_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "hld_utils.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

struct resolution_cfg_handle_t;

class la_asbr_lsp_impl : public la_asbr_lsp, public dependency_listener
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_asbr_lsp_impl(const la_device_impl_wptr& device);
    ~la_asbr_lsp_impl() override;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    la_status initialize(la_object_id_t oid, const la_prefix_object_wcptr& asbr, const la_l3_destination_wcptr& destination);
    la_status destroy();
    la_status instantiate(resolution_step_e prev_step);
    la_status uninstantiate(resolution_step_e prev_step);

    // la_object APIs
    const la_device* get_device() const override;
    object_type_e type() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_asbr_lsp APIs
    const la_prefix_object* get_asbr() const override;
    la_status set_asbr(const la_prefix_object* asbr) override;
    const la_l3_destination* get_destination() const override;
    la_status set_destination(const la_l3_destination* destination) override;

    // Resolution API helpers
    destination_id get_destination_id(resolution_step_e prev_step) const;
    la_l3_destination_gid_t get_asbr_gid() const;
    la_status get_resolution_cfg_handle(const resolution_cfg_handle_t*& out_cfg_handle) const;

private:
    // Creating device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // ASBR
    la_prefix_object_wcptr m_asbr;

    // Destination
    la_l3_destination_wcptr m_destination;

    // Primary and Backup NH if destination is a Protection group
    la_next_hop_wcptr m_primary_nh;
    la_next_hop_wcptr m_backup_nh;

    // Attributes management
    la_status update_dependent_attributes(dependency_management_op op);

    // Helper functions for adding/removing dependency
    void add_dependency(const la_prefix_object_wcptr& asbr, const la_l3_destination_wcptr& destination);
    void remove_dependency(const la_prefix_object_wcptr& asbr, const la_l3_destination_wcptr& destination);
    void register_attribute_dependency(const la_l3_destination_wcptr& destination);
    void deregister_attribute_dependency(const la_l3_destination_wcptr& destination);

    la_status check_asbr_and_destination(const la_prefix_object_wcptr& asbr, const la_l3_destination_wcptr& destination);

    la_status get_l3_protection_group_destinations(const la_l3_destination_wcptr& destination,
                                                   la_next_hop_wcptr& primary_nh,
                                                   la_next_hop_wcptr& backup_nh);
    la_status notify_asbr_about_lsp_destination(const la_prefix_object_wcptr& asbr,
                                                const la_l3_destination_wcptr& l3_dest,
                                                bool is_add);
    la_status notify_asbr_about_lsp_next_hop(const la_prefix_object_wcptr& asbr, const la_next_hop_wcptr& next_hop, bool is_add);

    la_asbr_lsp_impl() = default; // For serialization purposes only.
};

} // namespace silicon_one

#endif // __LA_ASBR_LSP_IMPL_H__
