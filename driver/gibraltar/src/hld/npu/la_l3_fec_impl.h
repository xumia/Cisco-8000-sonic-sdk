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

#ifndef __LA_L3_FEC_IMPL_H__
#define __LA_L3_FEC_IMPL_H__

#include "api/npu/la_l3_fec.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

class la_l3_fec_impl : public la_l3_fec, public std::enable_shared_from_this<la_l3_fec_impl>, public dependency_listener
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_l3_fec_impl() = default;
    //////////////////////////////

public:
    explicit la_l3_fec_impl(const la_device_impl_wptr& device);
    ~la_l3_fec_impl() override;

    la_status initialize(la_object_id_t oid,
                         la_fec_gid_t fec_gid,
                         bool is_internal_wrapper,
                         const la_l3_destination_wptr& destination);
    la_status initialize(la_object_id_t oid,
                         la_fec_gid_t fec_gid,
                         bool is_internal_wrapper,
                         const la_l2_destination_wptr& destination);

    la_status destroy();
    la_fec_gid_t get_gid() const;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_l3_fec API-s
    la_status set_destination(la_l3_destination* destination) override;
    la_status set_destination(la_l2_destination* destination) override;
    la_l3_destination* get_destination() const override;

    // la_l3_fec_impl API-s
    la_status update_fec(const la_l3_destination_wptr& destination);
    la_status update_fec(const la_l2_destination_wptr& destination);

    // Resolution API helpers
    lpm_destination_id get_lpm_destination_id(resolution_step_e prev_step) const;
    destination_id get_destination_id(resolution_step_e prev_step) const;

private:
    // Attributes management
    la_status update_dependent_attributes(dependency_management_op op);

    // Helper functions for adding/removing attribute dependency
    void add_dependency(const la_l3_destination_wptr& destination);
    void add_dependency(const la_l2_destination_wptr& destination);
    void remove_dependency(const la_l3_destination_wptr& destination);
    void remove_dependency(const la_l2_destination_wptr& destination);

    // Delete the object from the resolution, and helper functions
    la_status teardown_resolution_step_fec();

    template <class _DestinationType>
    la_status do_initialize(la_object_id_t oid,
                            la_fec_gid_t fec_gid,
                            bool is_internal_wrapper,
                            const weak_ptr_unsafe<_DestinationType>& destination);

    template <class _DestinationType>
    la_status do_set_destination(const weak_ptr_unsafe<_DestinationType>& destination);
    // Owner device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid{LA_OBJECT_ID_INVALID};
    // FEC ID
    la_fec_gid_t m_gid;

    // Is object created by SDK
    bool m_is_wrapper;

    // Destination object
    la_l3_destination_wptr m_l3_destination;
    la_l2_destination_wptr m_l2_destination;

    // FEC table entry
    npl_fec_table_entry_wptr_t m_fec_table_entry;

    // RPF FEC table entry
    npl_rpf_fec_table_entry_wptr_t m_rpf_fec_table_entry;

    // Table configuration helper functions
    la_status configure_basic_routing(const la_next_hop_gibraltar_wptr& nh);
    la_status configure_basic_routing(const la_ecmp_group_impl_wptr& ecmp);
    la_status configure_basic_routing(const la_prefix_object_base_wptr& pfx_obj);
    la_status configure_l3_vxlan(const la_l2_service_port_base_wptr& vxlan_port);
    la_status remove_basic_routing();
    la_status remove_l3_vxlan();
    la_status config_fec_table(npl_fec_table_value_t value);
    la_status config_rpf_fec_table(npl_destination_t dest);
    void save_destination(const la_l3_destination_wptr& destination);
    void save_destination(const la_l2_destination_wptr& destination);
};

} // namespace silicon_one

#endif // __LA_L3_FEC_IMPL_H__
