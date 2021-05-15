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

#ifndef __LA_IP_TUNNEL_DESTINATION_IMPL_H__
#define __LA_IP_TUNNEL_DESTINATION_IMPL_H__

#include "api/npu/la_ip_tunnel_destination.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "hld_utils.h"
#include "ifg_use_count.h"

namespace silicon_one
{

class la_ip_tunnel_destination_impl : public la_ip_tunnel_destination, public dependency_listener
{
    //////////////SERIALIZATION///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_ip_tunnel_destination_impl() = default;
    //////////////////////////////////////////
public:
    explicit la_ip_tunnel_destination_impl(const la_device_impl_wptr& device);
    ~la_ip_tunnel_destination_impl() override;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    la_status initialize(la_object_id_t oid,
                         la_l3_destination_gid_t ip_tunnel_destination_gid,
                         const la_l3_port_wcptr& ip_tunnel_port,
                         const la_l3_destination_wcptr& underlay_destination);
    la_status destroy();
    la_status instantiate(resolution_step_e prev_step);
    la_status uninstantiate(resolution_step_e prev_step);

    // la_object APIs
    const la_device* get_device() const override;
    object_type_e type() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;
    la_l3_destination_gid_t get_gid() const override;

    // la_ip_tunnel_destination APIs
    const la_l3_port* get_ip_tunnel_port() const override;
    const la_l3_destination* get_underlay_destination() const override;
    la_status set_underlay_destination(const la_l3_destination* underlay_destination) override;

    // Resolution API helpers
    lpm_destination_id get_lpm_destination_id(resolution_step_e prev_step) const;
    destination_id get_destination_id(resolution_step_e prev_step) const;

private:
    // Creating device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Global ID
    la_l3_destination_gid_t m_ip_tunnel_destination_gid;

    // Associated destination
    la_l3_destination_wcptr m_underlay_destination;

    // ip tunnel port
    la_l3_port_wcptr m_ip_tunnel_port;

    // Attributes management
    la_status update_dependent_attributes(dependency_management_op op);

    la_status update_destination(const la_l3_port_wcptr& ip_tunnel_port, const la_l3_destination_wcptr& destination, bool is_init);

    // Helper functions for adding/removing attribute dependency
    void add_dependency(const la_l3_destination_wcptr& destination);
    void remove_dependency(const la_l3_destination_wcptr& destination);

    // Resolution API helpers
    // General functions
    resolution_step_e get_next_resolution_step(resolution_step_e prev_step) const;

    // Manage the resolution table configuration
    la_status configure_ip_tunnel_destination_table();
    la_status teardown_ip_tunnel_destination_table();
};

} // namespace silicon_one

#endif // __LA_IP_TUNNEL_DESTINATION_IMPL_H__
