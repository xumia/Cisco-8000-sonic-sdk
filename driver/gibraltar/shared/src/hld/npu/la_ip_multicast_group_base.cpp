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

#include <sstream>

#include "api/npu/la_mpls_multicast_group.h"
#include "api/system/la_spa_port.h"
#include "api/types/la_ethernet_types.h"
#include "npu/la_counter_set_impl.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_ip_multicast_group_base.h"
#include "npu/la_l2_multicast_group_base.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_stack_port_base.h"
#include "npu/la_svi_port_base.h"
#include "npu/la_vrf_impl.h"
#include "npu/resolution_utils.h"
#include "system/cud_range_manager.h"
#include "system/la_device_impl.h"
#include "system/la_system_port_base.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "la_strings.h"

#include "npu/la_mpls_multicast_group_impl.h"

namespace silicon_one
{

la_ip_multicast_group_base::la_ip_multicast_group_base(la_device_impl_wptr device)
    : m_device(device),
      m_gid((la_multicast_group_gid_t)-1),
      m_local_mcid((la_multicast_group_gid_t)-1),
      m_is_scale_mode_smcid(false),
      m_slice_use_count{0},
      m_mcg_counter_device_id(LA_DEVICE_ID_INVALID),
      m_is_mcg_counter_allocated(false)
{
}

la_ip_multicast_group_base::~la_ip_multicast_group_base()
{
}

la_status
la_ip_multicast_group_base::initialize(la_object_id_t oid,
                                       la_multicast_group_gid_t multicast_gid,
                                       la_replication_paradigm_e rep_paradigm)
{
    m_oid = oid;
    transaction txn;

    m_gid = multicast_gid;
    m_rep_paradigm = rep_paradigm;

    // set the local_mcid based on the multicast_gid
    if (m_device->is_scale_mode_smcid(m_gid)) {
        if (m_device->is_reserved_smcid(m_gid)) {
            m_is_scale_mode_smcid = false;
            // reserved MCIDs get the reserved local MCID values
            txn.status = m_device->multicast_reserved_smcid_to_local_mcid(m_gid, m_local_mcid);
            return_on_error(txn.status);
        } else {
            m_is_scale_mode_smcid = true;
            // For scaled mode MCIDs the local MCID will get allocated when
            // the first member is added.
            // use to fabric mcid for the first pass
            m_local_mcid = NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE;
        }
    } else {
        // non-scaled mode MCIDs have the local_mcid == smcid
        m_local_mcid = multicast_gid;
    }

    txn.status = m_device->create_multicast_group_common(m_mc_common);
    return_on_error(txn.status);

    txn.status = m_mc_common->initialize(m_gid, m_local_mcid, rep_paradigm, m_is_scale_mode_smcid);
    return_on_error(txn.status);
    txn.on_fail([=]() { m_mc_common->destroy(); });

    if (m_device->is_reserved_smcid(m_gid) && (m_gid != la_device_impl::MULTICAST_RESERVED_SMCID_TO_FABRIC_SLICE)) {
        // On the egress linecard the reserved MCIDs require the system port to
        // be added as a member. The reserved fabric slice MCID is only used on
        // ingress linecard and does not require a system port.
        la_system_port_wcptr system_recycle_port;

        txn.status = m_device->get_system_recycle_port(m_gid, system_recycle_port);
        return_on_error(txn.status);
        auto system_recycle_port_base = la_system_port_base::upcast_from_api(m_device, system_recycle_port);

        // add a null member for the recycle port on this multicast reserved group
        member_t member(la_l3_port_wcptr{nullptr}, la_l2_destination_wcptr{nullptr});
        txn.status = do_add(member, system_recycle_port_base);
        return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    // Removing in reverse order is easier - see remove_mc_em_db_entry_egress_rep()
    std::vector<member_t> temp(m_members);
    std::reverse_iterator<std::vector<member_t>::iterator> rit;
    for (rit = temp.rbegin(); rit != temp.rend(); rit++) {
        auto member = *rit;
        la_status status = do_remove(member);
        return_on_error(status);
    }

    la_status status = m_mc_common->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_ip_multicast_group_base::type() const
{
    return la_object::object_type_e::IP_MULTICAST_GROUP;
}

std::string
la_ip_multicast_group_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_ip_multicast_group_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_ip_multicast_group_base::oid() const
{
    return m_oid;
}

const la_device*
la_ip_multicast_group_base::get_device() const
{
    return m_device.get();
}

la_multicast_group_gid_t
la_ip_multicast_group_base::get_gid() const
{
    return m_gid;
}

la_multicast_group_gid_t
la_ip_multicast_group_base::get_local_mcid() const
{
    return m_local_mcid;
}

size_t
la_ip_multicast_group_base::get_slice_bitmap() const
{
    return m_mc_common->get_slice_bitmap();
}

la_status
la_ip_multicast_group_base::configure_egress_rep(const member_t& member, const la_system_port_base_wcptr& dsp, uint64_t mc_copy_id)
{
    // Configure MC EM DB
    auto adsp = get_actual_dsp(dsp);
    la_status status = m_mc_common->configure_egress_rep_common(member, adsp, mc_copy_id);

    return status;
}

la_status
la_ip_multicast_group_base::teardown_egress_rep(const member_t& member, const la_system_port_base_wcptr& dsp)
{
    auto adsp = get_actual_dsp(dsp);
    la_status status = m_mc_common->teardown_egress_rep_common(member, adsp);

    return status;
}

la_status
la_ip_multicast_group_base::verify_parameters(const la_l3_port_wcptr& l3_port,
                                              const la_l2_port_wcptr& l2_port,
                                              const la_system_port_base_wcptr& dsp) const
{
    la_status status = verify_parameters(l3_port, l2_port);
    return_on_error(status);

    la_ethernet_port_wcptr eth;
    if (l3_port->type() == la_object::object_type_e::SVI_PORT) {
        auto ac_port = std::static_pointer_cast<const la_l2_service_port_base>(l2_port.lock());
        eth = ac_port->get_ethernet_port();
    } else {
        auto ac_port = std::static_pointer_cast<const la_l3_ac_port>(l3_port.lock());
        eth = m_device->get_sptr(ac_port->get_ethernet_port());
    }

    status = m_mc_common->verify_dsp(eth, dsp);

    return status;
}

la_status
la_ip_multicast_group_base::verify_parameters(const la_l3_port_wcptr& l3_port, const la_l2_port_wcptr& l2_port) const
{
    if (l3_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(l3_port, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (l3_port->type() == la_object::object_type_e::SVI_PORT) {
        if (l2_port == nullptr) {
            return LA_STATUS_EINVAL;
        }

        if (!of_same_device(l2_port, this)) {
            return LA_STATUS_EDIFFERENT_DEVS;
        }

        if (l2_port->type() != la_object::object_type_e::L2_SERVICE_PORT) {
            return LA_STATUS_ENOTIMPLEMENTED;
        }

        auto ac_port = std::static_pointer_cast<const la_l2_service_port_base>(l2_port.lock());
        if (ac_port->get_port_type() != la_l2_service_port_base::port_type_e::AC) {
            return LA_STATUS_ENOTIMPLEMENTED;
        }
    } else {
        dassert_crit(l3_port->type() == la_object::object_type_e::L3_AC_PORT);
        if (l2_port != nullptr) {
            auto l2_ac = std::static_pointer_cast<const la_l2_service_port_base>(l2_port.lock());
            if (!((l2_ac != nullptr) && (l2_ac->get_port_type() == la_l2_service_port_base::port_type_e::VXLAN))) {
                return LA_STATUS_EINVAL;
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::register_mc_ipv4_vrf_route(la_vrf_impl_sptr vrf_impl,
                                                       const la_ipv4_addr_t saddr,
                                                       const la_ipv4_addr_t gaddr)
{
    if (!m_is_scale_mode_smcid) {
        // only scale mode MCIDs need to track the routes using the group
        return LA_STATUS_SUCCESS;
    }

    auto vrf_route = v4_key_t(vrf_impl, saddr, gaddr);
    auto it = m_mc_ipv4_vrf_routes.find(vrf_route);
    if (it != m_mc_ipv4_vrf_routes.end()) {
        return LA_STATUS_EUNKNOWN;
    }
    m_mc_ipv4_vrf_routes.insert(vrf_route);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::unregister_mc_ipv4_vrf_route(const la_vrf_impl_sptr vrf_impl,
                                                         const la_ipv4_addr_t saddr,
                                                         const la_ipv4_addr_t gaddr)
{
    if (!m_is_scale_mode_smcid) {
        // only scale mode MCIDs need to track the routes using the group
        return LA_STATUS_SUCCESS;
    }

    auto vrf_route = v4_key_t(vrf_impl, saddr, gaddr);
    auto it = m_mc_ipv4_vrf_routes.find(vrf_route);
    if (it == m_mc_ipv4_vrf_routes.end()) {
        return LA_STATUS_EUNKNOWN;
    }
    m_mc_ipv4_vrf_routes.erase(it);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::register_mc_ipv6_vrf_route(const la_vrf_impl_sptr vrf_impl,
                                                       const la_ipv6_addr_t saddr,
                                                       const la_ipv6_addr_t gaddr)
{
    if (!m_is_scale_mode_smcid) {
        // only scale mode MCIDs need to track the routes using the group
        return LA_STATUS_SUCCESS;
    }

    auto vrf_route = v6_key_t(vrf_impl, saddr, gaddr);
    auto it = m_mc_ipv6_vrf_routes.find(vrf_route);
    if (it != m_mc_ipv6_vrf_routes.end()) {
        return LA_STATUS_EEXIST;
    }
    m_mc_ipv6_vrf_routes.insert(vrf_route);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::unregister_mc_ipv6_vrf_route(const la_vrf_impl_sptr vrf_impl,
                                                         const la_ipv6_addr_t saddr,
                                                         const la_ipv6_addr_t gaddr)
{
    if (!m_is_scale_mode_smcid) {
        // only scale mode MCIDs need to track the routes using the group
        return LA_STATUS_SUCCESS;
    }

    auto vrf_route = v6_key_t(vrf_impl, saddr, gaddr);
    auto it = m_mc_ipv6_vrf_routes.find(vrf_route);
    if (it == m_mc_ipv6_vrf_routes.end()) {
        return LA_STATUS_ENOTFOUND;
    }
    m_mc_ipv6_vrf_routes.erase(it);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::update_mc_ipv4_vrf_routes()
{
    for (auto vrf_route : m_mc_ipv4_vrf_routes) {
        la_status status;
        const auto& vrf_impl = std::get<0>(vrf_route);
        la_ipv4_addr_t saddr = std::get<1>(vrf_route);
        la_ipv4_addr_t gaddr = std::get<2>(vrf_route);
        status = vrf_impl->update_ipv4_multicast_route(saddr, gaddr);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::update_mc_ipv6_vrf_routes()
{
    for (auto vrf_route : m_mc_ipv6_vrf_routes) {
        la_status status;
        auto vrf_impl = std::get<0>(vrf_route);
        la_ipv6_addr_t saddr = std::get<1>(vrf_route);
        la_ipv6_addr_t gaddr = std::get<2>(vrf_route);
        status = vrf_impl->update_ipv6_multicast_route(saddr, gaddr);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::do_add(const member_t& member, const la_system_port_base_wcptr& dsp)
{
    transaction txn;

    auto it = std::find(m_members.begin(), m_members.end(), member);
    if (it != m_members.end()) {
        return LA_STATUS_EEXIST;
    }

    if (m_is_scale_mode_smcid && (m_members.size() == 0)) {
        // the first member is being added, check if local mcid is allocated,
        // if not, allocate mcid and update ipv4 and ipv6 routes
        uint64_t local_mcid;
        if (m_device->m_index_generators.local_mcids.allocate(local_mcid)) {
            m_local_mcid = local_mcid;
            txn.on_fail([=]() { m_device->m_index_generators.local_mcids.release(local_mcid); });
        } else {
            log_err(HLD, "Unable to allocate a local MCID");
            return LA_STATUS_ERESOURCE;
        }
        m_mc_common->set_local_mcid(m_local_mcid);

        // update all the IPv4 VRF routes with the new local MCID
        txn.status = update_mc_ipv4_vrf_routes();
        return_on_error(txn.status);
        txn.on_fail([=]() {
            m_local_mcid = NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE;
            update_mc_ipv4_vrf_routes();
        });

        // update all the IPv6 VRF routes with the new local MCID
        txn.status = update_mc_ipv6_vrf_routes();
        return_on_error(txn.status);
        txn.on_fail([=]() {
            m_local_mcid = NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE;
            update_mc_ipv6_vrf_routes();
        });
    }

    uint64_t mc_copy_id;
    la_slice_id_t dest_slice = (member.counter != nullptr) ? member.counter_slice_ifg.slice : get_actual_dsp_slice(dsp);
    txn.status = allocate_mc_copy_id(member, dest_slice, mc_copy_id);
    return_on_error(txn.status);
    txn.on_fail([=]() { release_mc_copy_id(member, dest_slice); });

    txn.status = configure_cud_mapping(member, dest_slice, mc_copy_id);
    return_on_error(txn.status);
    txn.on_fail([=]() {
        teardown_cud_mapping(member, dest_slice, mc_copy_id);
        release_mc_copy_id(member, dest_slice);
    });

    // individual port member always configure egress rep
    txn.status = configure_egress_rep(member, dsp, mc_copy_id);
    return_on_error(txn.status);
    txn.on_fail([=]() { teardown_egress_rep(member, dsp); });

    // Object dependencies
    if (dsp != nullptr) {
        m_device->add_object_dependency(dsp, this);
    }

    if (member.l3_port != nullptr) {
        m_device->add_object_dependency(member.l3_port, this);
    }

    if (member.l2_dest != nullptr) {
        m_device->add_object_dependency(member.l2_dest, this);
    }

    if (member.stackport != nullptr) {
        m_device->add_object_dependency(member.stackport, this);
    }

    txn.on_fail([=]() {
        if (dsp != nullptr) {
            m_device->remove_object_dependency(dsp, this);
        }

        if (member.l3_port != nullptr) {
            m_device->remove_object_dependency(member.l3_port, this);
        }

        if (member.l2_dest != nullptr) {
            m_device->remove_object_dependency(member.l2_dest, this);
        }

        if (member.stackport != nullptr) {
            m_device->remove_object_dependency(member.stackport, this);
        }
    });

    txn.status = process_slice_addition(dest_slice);
    return_on_error(txn.status);

    // Store
    if (dsp != nullptr) {
        dassert_crit(m_dsp_mapping.find(member) == m_dsp_mapping.end());
        m_dsp_mapping[member] = dsp;
    }

    m_members.push_back(member);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::add(const la_l3_port* l3_port,
                                const la_l2_port* vxlan_port,
                                la_next_hop* next_hop,
                                const la_system_port* dsp)
{
    start_api_call("l3_port=", l3_port, "vxlan_port=", vxlan_port, "next_hop=", next_hop, "dsp=", dsp);
    la_l3_port_wcptr l3_port_wptr = nullptr;
    la_l3_port_wcptr l3_nh_port_wptr;
    la_status status;

    la_l2_port_wcptr l2_port_wptr = m_device->get_sptr(vxlan_port);
    la_system_port_base_wcptr dsp_wptr = la_system_port_base::upcast_from_api(m_device, dsp);

    // l3_port should be null when we have vxlan port
    dassert_crit(l3_port == nullptr);
    dassert_crit(vxlan_port != nullptr);

    // Use next hop router port as l3 port for the member
    la_l3_port* l3_nh_port;
    status = next_hop->get_router_port(l3_nh_port);
    return_on_error(status);

    l3_nh_port_wptr = m_device->get_sptr(l3_nh_port);
    status = verify_parameters(l3_nh_port_wptr, l2_port_wptr, dsp_wptr);
    return_on_error(status);

    auto l2_dest = std::static_pointer_cast<const la_l2_destination>(l2_port_wptr.lock());
    member_t member(l3_port_wptr, l2_dest);
    member.next_hop = m_device->get_sptr(next_hop);
    member.vxlan_type = la_multicast_group_common_base::vxlan_type_e::L3_VXLAN;

    status = do_add(member, dsp_wptr);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::add(const la_l3_port* l3_port, const la_l2_port* l2_port, const la_system_port* dsp)
{
    start_api_call("l3_port=", l3_port, "l2_port=", l2_port, "dsp=", dsp);

    la_l3_port_wcptr l3_port_wptr = m_device->get_sptr(l3_port);
    la_l2_port_wcptr l2_port_wptr = m_device->get_sptr(l2_port);

    auto dsp_wptr = la_system_port_base::upcast_from_api(m_device, dsp);

    la_status status = verify_parameters(l3_port_wptr, l2_port_wptr, dsp_wptr);
    return_on_error(status);

    auto l2_dest = std::static_pointer_cast<const la_l2_destination>(l2_port_wptr.lock());
    member_t member(l3_port_wptr, l2_dest);

    status = do_add(member, dsp_wptr);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::add(const la_stack_port* stackport, const la_system_port* dsp)
{
    start_api_call("stackport=", stackport, "dsp=", dsp);

    la_stack_port_wcptr stackport_wptr = m_device->get_sptr(stackport);
    la_system_port_base_wcptr dsp_wptr = la_system_port_base::upcast_from_api(m_device, dsp);

    if (stackport_wptr == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(stackport_wptr, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    member_t member(stackport_wptr);

    auto it = std::find(m_members.begin(), m_members.end(), member);
    if (it != m_members.end()) {
        return LA_STATUS_EEXIST;
    }

    if (dsp_wptr == nullptr) {
        return LA_STATUS_EINVAL;
    }

    auto stackport_base = m_device->get_sptr<la_stack_port_base>(stackport);
    if (!stackport_base->is_member(dsp_wptr)) {
        return LA_STATUS_EINVAL;
    }

    return do_add(member, dsp_wptr);
}

la_status
la_ip_multicast_group_base::do_remove(const member_t& member)
{
    transaction txn;

    if (is_mcg_member(member)) {
        la_status status = do_remove_mcg_member(member);
        return status;
    }

    auto members_it = std::find(m_members.begin(), m_members.end(), member);
    if (members_it == m_members.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    // Get destination system port
    la_system_port_base_wcptr dsp;
    if (member.counter == nullptr) { // Not relevant for MCG counter special member case
        auto dsp_it = m_dsp_mapping.find(member);
        if (dsp_it == m_dsp_mapping.end()) {
            log_err(HLD, "member <%s> not found in dsp mapping", member.to_string().c_str());

            return LA_STATUS_EUNKNOWN;
        }

        dsp = dsp_it->second;
    } else {
        const auto& counter_impl = member.counter.weak_ptr_static_cast<la_counter_set_impl>();
        txn.status = counter_impl->remove_mcg_counter(member.counter_slice_ifg);
        return_on_error(txn.status);
    }

    // Get MC copy ID
    la_slice_id_t dest_slice = (member.counter != nullptr) ? member.counter_slice_ifg.slice : get_actual_dsp_slice(dsp);
    auto mc_copy_id_it = m_mc_copy_id_mapping[dest_slice].find(member);
    if (mc_copy_id_it == m_mc_copy_id_mapping[dest_slice].end()) {
        log_err(HLD, "member <%s> not found in mc_copy_id mapping", member.to_string().c_str());

        return LA_STATUS_EUNKNOWN;
    }
    uint64_t mc_copy_id = mc_copy_id_it->second;

    txn.status = teardown_egress_rep(member, dsp);
    return_on_error(txn.status);
    txn.on_fail([=]() { configure_egress_rep(member, dsp, mc_copy_id); });

    // Remove object dependencies
    if (dsp != nullptr) {
        m_device->remove_object_dependency(dsp, this);
    }

    if (member.l3_port != nullptr) {
        m_device->remove_object_dependency(member.l3_port, this);
    }

    if (member.l2_dest != nullptr) {
        m_device->remove_object_dependency(member.l2_dest, this);
    }

    txn.on_fail([=]() {
        if (member.l2_dest != nullptr) {
            m_device->add_object_dependency(member.l2_dest, this);
        }
        if (member.l3_port != nullptr) {
            m_device->add_object_dependency(member.l3_port, this);
        }
        if (dsp != nullptr) {
            m_device->add_object_dependency(dsp, this);
        }
    });

    // Teardown CUD mapping
    txn.status = teardown_cud_mapping(member, dest_slice, mc_copy_id);
    return_on_error(txn.status);
    txn.on_fail([=]() { configure_cud_mapping(member, dest_slice, mc_copy_id); });

    txn.status = process_slice_removal(dest_slice);
    return_on_error(txn.status);

    // Release MC copy ID last, so rollback is easy.
    txn.status = release_mc_copy_id(member, dest_slice);
    return_on_error(txn.status);

    if (m_is_scale_mode_smcid && (m_members.size() == 1)) {
        // the last member was removed
        uint64_t old_local_mcid = m_local_mcid;

        // update all the IPv4 VRF routes with the invalid local MCID
        m_local_mcid = NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE;
        txn.status = update_mc_ipv4_vrf_routes();
        return_on_error(txn.status);
        txn.on_fail([=]() {
            m_local_mcid = old_local_mcid;
            update_mc_ipv4_vrf_routes();
        });

        // update all the IPv6 VRF routes with the invalid local MCID
        txn.status = update_mc_ipv6_vrf_routes();
        return_on_error(txn.status);
        txn.on_fail([=]() {
            m_local_mcid = old_local_mcid;
            update_mc_ipv6_vrf_routes();
        });

        // release the local mcid
        m_device->m_index_generators.local_mcids.release(old_local_mcid);

        // set the local MCID to invalid
        m_mc_common->set_local_mcid(m_local_mcid);

        // on failure restore the old local mcid
        txn.on_fail([=]() {
            uint64_t dummy;
            m_device->m_index_generators.local_mcids.allocate(old_local_mcid, dummy);
            m_mc_common->set_local_mcid(old_local_mcid);
            m_local_mcid = old_local_mcid;
        });
    }

    if (dsp != nullptr) {
        m_dsp_mapping.erase(member);
    }
    m_members.erase(members_it);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::remove(const la_l3_port* l3_port, const la_l2_port* l2_port)
{
    start_api_call("l3_port=", l3_port, "l2_port=", l2_port);
    la_l3_port_wcptr l3_port_wptr = m_device->get_sptr(l3_port);
    la_l2_port_wcptr l2_port_wptr = m_device->get_sptr(l2_port);

    auto l2_dest = std::static_pointer_cast<const la_l2_destination>(l2_port_wptr.lock());
    member_t member(l3_port_wptr, l2_dest);

    la_status status;

    if (l3_port == nullptr) {
        auto it = std::find(m_members.begin(), m_members.end(), member);
        if (it == m_members.end()) {
            return LA_STATUS_ENOTFOUND;
        }
        la_l3_port* l3_nh_port;
        status = it->next_hop->get_router_port(l3_nh_port);
        return_on_error(status);

        la_l3_port_wcptr l3_nh_port_wptr = m_device->get_sptr(l3_nh_port);
        la_status status = verify_parameters(l3_nh_port_wptr, l2_port_wptr);
        return_on_error(status);

    } else {
        status = verify_parameters(l3_port_wptr, l2_port_wptr);
        return_on_error(status);
    }

    status = do_remove(member);
    return_on_error(status);

    member.is_punt = true;
    auto punt_it = std::find(m_members.begin(), m_members.end(), member);
    if (punt_it == m_members.end()) {
        return LA_STATUS_SUCCESS;
    }

    status = do_remove(member);
    return status;
}

la_status
la_ip_multicast_group_base::remove(const la_stack_port* stackport)
{
    start_api_call("stackport=", stackport);

    la_stack_port_wcptr stackport_wptr = m_device->get_sptr(stackport);

    if (stackport_wptr == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(stackport_wptr, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    member_t member(stackport_wptr);

    auto it = std::find(m_members.begin(), m_members.end(), member);
    if (it != m_members.end()) {
        return LA_STATUS_EEXIST;
    }

    return do_remove(member);
}

bool
la_ip_multicast_group_base::is_mcg_member(const member_t& member) const
{
    if ((member.ip_mcg != nullptr) || (member.l2_mcg != nullptr) || (member.mpls_mcg != nullptr)) {
        return true;
    } else {
        return false;
    }
}

void
la_ip_multicast_group_base::get_non_mcg_member_list(std::vector<member_t>& out_member_list) const
{
    for (auto it = m_members.begin(); it != m_members.end(); it++) {
        if (!(is_mcg_member(*it))) {
            out_member_list.push_back(*it);
        }
    }
}

size_t
la_ip_multicast_group_base::get_non_mcg_member_size() const
{
    std::vector<member_t> non_mcg_members;
    get_non_mcg_member_list(non_mcg_members);
    return (non_mcg_members.size());
}

void
la_ip_multicast_group_base::get_non_punt_and_counter_member_list(std::vector<member_t>& out_member_list) const
{
    for (auto it = m_members.begin(); it != m_members.end(); it++) {
        if ((it->is_punt == false) && (it->counter == nullptr) && (it->ip_mcg != this)) {
            out_member_list.push_back(*it);
        }
    }
}

la_status
la_ip_multicast_group_base::get_member(size_t member_idx, member_info& out_member) const
{
    start_api_getter_call();

    // Filter out members only used for egress member punt or counter
    std::vector<member_t> non_punt_members;
    get_non_punt_and_counter_member_list(non_punt_members);

    if (member_idx >= non_punt_members.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    auto& member = non_punt_members[member_idx];
    out_member.l3_port = member.l3_port.get();
    out_member.l2_port = static_cast<const la_l2_port*>(member.l2_dest.get());
    out_member.l2_mcg = member.l2_mcg.get();
    out_member.ip_mcg = member.ip_mcg.get();
    out_member.mpls_mcg = member.mpls_mcg.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::get_size(size_t& out_size) const
{
    start_api_getter_call();

    // Filter out members only used for egress member punt or counter
    std::vector<member_t> non_punt_members;
    get_non_punt_and_counter_member_list(non_punt_members);
    out_size = non_punt_members.size();

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::get_replication_paradigm(la_replication_paradigm_e& out_replication_paradigm) const
{
    start_api_getter_call();
    out_replication_paradigm = m_rep_paradigm;
    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::get_destination_system_port(const la_l3_port* l3_port,
                                                        const la_l2_port* l2_port,
                                                        const la_system_port*& out_dsp) const
{
    start_api_getter_call();

    la_l3_port_wcptr l3_port_wptr = m_device->get_sptr(l3_port);
    la_l2_port_wcptr l2_port_wptr = m_device->get_sptr(l2_port);

    la_status status = verify_parameters(l3_port_wptr, l2_port_wptr);
    return_on_error(status);

    auto l2_dest = std::static_pointer_cast<const la_l2_destination>(l2_port_wptr.lock());
    auto dsp_it = m_dsp_mapping.find(member_t(l3_port_wptr, l2_dest));
    if (dsp_it == m_dsp_mapping.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    auto dsp = dsp_it->second;

    out_dsp = dsp.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::do_set_destination_system_port(const member_t& member, const la_system_port_base_wcptr& dsp)
{
    auto dsp_in = la_system_port_base::upcast_from_api(m_device, dsp);
    transaction txn;

    auto dsp_it = m_dsp_mapping.find(member);
    if (dsp_it == m_dsp_mapping.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    auto curr_dsp = la_system_port_base::upcast_from_api(m_device, dsp_it->second);
    la_slice_id_t curr_slice = curr_dsp->get_slice();

    // Get the current MC copy ID
    auto mc_copy_id_it = m_mc_copy_id_mapping[curr_slice].find(member);
    dassert_crit(mc_copy_id_it != m_mc_copy_id_mapping[curr_slice].end());
    uint64_t mc_copy_id = mc_copy_id_it->second;

    if (curr_slice == dsp_in->get_slice()) {
        // DSPs are on the same slice
        auto adsp = get_actual_dsp(dsp);
        txn.status = m_mc_common->set_member_dsp(member, curr_dsp, adsp, mc_copy_id, mc_copy_id);
        return_on_error(txn.status);

        m_device->remove_object_dependency(curr_dsp, this);
        m_device->add_object_dependency(dsp, this);
        // Replace the current DSP
        m_dsp_mapping[member] = dsp;

        return LA_STATUS_SUCCESS;
    }

    // DSPs are not on the same slice. Need to configure CUD on the new slice
    uint64_t new_mc_copy_id;
    la_slice_id_t dest_slice = get_actual_dsp_slice(dsp);
    txn.status = allocate_mc_copy_id(member, dest_slice, new_mc_copy_id);
    return_on_error(txn.status);
    txn.on_fail([=]() { release_mc_copy_id(member, dest_slice); });

    txn.status = configure_cud_mapping(member, dsp->get_slice(), new_mc_copy_id);
    return_on_error(txn.status);
    txn.on_fail([=]() { teardown_cud_mapping(member, dsp->get_slice(), new_mc_copy_id); });

    auto adsp = get_actual_dsp(dsp);
    txn.status = m_mc_common->set_member_dsp(member, curr_dsp, adsp, mc_copy_id, new_mc_copy_id);
    return_on_error(txn.status);
    txn.on_fail([=]() { m_mc_common->set_member_dsp(member, adsp, curr_dsp, new_mc_copy_id, mc_copy_id); });

    // Teardown old CUD mapping
    txn.status = teardown_cud_mapping(member, curr_dsp->get_slice(), mc_copy_id);
    return_on_error(txn.status);
    txn.on_fail([=]() { configure_cud_mapping(member, curr_dsp->get_slice(), mc_copy_id); });

    // Release old MC copy ID
    la_slice_id_t curr_dest_slice = get_actual_dsp_slice(curr_dsp);
    txn.status = release_mc_copy_id(member, curr_dest_slice);
    return_on_error(txn.status);

    txn.status = process_slice_removal(curr_slice);
    return_on_error(txn.status);

    txn.status = process_slice_addition(dest_slice);
    return_on_error(txn.status);

    m_device->remove_object_dependency(curr_dsp, this);
    m_device->add_object_dependency(dsp, this);
    // Replace the current DSP
    m_dsp_mapping[member] = dsp;

    return LA_STATUS_SUCCESS;
}
la_status
la_ip_multicast_group_base::set_destination_system_port(const la_l3_port* l3_port,
                                                        const la_l2_port* l2_port,
                                                        const la_system_port* dsp)
{
    start_api_call("l3_port=", l3_port, "l2_port=", l2_port, "dsp=", dsp);

    la_l3_port_wcptr l3_port_wptr = m_device->get_sptr(l3_port);
    la_l2_port_wcptr l2_port_wptr = m_device->get_sptr(l2_port);
    la_system_port_base_wcptr dsp_wptr = la_system_port_base::upcast_from_api(m_device, dsp);

    la_status status = verify_parameters(l3_port_wptr, l2_port_wptr, dsp_wptr);
    return_on_error(status);

    auto l2_dest = std::static_pointer_cast<const la_l2_destination>(l2_port_wptr.lock());
    member_t member(l3_port_wptr, l2_dest);
    status = do_set_destination_system_port(member, dsp_wptr);

    member.is_punt = true;
    auto it = std::find(m_members.begin(), m_members.end(), member);
    if (it == m_members.end()) {
        return LA_STATUS_SUCCESS;
    }

    status = do_set_destination_system_port(member, dsp_wptr);

    return status;
}

la_status
la_ip_multicast_group_base::set_punt_enabled(const la_l3_port* l3_port, const la_l2_port* l2_port, bool punt_enabled)
{
    start_api_call("l3_port=", l3_port, "l2_port=", l2_port, "punt_enabled=", punt_enabled);
    la_l3_port_wcptr l3_port_wptr = m_device->get_sptr(l3_port);
    la_l2_port_wcptr l2_port_wptr = m_device->get_sptr(l2_port);

    transaction txn;

    la_status status = verify_parameters(l3_port_wptr, l2_port_wptr);
    return_on_error(status);

    // Search for original member - if not found, return error
    auto l2_dest = std::static_pointer_cast<const la_l2_destination>(l2_port_wptr.lock());
    member_t member(l3_port_wptr, l2_dest, false /* is_punt */);
    auto member_it = std::find(m_members.begin(), m_members.end(), member);
    if (member_it == m_members.end()) {
        return LA_STATUS_ENOTFOUND;
    }
    auto dsp = m_dsp_mapping[member];

    // Search for punt copy member
    member.is_punt = true;
    auto punt_member_it = std::find(m_members.begin(), m_members.end(), member);
    if (punt_member_it != m_members.end() && punt_enabled) {
        // If enabling and punt copy member already present - success
        return LA_STATUS_SUCCESS;
    }
    if (punt_member_it == m_members.end() && !punt_enabled) {
        // If disabling and puny copy member already not present - success
        return LA_STATUS_SUCCESS;
    }

    if (punt_enabled) {
        status = do_add(member, dsp);
        return_on_error(status);
    } else {
        status = do_remove(member);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::get_punt_enabled(const la_l3_port* l3_port, const la_l2_port* l2_port, bool& out_punt_enabled) const
{
    start_api_getter_call();
    la_l3_port_wcptr l3_port_wptr = m_device->get_sptr(l3_port);
    la_l2_port_wcptr l2_port_wptr = m_device->get_sptr(l2_port);

    auto l2_dest = std::static_pointer_cast<const la_l2_destination>(l2_port_wptr.lock());
    member_t tmp_member(l3_port_wptr, l2_dest, false);
    auto it = std::find(m_members.begin(), m_members.end(), tmp_member);
    if (it == m_members.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    tmp_member.is_punt = true;
    auto punt_it = std::find(m_members.begin(), m_members.end(), tmp_member);
    if (punt_it == m_members.end()) {
        out_punt_enabled = false;
    } else {
        out_punt_enabled = true;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::set_egress_counter(la_device_id_t device_id, la_counter_set* counter_set)
{
    start_api_call("device_id=", device_id, "counter_set=", counter_set);

    auto counter_impl = m_device->get_sptr<la_counter_set_impl>(counter_set);

    if ((counter_impl != nullptr) && (!of_same_device(counter_impl, m_device))) {
        log_err(HLD, "la_counter_set device doesn't match la_ip_multicast_group device");
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if ((counter_impl != nullptr) && (counter_impl->get_set_size() != 1)) {
        log_err(HLD, "MCG counter_impl size must be == 1");
        return LA_STATUS_EINVAL;
    }

    bool is_dev_id_match = true;
    if (device_id != m_device->get_id()) {
        // This set function may be called on other devices in case of distributed systems.
        // No action is required in this case.
        log_debug(
            HLD, "Requested device ID (%u) for MCG counter doesn't match the local device ID (%u)", device_id, m_device->get_id());
        is_dev_id_match = false;
    }

    transaction txn;
    if ((counter_impl == nullptr) || (m_counter != nullptr)) {
        // Remove current MCG counter
        if (m_counter != nullptr) {
            if (m_is_mcg_counter_allocated) {
                for (auto it = m_members.begin(); it != m_members.end(); it++) {
                    if (it->counter == m_counter) {
                        auto member = *it;
                        txn.status = do_remove(member);
                        return_on_error(txn.status);
                        break;
                    }
                }
                m_is_mcg_counter_allocated = false;
            }
            m_device->remove_object_dependency(m_counter, this);
            m_counter = nullptr;
        }

        if (counter_impl == nullptr) {
            m_mcg_counter_device_id = device_id;
            return LA_STATUS_SUCCESS;
        }
    }

    if (is_dev_id_match) {
        la_slice_ifg slice_ifg;
        txn.status = counter_impl->add_mcg_counter(slice_ifg);
        return_on_error(txn.status);
        txn.on_fail([=]() { counter_impl->remove_mcg_counter(slice_ifg); });

        member_t member(counter_impl, slice_ifg);

        txn.status = do_add(member, nullptr /* dsp */);
        return_on_error(txn.status);

        m_is_mcg_counter_allocated = true;
    }

    m_mcg_counter_device_id = device_id;
    m_counter = counter_impl;
    m_device->add_object_dependency(m_counter, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::get_egress_counter(la_device_id_t& out_device_id, la_counter_set*& out_counter) const
{
    start_api_getter_call();

    out_device_id = m_mcg_counter_device_id;
    out_counter = m_counter.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::add(const la_svi_port* svi_port, la_l2_multicast_group* l2_mcg)
{
    start_api_call("svi_port=", svi_port, "l2_mcg=", l2_mcg);

    if (m_rep_paradigm == la_replication_paradigm_e::EGRESS) {
        log_err(HLD,
                "la_l2_multicast_group cannot be added as a member to "
                "la_ip_multicast_group with la_replication_paradigm_e::EGRESS");
        return LA_STATUS_EINVAL;
    }

    if ((svi_port == nullptr) || (l2_mcg == nullptr)) {
        log_err(HLD, "svi_port or l2_mcg is invalid");
        return LA_STATUS_EINVAL;
    }

    const la_l3_port* l3_port = static_cast<const la_l3_port*>(svi_port);
    la_l3_port_wcptr l3_port_wptr = m_device->get_sptr(l3_port);
    la_l2_multicast_group_wptr l2_mcg_wptr = m_device->get_sptr(l2_mcg);
    member_t member(l3_port_wptr, l2_mcg_wptr);

    la_status status = verify_parameters(member);
    return_on_error(status);

    status = do_add_mcg_member(member);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::remove(const la_svi_port* svi_port, la_l2_multicast_group* l2_mcg)
{
    start_api_call("svi_port=", svi_port, "l2_mcg=", l2_mcg);

    if (m_rep_paradigm == la_replication_paradigm_e::EGRESS) {
        log_err(HLD,
                "la_l2_multicast_group cannot be removed as a member from"
                "la_ip_multicast_group with la_replication_paradigm_e::EGRESS");
        return LA_STATUS_EINVAL;
    }

    if ((svi_port == nullptr) || (l2_mcg == nullptr)) {
        log_err(HLD, "svi_port or l2_mcg is invalid");
        return LA_STATUS_EINVAL;
    }

    const la_l3_port* l3_port = static_cast<const la_l3_port*>(svi_port);
    la_l3_port_wcptr l3_port_wptr = m_device->get_sptr(l3_port);
    la_l2_multicast_group_wptr l2_mcg_wptr = m_device->get_sptr(l2_mcg);
    member_t member(l3_port_wptr, l2_mcg_wptr);

    la_status status = do_remove(member);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

// Adding ingress-ipmcg to ingress-ipmcg is not restricted, but MCID that is derived from route lookup
// result will be the one, used as key to read into MC-EM-DB in RXPP.
la_status
la_ip_multicast_group_base::add(const la_ip_multicast_group* ip_mcg)
{
    start_api_call("ip_mcg=", ip_mcg);

    if (m_rep_paradigm == la_replication_paradigm_e::EGRESS) {
        log_err(HLD,
                "la_ip_multicast_group cannot be added as a member to "
                "la_ip_multicast_group with la_replication_paradigm_e::EGRESS");
        return LA_STATUS_EINVAL;
    }

    if (ip_mcg == nullptr) {
        log_err(HLD, "ip_mcg is invalid");
        return LA_STATUS_EINVAL;
    }

    la_ip_multicast_group_wcptr ip_mcg_wptr = m_device->get_sptr(ip_mcg);

    la_multicast_group_gid_t mcid = ip_mcg_wptr->get_gid();
    if (m_device->is_scale_mode_smcid(mcid)) {
        log_err(HLD,
                "la_ip_multicast_group with scaled mcid cannot be added as a member to "
                "la_ip_multicast_group with la_replication_paradigm_e::INGRESS");
        return LA_STATUS_EINVAL;
    }

    member_t member(ip_mcg_wptr);

    la_status status = do_add_mcg_member(member);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::remove(const la_ip_multicast_group* ip_mcg)
{
    start_api_call("ip_mcg=", ip_mcg);

    if (m_rep_paradigm == la_replication_paradigm_e::EGRESS) {
        log_err(HLD,
                "la_ip_multicast_group cannot be removed as a member from "
                "la_ip_multicast_group with la_replication_paradigm_e::EGRESS");
        return LA_STATUS_EINVAL;
    }

    if (ip_mcg == nullptr) {
        log_err(HLD, "ip_mcg is invalid");
        return LA_STATUS_EINVAL;
    }

    la_ip_multicast_group_wcptr ip_mcg_wptr = m_device->get_sptr(ip_mcg);
    member_t member(ip_mcg_wptr);

    la_status status = do_remove(member);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::add(const la_mpls_multicast_group* mpls_mcg)
{
    start_api_call("mpls_mcg=", mpls_mcg);

    if (m_rep_paradigm != la_replication_paradigm_e::INGRESS) {
        log_err(
            HLD,
            "la_mpls_multicast_group cannot be added as a member to la_ip_multicast_group with la_replication_paradigm_e::EGRESS");
        return LA_STATUS_EINVAL;
    }

    if (mpls_mcg == nullptr) {
        log_err(HLD, "mpls_mcg is invalid");
        return LA_STATUS_EINVAL;
    }

    la_mpls_multicast_group_wcptr mpls_mcg_wptr = m_device->get_sptr(mpls_mcg);
    member_t member(mpls_mcg_wptr);

    la_status status = do_add_mcg_member(member);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::remove(const la_mpls_multicast_group* mpls_mcg)
{
    start_api_call("mpls_mcg=", mpls_mcg);

    if (m_rep_paradigm != la_replication_paradigm_e::INGRESS) {
        log_err(HLD,
                "la_mpls_multicast_group cannot be removed as a member from la_ip_multicast_group with "
                "la_replication_paradigm_e::EGRESS");
        return LA_STATUS_EINVAL;
    }

    if (mpls_mcg == nullptr) {
        log_err(HLD, "mpls_mcg is invalid");
        return LA_STATUS_EINVAL;
    }

    la_mpls_multicast_group_wcptr mpls_mcg_wptr = m_device->get_sptr(mpls_mcg);
    member_t member(mpls_mcg_wptr);

    la_status status = do_remove(member);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::do_add_mcg_member(const member_t& member)
{

    transaction txn;

    auto it = std::find(m_members.begin(), m_members.end(), member);
    if (it != m_members.end()) {
        return LA_STATUS_EEXIST;
    }

    if (m_is_scale_mode_smcid && (m_members.size() == 0)) {
        // the first member is being added, check if local mcid is allocated,
        // if not, allocate mcid and update ipv4 and ipv6 routes
        uint64_t local_mcid;
        if (m_device->m_index_generators.local_mcids.allocate(local_mcid)) {
            m_local_mcid = local_mcid;
            txn.on_fail([=]() { m_device->m_index_generators.local_mcids.release(local_mcid); });
        } else {
            log_err(HLD, "Unable to allocate a local MCID");
            return LA_STATUS_ERESOURCE;
        }
        m_mc_common->set_local_mcid(m_local_mcid);

        // update all the IPv4 VRF routes with the new local MCID
        txn.status = update_mc_ipv4_vrf_routes();
        return_on_error(txn.status);
        txn.on_fail([=]() {
            m_local_mcid = NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE;
            update_mc_ipv4_vrf_routes();
        });

        // update all the IPv6 VRF routes with the new local MCID
        txn.status = update_mc_ipv6_vrf_routes();
        return_on_error(txn.status);
        txn.on_fail([=]() {
            m_local_mcid = NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE;
            update_mc_ipv6_vrf_routes();
        });
    }

    txn.status = configure_ingress_rep(member);
    return_on_error(txn.status);
    txn.on_fail([=]() { teardown_ingress_rep(member); });

    if (member.l2_mcg != nullptr) {
        la_l2_multicast_group_base* l2_mcg_base = static_cast<la_l2_multicast_group_base*>(member.l2_mcg.get());
        txn.status = l2_mcg_base->transition_copyid_range(member.l3_port);
        return_on_error(txn.status, API, ERROR, "Transition of l2_mcg members to CUD mapping range failed");
        txn.on_fail([=]() { l2_mcg_base->transition_copyid_range((la_l3_port_wcptr{nullptr})); });
    }

    // Object dependencies
    bit_vector registered_attributes((la_uint64_t)attribute_management_op::MCG_MEMBER_LIST_CHANGED);
    if (member.l3_port != nullptr) {
        m_device->add_object_dependency(member.l3_port, this);
    }

    if (member.l2_mcg != nullptr) {
        m_device->add_object_dependency(member.l2_mcg, this);
        m_device->add_attribute_dependency(member.l2_mcg, this, registered_attributes);
    }

    if (member.ip_mcg != nullptr) {
        m_device->add_object_dependency(member.ip_mcg, this);
        m_device->add_attribute_dependency(member.ip_mcg, this, registered_attributes);
    }

    if (member.mpls_mcg != nullptr) {
        m_device->add_object_dependency(member.mpls_mcg, this);
        m_device->add_attribute_dependency(member.mpls_mcg, this, registered_attributes);
    }

    txn.on_fail([=]() {
        if (member.l3_port != nullptr) {
            m_device->remove_object_dependency(member.l3_port, this);
        }

        if (member.l2_mcg != nullptr) {
            m_device->remove_attribute_dependency(member.l2_mcg, this, registered_attributes);
            m_device->remove_object_dependency(member.l2_mcg, this);
        }

        if (member.ip_mcg != nullptr) {
            m_device->remove_attribute_dependency(member.ip_mcg, this, registered_attributes);
            m_device->remove_object_dependency(member.ip_mcg, this);
        }

        if (member.mpls_mcg != nullptr) {
            m_device->remove_attribute_dependency(member.mpls_mcg, this, registered_attributes);
            m_device->remove_object_dependency(member.mpls_mcg, this);
        }
    });

    m_members.push_back(member);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::do_remove_mcg_member(const member_t& member)
{
    transaction txn;
    // Skip the self egress-group member as it will be removed when the last non-mcg
    // member gets deleted.
    if ((member.ip_mcg != nullptr) && (member.ip_mcg->get_gid() == m_gid)) {
        return LA_STATUS_SUCCESS;
    }

    auto members_it = std::find(m_members.begin(), m_members.end(), member);
    if (members_it == m_members.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    txn.status = teardown_ingress_rep(member);
    return_on_error(txn.status);
    txn.on_fail([=]() { configure_ingress_rep(member); });

    if (member.l2_mcg != nullptr) {
        la_l2_multicast_group_base* l2_mcg_base = static_cast<la_l2_multicast_group_base*>(member.l2_mcg.get());
        txn.status = l2_mcg_base->transition_copyid_range((la_l3_port_wcptr{nullptr}));
        return_on_error(txn.status, API, ERROR, "Transition of l2_mcg members to L2-DLP range failed");
        txn.on_fail([=]() { l2_mcg_base->transition_copyid_range(member.l3_port); });
    }

    // Remove object dependencies
    bit_vector registered_attributes((la_uint64_t)attribute_management_op::MCG_MEMBER_LIST_CHANGED);
    if (member.l3_port != nullptr) {
        m_device->remove_object_dependency(member.l3_port, this);
    }

    if (member.l2_mcg != nullptr) {
        m_device->remove_attribute_dependency(member.l2_mcg, this, registered_attributes);
        m_device->remove_object_dependency(member.l2_mcg, this);
    }

    if (member.ip_mcg != nullptr) {
        m_device->remove_attribute_dependency(member.ip_mcg, this, registered_attributes);
        m_device->remove_object_dependency(member.ip_mcg, this);
    }

    if (member.mpls_mcg != nullptr) {
        m_device->remove_attribute_dependency(member.mpls_mcg, this, registered_attributes);
        m_device->remove_object_dependency(member.mpls_mcg, this);
    }

    txn.on_fail([=]() {
        if (member.l2_mcg != nullptr) {
            m_device->add_object_dependency(member.l2_mcg, this);
            m_device->add_attribute_dependency(member.l2_mcg, this, registered_attributes);
        }
        if (member.l3_port != nullptr) {
            m_device->add_object_dependency(member.l3_port, this);
        }
        if (member.ip_mcg != nullptr) {
            m_device->add_object_dependency(member.ip_mcg, this);
            m_device->add_attribute_dependency(member.ip_mcg, this, registered_attributes);
        }
        if (member.mpls_mcg != nullptr) {
            m_device->add_object_dependency(member.mpls_mcg, this);
            m_device->add_attribute_dependency(member.mpls_mcg, this, registered_attributes);
        }
    });

    m_members.erase(members_it);

    if (m_is_scale_mode_smcid && (m_members.size() == 0)) {
        // the last member was removed
        uint64_t old_local_mcid = m_local_mcid;
        // update all the IPv4 VRF routes with the invalid local MCID
        m_local_mcid = NPL_MULTICAST_RESERVED_MCID_TO_FABRIC_SLICE;
        txn.status = update_mc_ipv4_vrf_routes();
        return_on_error(txn.status);
        txn.on_fail([=]() {
            m_local_mcid = old_local_mcid;
            update_mc_ipv4_vrf_routes();
        });

        // update all the IPv6 VRF routes with the invalid local MCID
        txn.status = update_mc_ipv6_vrf_routes();
        return_on_error(txn.status);
        txn.on_fail([=]() {
            m_local_mcid = old_local_mcid;
            update_mc_ipv6_vrf_routes();
        });

        // release the local mcid
        m_device->m_index_generators.local_mcids.release(old_local_mcid);

        // set the local MCID to invalid
        m_mc_common->set_local_mcid(m_local_mcid);

        // on failure restore the old local mcid
        txn.on_fail([=]() {
            uint64_t dummy;
            m_device->m_index_generators.local_mcids.allocate(old_local_mcid, dummy);
            m_mc_common->set_local_mcid(old_local_mcid);
            m_local_mcid = old_local_mcid;
        });
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::configure_ingress_rep(const member_t& member, la_slice_id_t slice)
{
    // Add rx entry to MC-EM-DB for (mem-mcid, slice)
    la_multicast_group_gid_t mem_mcid = m_mc_common->get_local_mcid(member);
    log_debug(HLD, "%s:%d: GID:0x%x: adding entry for mcid-slice 0x%x-%d", __func__, __LINE__, m_gid, mem_mcid, slice);
    la_status status = m_mc_common->configure_ingress_rep_common(member, slice);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::teardown_ingress_rep(const member_t& member, la_slice_id_t slice)
{
    la_multicast_group_gid_t mem_mcid = m_mc_common->get_local_mcid(member);
    log_debug(HLD, "%s:%d: GID:0x%x: removing entry for mcid-slice 0x%x-%d", __func__, __LINE__, m_gid, mem_mcid, slice);
    la_status status = m_mc_common->teardown_ingress_rep_common(member, slice);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::configure_ingress_rep(const member_t& member)
{
    la_status status = LA_STATUS_SUCCESS;
    size_t slice_bmp(0);

    if (member.ip_mcg != nullptr) {
        const la_ip_multicast_group_base* ip_mcg_base = static_cast<const la_ip_multicast_group_base*>(member.ip_mcg.get());
        slice_bmp = ip_mcg_base->get_slice_bitmap();
    } else if (member.l2_mcg != nullptr) {
        const la_l2_multicast_group_base* l2_mcg_base = static_cast<const la_l2_multicast_group_base*>(member.l2_mcg.get());
        slice_bmp = l2_mcg_base->get_slice_bitmap();
    } else if (member.mpls_mcg != nullptr) {
        const la_mpls_multicast_group_impl* mpls_mcg_impl = static_cast<const la_mpls_multicast_group_impl*>(member.mpls_mcg.get());
        slice_bmp = mpls_mcg_impl->get_slice_bitmap();
    }

    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        for (size_t slice : m_device->get_used_slices()) {
            if (slice_bmp & (1 << slice)) {
                // add an entry only if there are any members in the slice
                status = configure_ingress_rep(member, slice);
                return_on_error(status);
            }
        }
    }

    // In distributed systems copy is always sent to fabric slice
    // rx entry to MC-EM-DB is added with (mcid, fabric-slice)
    if (m_device->m_device_mode == device_mode_e::LINECARD) {
        if (slice_bmp != 0) {
            status = configure_ingress_rep(member, la_multicast_group_common_base::FABRIC_SLICE);
            return_on_error(status);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::teardown_ingress_rep(const member_t& member)
{
    la_status status = LA_STATUS_SUCCESS;
    size_t slice_bmp(0);

    if (member.ip_mcg != nullptr) {
        const la_ip_multicast_group_base* ip_mcg_base = static_cast<const la_ip_multicast_group_base*>(member.ip_mcg.get());
        slice_bmp = ip_mcg_base->get_slice_bitmap();
    } else if (member.l2_mcg != nullptr) {
        const la_l2_multicast_group_base* l2_mcg_base = static_cast<const la_l2_multicast_group_base*>(member.l2_mcg.get());
        slice_bmp = l2_mcg_base->get_slice_bitmap();
    } else if (member.mpls_mcg != nullptr) {
        const la_mpls_multicast_group_impl* mpls_mcg_impl = static_cast<const la_mpls_multicast_group_impl*>(member.mpls_mcg.get());
        slice_bmp = mpls_mcg_impl->get_slice_bitmap();
    }

    if (m_device->m_device_mode == device_mode_e::STANDALONE) {
        for (size_t slice : m_device->get_used_slices()) {
            if (slice_bmp & (1 << slice)) {
                status = teardown_ingress_rep(member, slice);
                return_on_error(status);
            }
        }
    }
    if (m_device->m_device_mode == device_mode_e::LINECARD) {
        if (slice_bmp != 0) {
            status = teardown_ingress_rep(member, la_multicast_group_common_base::FABRIC_SLICE);
            return_on_error(status);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::set_replication_paradigm(la_replication_paradigm_e rep_paradigm)
{
    start_api_call("rep_paradigm=", rep_paradigm);

    if (m_rep_paradigm == rep_paradigm) {
        log_debug(API,
                  "rep_paradigm for la_ip_multicast_group is already %s",
                  ((m_rep_paradigm == la_replication_paradigm_e::INGRESS) ? "INGRESS" : "EGRESS"));
        return LA_STATUS_SUCCESS;
    }

    la_status status;
    member_t this_mem(m_device->get_sptr(this));

    status = verify_parameters(rep_paradigm);
    return_on_error(status);

    if (rep_paradigm == la_replication_paradigm_e::INGRESS) {
        // transition from Egress to Ingress
        log_debug(HLD, "%s:%d: GID: 0x%x: convert egress rep to ingress rep", __func__, __LINE__, m_gid);
        if (get_non_mcg_member_size() != 0) {
            status = configure_ingress_rep(this_mem);
            return_on_error(status);
        }
        m_rep_paradigm = rep_paradigm;
        m_mc_common->set_replication_paradigm(rep_paradigm);

        if (!m_is_scale_mode_smcid) {
            status = m_mc_common->configure_mc_slice_bitmap();
        } else {
            // scale mode need to check if it has member
            // if no member, don't have to set slice bitmap
            // as there is no local mcid yet
            if (m_members.size() != 0) {
                status = m_mc_common->configure_mc_slice_bitmap();
            }
        }
        return_on_error(status);
    } else {
        // transition from Ingress to Egress
        log_debug(HLD, "%s:%d: GID: 0x%x: convert ingress rep to egress rep", __func__, __LINE__, m_gid);
        m_rep_paradigm = rep_paradigm;
        m_mc_common->set_replication_paradigm(rep_paradigm);

        if (!m_is_scale_mode_smcid) {
            status = m_mc_common->configure_mc_slice_bitmap();
        } else {
            // scale mode need to check if it has member
            // if no member, don't have to set slice bitmap
            // as there is no local mcid yet
            if (m_members.size() != 0) {
                status = m_mc_common->configure_mc_slice_bitmap();
            }
        }
        return_on_error(status);
        if (get_non_mcg_member_size() != 0) {
            status = teardown_ingress_rep(this_mem);
            return_on_error(status);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::verify_parameters(member_t l2mcg_member) const
{
    // check if l2_mcg is added with anyother svi port
    for (member_t tmp_member : m_members) {
        if ((tmp_member.l2_mcg != nullptr) && (tmp_member.l2_mcg == l2mcg_member.l2_mcg)
            && (tmp_member.l3_port != l2mcg_member.l3_port)) {
            log_err(API,
                    "l2-mcg with GID 0x%x is already a member with SVI 0x%x",
                    tmp_member.l2_mcg->get_gid(),
                    tmp_member.l3_port->get_gid());
            return LA_STATUS_EINVAL;
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::verify_parameters(la_replication_paradigm_e rep_paradigm) const
{
    if (rep_paradigm == la_replication_paradigm_e::EGRESS) {
        for (auto it = m_members.begin(); it != m_members.end(); it++) {
            if (is_mcg_member(*it)) {
                auto member = *it;
                if ((member.ip_mcg != nullptr) && (member.ip_mcg->get_gid() == m_gid)) {
                    continue;
                } else {
                    log_err(API, "MC-Group[0x%x] contains other MC-Group as members, set_replication_paradigm() failed", m_gid);
                    return LA_STATUS_EINVAL;
                }
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::notify_change(dependency_management_op op)
{
    switch (op.type_e) {
    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT:
        switch (op.action.attribute_management.op) {
        case attribute_management_op::MCG_MEMBER_LIST_CHANGED:
            return handle_mcg_change_event(op);
        default:
            log_err(HLD, "la_ip_multicast_group_base::notify_change received unsupported attribute");
            return LA_STATUS_EUNKNOWN;
        }
        break;
    default:
        log_err(HLD,
                "la_ip_multicast_group_base::notify_change received unsupported notification (%s)",
                silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::handle_mcg_change_event(dependency_management_op op)
{
    la_multicast_group_gid_t member_gid = -1;

    member_t member;
    if (op.dependee->type() == object_type_e::IP_MULTICAST_GROUP) {
        const la_ip_multicast_group_base* ip_mcg_base = static_cast<const la_ip_multicast_group_base*>(op.dependee);
        member_gid = ip_mcg_base->get_local_mcid();

        const la_ip_multicast_group* ip_mcg = static_cast<const la_ip_multicast_group*>(op.dependee);
        la_ip_multicast_group_wcptr ip_mcg_wptr = m_device->get_sptr(ip_mcg);
        member.ip_mcg = ip_mcg_wptr;

    } else if (op.dependee->type() == object_type_e::L2_MULTICAST_GROUP) {
        const la_l2_multicast_group* l2mcg = static_cast<const la_l2_multicast_group*>(op.dependee);
        member_gid = l2mcg->get_gid();

        la_l2_multicast_group* l2_mcg = nullptr;
        la_status status = m_device->get_l2_multicast_group(member_gid, l2_mcg);
        return_on_error(status);

        la_l2_multicast_group_wptr l2_mcg_wptr = m_device->get_sptr(l2_mcg);
        member.l2_mcg = l2_mcg_wptr;
        member.l3_port = m_device->get_sptr(op.action.attribute_management.mcg_slice_update.l3_port);

    } else if (op.dependee->type() == object_type_e::MPLS_MULTICAST_GROUP) {
        const la_mpls_multicast_group* mplsmcg = static_cast<const la_mpls_multicast_group*>(op.dependee);
        member_gid = mplsmcg->get_gid();

        la_mpls_multicast_group* mpls_mcg = nullptr;
        la_status status = m_device->get_mpls_multicast_group(member_gid, mpls_mcg);
        return_on_error(status);

        la_mpls_multicast_group_wptr mpls_mcg_wptr = m_device->get_sptr(mpls_mcg);
        member.mpls_mcg = mpls_mcg_wptr;
    } else {
        log_err(HLD, "%s:%d: GID:0x%x: recevied mcg_change_notification for unsupported object", __func__, __LINE__, m_gid);
    }

    auto members_it = std::find(m_members.begin(), m_members.end(), member);
    if (members_it == m_members.end()) {
        log_err(HLD, "%s:%d: GID:0x%x: member<%s> not found", __func__, __LINE__, m_gid, member.to_string().c_str());
        return LA_STATUS_ENOTFOUND;
    }

    bool slice_added = op.action.attribute_management.mcg_slice_update.slice_added;
    la_slice_id_t slice = op.action.attribute_management.mcg_slice_update.slice;

    if (slice_added) {
        la_status status = configure_ingress_rep(member, slice);
        return_on_error(status,
                        HLD,
                        ERROR,
                        "%s:%d: GID:0x%x: handling slice_added notifiication from member_mcg: 0x%x failed(status= %s)",
                        __func__,
                        __LINE__,
                        m_gid,
                        member_gid,
                        la_status2str(status).c_str());
    } else {
        la_status status = teardown_ingress_rep(member, slice);
        return_on_error(status,
                        HLD,
                        ERROR,
                        "%s:%d: GID:0x%x: handling slice_removed notifiication from member_mcg: 0x%x failed(status= %s)",
                        __func__,
                        __LINE__,
                        m_gid,
                        member_gid,
                        la_status2str(status).c_str());
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::process_slice_addition(la_slice_id_t slice)
{
    la_status status = LA_STATUS_SUCCESS;
    if (m_rep_paradigm == la_replication_paradigm_e::EGRESS) {
        // When individual ports/counter is added to egress replication group, notify to all ingress
        // group in which this egress group is a member
        if (m_device->m_device_mode == device_mode_e::STANDALONE) {
            bool slice_added = add_slice_user(slice);
            if (slice_added) {
                status = notify_mcg_change_event(true, slice);
                return_on_error(status);
            }
        }
        if (m_device->m_device_mode == device_mode_e::LINECARD) {
            bool slice_added = add_slice_user(la_multicast_group_common_base::FABRIC_SLICE);
            if (slice_added) {
                status = notify_mcg_change_event(true, la_multicast_group_common_base::FABRIC_SLICE);
                return_on_error(status);
            }
        }
    } else {
        // When individual ports/counter is added to ingress replication group, add self-group and slice
        // to ingress group. Call configure_ingress_rep directly from here instead of do_add_mcg_member
        // to avoid the object dependency configurations.
        member_t this_mem(m_device->get_sptr(this));
        if (m_device->m_device_mode == device_mode_e::STANDALONE) {
            bool slice_added = add_slice_user(slice);
            if (slice_added) {
                status = configure_ingress_rep(this_mem, slice);
                return_on_error(status);
            }
        }
        if (m_device->m_device_mode == device_mode_e::LINECARD) {
            bool slice_added = add_slice_user(la_multicast_group_common_base::FABRIC_SLICE);
            if (slice_added) {
                status = configure_ingress_rep(this_mem, la_multicast_group_common_base::FABRIC_SLICE);
                return_on_error(status);
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::process_slice_removal(la_slice_id_t slice)
{
    la_status status = LA_STATUS_SUCCESS;
    if (m_rep_paradigm == la_replication_paradigm_e::EGRESS) {
        if (m_device->m_device_mode == device_mode_e::STANDALONE) {
            bool slice_removed = remove_slice_user(slice);
            if (slice_removed) {
                status = notify_mcg_change_event(false, slice);
                return_on_error(status);
            }
        }
        if (m_device->m_device_mode == device_mode_e::LINECARD) {
            bool slice_removed = remove_slice_user(la_multicast_group_common_base::FABRIC_SLICE);
            if (slice_removed) {
                status = notify_mcg_change_event(false, la_multicast_group_common_base::FABRIC_SLICE);
                return_on_error(status);
            }
        }
    } else {
        member_t this_mem(m_device->get_sptr(this));
        if (m_device->m_device_mode == device_mode_e::STANDALONE) {
            bool slice_removed = remove_slice_user(slice);
            if (slice_removed) {
                status = teardown_ingress_rep(this_mem, slice);
                return_on_error(status);
            }
        }
        if (m_device->m_device_mode == device_mode_e::LINECARD) {
            bool slice_removed = remove_slice_user(la_multicast_group_common_base::FABRIC_SLICE);
            if (slice_removed) {
                status = teardown_ingress_rep(this_mem, la_multicast_group_common_base::FABRIC_SLICE);
                return_on_error(status);
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_base::notify_mcg_change_event(bool slice_added, la_slice_id_t slice)
{
    attribute_management_details amd;
    amd.op = attribute_management_op::MCG_MEMBER_LIST_CHANGED;
    amd.mcg_slice_update.slice_added = slice_added;
    amd.mcg_slice_update.slice = slice;

    la_amd_undo_callback_funct_t undo = [](attribute_management_details amd) { return amd; };
    la_ip_multicast_group* ip_mcg = static_cast<la_ip_multicast_group*>(this);
    la_status status = m_device->notify_attribute_changed(ip_mcg, amd, undo);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD,
                "%s:%d: GID: 0x%x: mcg_change_notification failed(status = %s)",
                __func__,
                __LINE__,
                m_gid,
                la_status2str(status).c_str());
    }
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

bool
la_ip_multicast_group_base::add_slice_user(la_slice_id_t slice)
{
    bool new_slice_added = false;
    if (m_slice_use_count[slice] == 0) {
        new_slice_added = true;
    }
    m_slice_use_count[slice]++;
    return new_slice_added;
}

bool
la_ip_multicast_group_base::remove_slice_user(la_slice_id_t slice)
{
    bool slice_removed = false;
    dassert_crit(m_slice_use_count[slice] != 0);
    m_slice_use_count[slice]--;

    if (m_slice_use_count[slice] == 0) {
        slice_removed = true;
    }
    return slice_removed;
}

} // namespace silicon_one
