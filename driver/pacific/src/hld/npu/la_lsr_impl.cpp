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

#include "la_lsr_impl.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_mpls_nhlfe.h"
#include "api/npu/la_vrf.h"
#include "common/dassert.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "la_ecmp_group_impl.h"
#include "la_l3_protection_group_impl.h"
#include "la_mldp_vpn_decap_impl.h"
#include "la_mpls_multicast_group_impl.h"
#include "la_mpls_vpn_decap_impl.h"
#include "npu/la_next_hop_base.h"
#include "npu/la_prefix_object_base.h"

#include "resolution_utils.h"
#include "system/la_device_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_lsr_impl::la_lsr_impl(const la_device_impl_wptr& device) : m_device(device)
{
}

la_lsr_impl::~la_lsr_impl()
{
}

la_status
la_lsr_impl::initialize(la_object_id_t oid)
{
    m_oid = oid;
    return LA_STATUS_SUCCESS;
}

la_status
la_lsr_impl::destroy()
{
    return LA_STATUS_SUCCESS;
}

// la_object API-s
la_object::object_type_e
la_lsr_impl::type() const
{
    return la_object::object_type_e::LSR;
}

std::string
la_lsr_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_lsr_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_lsr_impl::oid() const
{
    return m_oid;
}

const la_device*
la_lsr_impl::get_device() const
{
    return m_device.get();
}

la_status
la_lsr_impl::do_add_route(la_mpls_label label,
                          const la_vrf_gid_t vrf_gid,
                          const la_l3_destination_wcptr& destination,
                          la_user_data_t user_data)
{
    if (destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(this, destination)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    entry_info_map_t::const_iterator it = m_entry_info_map.find(label);

    if (it != m_entry_info_map.end()) {
        return LA_STATUS_EEXIST;
    }

    la_status status = do_set_route(label, vrf_gid, destination);
    return_on_error(status);

    // Add a dependency
    m_device->add_object_dependency(destination, this);

    // Add to own hash
    internal_mpls_route_info entry_info;

    entry_info.destination = destination;
    entry_info.user_data = user_data;
    entry_info.vrf_gid = vrf_gid;
    m_entry_info_map.insert(entry_info_map_t::value_type(label, entry_info));

    return LA_STATUS_SUCCESS;
}

la_status
la_lsr_impl::add_route(la_mpls_label label, const la_l3_destination* destination, la_user_data_t user_data)
{
    start_api_call("label=", label, "destination=", destination, "user_data=", user_data);

    auto destination_sptr = m_device->get_sptr(destination);

    la_status status = do_add_route(label, LA_VRF_GID_INVALID, destination_sptr, user_data);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_lsr_impl::add_route(la_mpls_label label, const la_vrf* vrf, const la_l3_destination* destination, la_user_data_t user_data)
{
    start_api_call("label=", label, "vrf=", vrf, "destination=", destination, "user_data=", user_data);

    if (vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    auto destination_sptr = m_device->get_sptr(destination);

    la_status status = do_add_route(label, vrf->get_gid(), destination_sptr, user_data);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_lsr_impl::modify_route(la_mpls_label label, const la_l3_destination* destination)
{
    start_api_call("label=", label, "destination=", destination);

    if (destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(destination, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    entry_info_map_t::iterator it = m_entry_info_map.find(label);
    if (it == m_entry_info_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    auto old_destination = it->second.destination;
    auto vrf_gid = it->second.vrf_gid;

    if (old_destination == destination) {
        return LA_STATUS_SUCCESS;
    }

    auto destination_sptr = m_device->get_sptr(destination);

    la_status status = do_set_route(label, vrf_gid, destination_sptr);
    return_on_error(status);

    it->second.destination = destination_sptr;
    m_device->add_object_dependency(destination_sptr, this);
    status = uninstantiate_resolution_object(old_destination, RESOLUTION_STEP_FORWARD_MPLS);
    m_device->remove_object_dependency(old_destination, this);

    return status;
}

la_status
la_lsr_impl::do_set_route(la_mpls_label label, const la_vrf_gid_t vrf_gid, const la_l3_destination_wcptr& destination)
{
    transaction txn;

    la_object::object_type_e dest_type = destination->type();

    if ((dest_type != la_object::object_type_e::MPLS_NHLFE) && (dest_type != la_object::object_type_e::PREFIX_OBJECT)
        && (dest_type != la_object::object_type_e::DESTINATION_PE)
        && (dest_type != la_object::object_type_e::FEC)
        && (dest_type != la_object::object_type_e::ECMP_GROUP)
        && (dest_type != la_object::object_type_e::PBTS_GROUP)
        && (dest_type != la_object::object_type_e::MPLS_MULTICAST_GROUP)) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (dest_type == object_type_e::ECMP_GROUP) {
        auto ecmp_group = destination.weak_ptr_static_cast<const la_ecmp_group_impl>();
        if (ecmp_group->get_ecmp_level() != la_ecmp_group::level_e::LEVEL_1) {
            return LA_STATUS_EINVAL;
        }
    }

    if (dest_type == object_type_e::PREFIX_OBJECT) {
        auto pfx_obj = destination.weak_ptr_static_cast<const la_prefix_object_base>();
        if (!pfx_obj->is_resolution_forwarding_supported()) {
            return LA_STATUS_EINVAL;
        }
    }

    txn.status = instantiate_resolution_object(destination, RESOLUTION_STEP_FORWARD_MPLS);
    return_on_error(txn.status);
    txn.on_fail([=]() { uninstantiate_resolution_object(destination, RESOLUTION_STEP_FORWARD_MPLS); });

    if (dest_type == la_object::object_type_e::MPLS_NHLFE) {
        // Add to device table
        auto nhlfe = destination.weak_ptr_static_cast<const la_mpls_nhlfe>();
        if (vrf_gid == LA_VRF_GID_INVALID) {
            txn.status = set_label_unicast_entry_nhlfe(label, nhlfe);
            return_on_error(txn.status);
        } else {
            txn.status = set_label_vrf_unicast_entry_nhlfe(label, vrf_gid, nhlfe);
            return_on_error(txn.status);
            txn.on_fail([=]() { erase_route(label, vrf_gid); });

            txn.status = set_label_unicast_entry_nhlfe(label, nhlfe);
            return_on_error(txn.status);
        }
    }

    if ((dest_type == la_object::object_type_e::PREFIX_OBJECT) || (dest_type == la_object::object_type_e::ECMP_GROUP)
        || (dest_type == la_object::object_type_e::DESTINATION_PE)
        || (dest_type == la_object::object_type_e::PBTS_GROUP)
        || (dest_type == la_object::object_type_e::FEC)
        || (dest_type == la_object::object_type_e::MPLS_MULTICAST_GROUP)) {
        if (vrf_gid == LA_VRF_GID_INVALID) {
            txn.status = set_label_unicast_entry_headend(label, destination);
            return_on_error(txn.status);
        } else {
            txn.status = set_label_vrf_unicast_entry_headend(label, vrf_gid, destination);
            return_on_error(txn.status);
            txn.on_fail([=]() { erase_route(label, vrf_gid); });

            txn.status = set_label_unicast_entry_headend(label, destination);
            return_on_error(txn.status);
        }
    }

    return LA_STATUS_SUCCESS;
}

npl_nhlfe_type_e
la_lsr_impl::get_nhlfe_type(la_mpls_label label1, la_mpls_label label2)
{
    npl_nhlfe_type_e type;

    if (label1.label == LA_MPLS_LABEL_IMPLICIT_NULL) {
        if (label2.label == LA_MPLS_LABEL_IMPLICIT_NULL) {
            type = NPL_NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_IMPLICIT_MP_SWP;
        } else {
            type = NPL_NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_IMPLICIT_SWP;
        }
    } else {
        if (label2.label == LA_MPLS_LABEL_IMPLICIT_NULL) {
            type = NPL_NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_IMPLICIT_MP;
        } else {
            type = NPL_NHLFE_TYPE_MIDPOINT_TUNNEL_PROTECTION_FULL;
        }
    }

    return type;
}

la_status
la_lsr_impl::set_label_unicast_entry_nhlfe(la_mpls_label label, const la_mpls_nhlfe_wcptr& nhlfe)
{
    const auto& table(m_device->m_tables.mpls_forwarding_table);
    npl_mpls_forwarding_table_key_t key;
    npl_mpls_forwarding_table_value_t value;
    npl_mpls_forwarding_table_entry_t* entry;
    npl_nhlfe_t& npl_nhlfe(value.payloads.nhlfe);

    key.label = label.label;

    la_status status = populate_fwd_mpls_forwarding_table_nhlfe(nhlfe, npl_nhlfe);
    return_on_error(status);

    status = table->set(key, value, entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_lsr_impl::set_label_vrf_unicast_entry_nhlfe(la_mpls_label label, const la_vrf_gid_t vrf_gid, const la_mpls_nhlfe_wcptr& nhlfe)
{
    const auto& table(m_device->m_tables.per_vrf_mpls_forwarding_table);
    npl_per_vrf_mpls_forwarding_table_key_t key;
    npl_per_vrf_mpls_forwarding_table_value_t value;
    npl_per_vrf_mpls_forwarding_table_entry_t* entry;
    npl_nhlfe_t& npl_nhlfe(value.payloads.nhlfe);

    key.label = label.label;
    key.vrf_id.id = vrf_gid;

    la_status status = populate_fwd_mpls_forwarding_table_nhlfe(nhlfe, npl_nhlfe);
    return_on_error(status);

    status = table->set(key, value, entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_lsr_impl::set_label_unicast_entry_headend(la_mpls_label label, const la_l3_destination_wcptr& destination)
{
    const auto& table(m_device->m_tables.mpls_forwarding_table);
    npl_mpls_forwarding_table_key_t key;
    npl_mpls_forwarding_table_value_t value;
    npl_mpls_forwarding_table_entry_t* entry;

    key.label = label.label;

    npl_nhlfe_t& npl_nhlfe(value.payloads.nhlfe);

    destination_id dest_id = silicon_one::get_destination_id(destination, RESOLUTION_STEP_FORWARD_MPLS);
    if (dest_id == DESTINATION_ID_INVALID) {
        return LA_STATUS_EUNKNOWN;
    }

    npl_nhlfe.type = NPL_NHLFE_TYPE_TE_HEADEND;
    npl_nhlfe.nhlfe_payload.te_headend.lsp_destination.val = dest_id.val;

    la_status status = table->set(key, value, entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_lsr_impl::set_label_vrf_unicast_entry_headend(la_mpls_label label,
                                                 const la_vrf_gid_t vrf_gid,
                                                 const la_l3_destination_wcptr& destination)
{
    const auto& table(m_device->m_tables.per_vrf_mpls_forwarding_table);
    npl_per_vrf_mpls_forwarding_table_key_t key;
    npl_per_vrf_mpls_forwarding_table_value_t value;
    npl_per_vrf_mpls_forwarding_table_entry_t* entry;

    key.label = label.label;
    key.vrf_id.id = vrf_gid;

    npl_nhlfe_t& npl_nhlfe(value.payloads.nhlfe);

    destination_id dest_id = silicon_one::get_destination_id(destination, RESOLUTION_STEP_FORWARD_MPLS);
    if (dest_id == DESTINATION_ID_INVALID) {
        return LA_STATUS_EUNKNOWN;
    }

    npl_nhlfe.type = NPL_NHLFE_TYPE_TE_HEADEND;
    npl_nhlfe.nhlfe_payload.te_headend.lsp_destination.val = dest_id.val;

    la_status status = table->set(key, value, entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_lsr_impl::populate_fwd_mpls_forwarding_table_nhlfe(const la_mpls_nhlfe_wcptr& nhlfe, npl_nhlfe_t& npl_nhlfe)
{
    const la_l3_destination* destination = nhlfe->get_destination();
    destination_id dest_id;

    la_next_hop_gid_t nh_gid = LA_L3_DESTINATION_GID_INVALID;
    la_l3_protection_group_gid_t l3_prot_gid = la_l3_protection_group_impl::LA_L3_PROTECTION_GROUP_GID_INVALID;
    la_l3_destination_gid_t l3_dlp_gid = LA_L3_DESTINATION_GID_INVALID;
    la_l3_destination_gid_t pfx_gid = LA_L3_DESTINATION_GID_INVALID;
    la_object::object_type_e dest_type = destination->type();
    uint32_t npl_dsp = 0;

    switch (dest_type) {
    case la_object::object_type_e::NEXT_HOP: {
        dest_id = silicon_one::get_destination_id(destination, RESOLUTION_STEP_FORWARD_MPLS);
        if (dest_id == DESTINATION_ID_INVALID) {
            return LA_STATUS_EUNKNOWN;
        }

        const la_next_hop_base* nh = static_cast<const la_next_hop_base*>(destination);
        nh_gid = nh->get_gid();
    }; break;

    case la_object::object_type_e::L3_PROTECTION_GROUP: {
        dest_id = silicon_one::get_destination_id(destination, RESOLUTION_STEP_FORWARD_MPLS);
        if (dest_id == DESTINATION_ID_INVALID) {
            return LA_STATUS_EUNKNOWN;
        }

        const la_l3_protection_group_impl* l3_prot = static_cast<const la_l3_protection_group_impl*>(destination);
        l3_prot_gid = l3_prot->get_gid();
    }; break;

    case la_object::object_type_e::PREFIX_OBJECT: {
        if (nhlfe->get_action() != la_mpls_action_e::L2_ADJACENCY) {
            break;
        }
        const la_prefix_object_base* pfx = static_cast<const la_prefix_object_base*>(destination);
        pfx_gid = pfx->get_gid();

        const la_next_hop_base* nh = static_cast<const la_next_hop_base*>(pfx->get_destination());
        nh_gid = nh->get_gid();
        la_next_hop::nh_type_e nh_type;
        la_status status = nh->get_nh_type(nh_type);
        return_on_error(status);
        if (nh_type != la_next_hop::nh_type_e::NORMAL) {
            npl_dsp = (uint32_t)la_2_npl_nh_type(nh_type);
            break;
        }

        la_l3_port* l3_port;
        status = nh->get_router_port(l3_port);
        return_on_error(status);
        if (l3_port == nullptr) {
            return LA_STATUS_ENOTIMPLEMENTED;
        }
        l3_dlp_gid = l3_port->get_gid();

        const la_system_port* dsp = nhlfe->get_destination_system_port();
        dassert_crit(dsp != nullptr);
        npl_dsp = dsp->get_gid();
    }; break;

    default:
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    la_mpls_action_e nhlfe_type = nhlfe->get_action();

    if (nhlfe_type == la_mpls_action_e::POP) {
        npl_nhlfe.type = NPL_NHLFE_TYPE_MIDPOINT_PHP;
        npl_nhlfe.nhlfe_payload.te_midpoint.midpoint_nh = nh_gid;
        return LA_STATUS_SUCCESS;
    }

    if (nhlfe_type == la_mpls_action_e::SWAP) {
        la_mpls_label new_label = nhlfe->get_label();
        npl_nhlfe.type = NPL_NHLFE_TYPE_MIDPOINT_SWAP;
        npl_nhlfe.nhlfe_payload.te_midpoint.midpoint_nh = nh_gid;
        npl_nhlfe.nhlfe_payload.te_midpoint.lsp.swap_label = new_label.label;
        return LA_STATUS_SUCCESS;
    }

    if (nhlfe_type == la_mpls_action_e::TUNNEL_PROTECTION) {
        la_mpls_label te_label = nhlfe->get_label();
        la_mpls_label mp_label = nhlfe->get_merge_point_label();
        npl_nhlfe.type = get_nhlfe_type(te_label, mp_label);
        npl_nhlfe.nhlfe_payload.te_midpoint.midpoint_nh = l3_prot_gid;
        npl_nhlfe.nhlfe_payload.te_midpoint.lsp.swap_label = te_label.label;
        npl_nhlfe.nhlfe_payload.te_midpoint.mp_label = mp_label.label;
        return LA_STATUS_SUCCESS;
    }

    if (nhlfe_type == la_mpls_action_e::L2_ADJACENCY) {
        npl_nhlfe.type = NPL_NHLFE_TYPE_L2_ADJ_SID;
        npl_nhlfe.nhlfe_payload.l2_adj_sid.l3_dlp_nh_encap.l3_dlp = get_l3_dlp_encap(l3_dlp_gid);
        npl_nhlfe.nhlfe_payload.l2_adj_sid.l3_dlp_nh_encap.l3_dlp.properties.monitor_or_l3_dlp_ip_type.l3_dlp_ip_type
            = NPL_IPV4_L3_DLP;
        npl_nhlfe.nhlfe_payload.l2_adj_sid.l3_dlp_nh_encap.nh = nh_gid;
        npl_nhlfe.nhlfe_payload.l2_adj_sid.prefix = pfx_gid;
        npl_nhlfe.nhlfe_payload.l2_adj_sid.dsp = npl_dsp;
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_lsr_impl::erase_route(const la_mpls_label label, const la_vrf_gid_t vrf_gid)
{
    if (vrf_gid == LA_VRF_GID_INVALID) {
        // Remove from the table
        const auto& table(m_device->m_tables.mpls_forwarding_table);
        npl_mpls_forwarding_table_key_t key;

        key.label = label.label;

        la_status status = table->erase(key);
        return_on_error(status);
    } else {
        // Remove from the table
        const auto& table(m_device->m_tables.per_vrf_mpls_forwarding_table);
        npl_per_vrf_mpls_forwarding_table_key_t key;

        key.label = label.label;
        key.vrf_id.id = vrf_gid;

        la_status status = table->erase(key);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_lsr_impl::delete_route(la_mpls_label label)
{
    start_api_call("label=", label);

    entry_info_map_t::iterator it = m_entry_info_map.find(label);

    if (it == m_entry_info_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }
    auto info = it->second;

    la_status status = erase_route(label, info.vrf_gid);
    return_on_error(status);

    if (info.vrf_gid != LA_VRF_GID_INVALID) {
        status = erase_route(label, LA_VRF_GID_INVALID);
        return_on_error(status);
    }

    // Remove LSR dependency
    status = uninstantiate_resolution_object(info.destination, RESOLUTION_STEP_FORWARD_MPLS);
    return_on_error(status);

    m_device->remove_object_dependency(info.destination, this);

    // Remove from own hash
    m_entry_info_map.erase(it);

    return status;
}

la_status
la_lsr_impl::clear_all_routes()
{
    start_api_call("");

    // clear all the routes in the mpls forwarding table
    const auto& table(m_device->m_tables.mpls_forwarding_table);
    npl_mpls_forwarding_table_entry_t* entry;

    while (true) {
        size_t num_of_entries = table->get_entries(&entry, 1);
        if (num_of_entries == 0) {
            break;
        }

        npl_mpls_forwarding_table_key_t key = entry->key();

        la_mpls_label label;
        label.label = key.label;

        la_status status = delete_route(label);
        return_on_error(status);
    }

    // clear all the routes in the vrf mpls_forwarding table
    const auto& vrf_table(m_device->m_tables.per_vrf_mpls_forwarding_table);
    npl_per_vrf_mpls_forwarding_table_entry_t* vrf_entry;

    while (true) {
        size_t num_of_entries = vrf_table->get_entries(&vrf_entry, 1);
        if (num_of_entries == 0) {
            break;
        }

        npl_per_vrf_mpls_forwarding_table_key_t vrf_key = vrf_entry->key();

        la_mpls_label label;
        label.label = vrf_key.label;

        la_status status = delete_route(label);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_lsr_impl::get_route(la_mpls_label label, la_mpls_route_info& out_mpls_route_info) const
{
    entry_info_map_t::const_iterator it = m_entry_info_map.find(label);

    if (it == m_entry_info_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    auto info = it->second;
    out_mpls_route_info.destination = info.destination.get();
    out_mpls_route_info.vrf_gid = info.vrf_gid;
    out_mpls_route_info.user_data = info.user_data;

    return LA_STATUS_SUCCESS;
}

la_status
la_lsr_impl::add_vpn_decap(la_mpls_label label, const la_vrf* vrf, la_mpls_vpn_decap*& out_mpls_vpn_decap)
{
    start_api_call("label=", label, "vrf=", vrf);

    la_mpls_vpn_decap_impl_wptr decap;
    auto vrf_sptr = m_device->get_sptr(vrf);
    auto status = m_device->create_mpls_vpn_decap(label, vrf_sptr, decap);
    return_on_error(status);

    out_mpls_vpn_decap = decap.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_lsr_impl::modify_vpn_decap(la_mpls_label label, const la_vrf* vrf, la_mpls_vpn_decap* mpls_vpn_decap)
{
    start_api_call("label=", label, "vrf=", vrf, "mpls_vpn_decap=", mpls_vpn_decap);

    return LA_STATUS_SUCCESS;
}

la_status
la_lsr_impl::add_vpn_decap(la_mpls_label label,
                           const la_vrf* vrf,
                           la_uint_t rpfid,
                           bool bud_node,
                           la_mldp_vpn_decap*& out_mldp_vpn_decap)

{
    start_api_call("label=", label, "vrf=", vrf, "rpfid=", rpfid, "bud_node=", bud_node);

    la_mldp_vpn_decap_impl_wptr decap;
    auto vrf_sptr = m_device->get_sptr(vrf);
    auto status = m_device->create_mldp_terminate(label, vrf_sptr, rpfid, bud_node, decap);
    return_on_error(status);

    out_mldp_vpn_decap = decap.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_lsr_impl::modify_vpn_decap(la_mpls_label label,
                              const la_vrf* vrf,
                              la_uint_t rpfid,
                              bool bud_node,
                              la_mldp_vpn_decap* mldp_vpn_decap)
{
    start_api_call("label=", label, "vrf=", vrf, "rpfid=", rpfid, "bud_node=", bud_node, "mldp_vpn_decap=", mldp_vpn_decap);

    la_mldp_vpn_decap_impl* decap = static_cast<la_mldp_vpn_decap_impl*>(mldp_vpn_decap);

    if (decap == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(decap, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto vrf_sptr = m_device->get_sptr(vrf);
    auto status = m_device->modify_mldp_terminate(label, vrf_sptr, rpfid, bud_node, decap);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_lsr_impl::delete_vpn_decap(la_mpls_vpn_decap* mpls_vpn_decap)
{
    start_api_call("mpls_vpn_decap=", mpls_vpn_decap);
    la_mpls_vpn_decap_impl* decap = static_cast<la_mpls_vpn_decap_impl*>(mpls_vpn_decap);

    if (decap == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(decap, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    return m_device->destroy(decap);
}

la_status
la_lsr_impl::delete_vpn_decap(la_mldp_vpn_decap* mldp_vpn_decap)
{
    start_api_call("mldp_vpn_decap=", mldp_vpn_decap);
    la_mldp_vpn_decap_impl* decap = static_cast<la_mldp_vpn_decap_impl*>(mldp_vpn_decap);

    if (decap == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(decap, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    return m_device->destroy(decap);
}

} // namespace silicon_one
