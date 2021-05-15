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

#include "api/npu/la_l3_ac_port.h"
#include "api/types/la_ethernet_types.h"
#include "la_mpls_multicast_group_impl.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_multicast_protection_group_base.h"
#include "npu/la_multicast_protection_monitor_base.h"
#include "npu/mc_copy_id_manager.h"
#include "resolution_utils.h"
#include "system/cud_range_manager.h"
#include "system/la_device_impl.h"
#include "system/la_system_port_base.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "la_strings.h"
#include "mc_copy_id_manager.h"

namespace silicon_one
{

la_mpls_multicast_group_impl::la_mpls_multicast_group_impl(la_device_impl_wptr device)
    : m_slice_use_count{0}, m_device(device), m_gid((la_multicast_group_gid_t)-1), m_punt_enabled(false)
{
}

la_mpls_multicast_group_impl::~la_mpls_multicast_group_impl()
{
}

la_status
la_mpls_multicast_group_impl::initialize(la_object_id_t oid,
                                         la_multicast_group_gid_t multicast_gid,
                                         la_replication_paradigm_e rep_paradigm)
{
    if (rep_paradigm == la_replication_paradigm_e::INGRESS) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    m_oid = oid;
    m_gid = multicast_gid;
    m_rep_paradigm = rep_paradigm;

    la_status status = m_device->create_multicast_group_common(m_mc_common);

    status = m_mc_common->initialize(multicast_gid, multicast_gid, rep_paradigm, false /* is_scale_mode_smcid */);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    // Removing in reverse order is easier - see remove_mc_em_db_entry_egress_rep()
    std::vector<member_t> temp(m_protected_members);
    std::reverse_iterator<std::vector<member_t>::iterator> rit;
    for (rit = temp.rbegin(); rit != temp.rend(); rit++) {
        auto member = *rit;
        la_status status = do_remove(member);
        return_on_error(status);
    }

    temp = m_members;
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
la_mpls_multicast_group_impl::type() const
{
    return la_object::object_type_e::MPLS_MULTICAST_GROUP;
}

std::string
la_mpls_multicast_group_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_mpls_multicast_group_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_mpls_multicast_group_impl::oid() const
{
    return m_oid;
}

const la_device*
la_mpls_multicast_group_impl::get_device() const
{
    return m_device.get();
}

la_multicast_group_gid_t
la_mpls_multicast_group_impl::get_gid() const
{
    return m_gid;
}

la_status
la_mpls_multicast_group_impl::configure_egress_rep(const member_t& member, const la_system_port_wcptr& dsp, uint64_t mc_copy_id)
{
    // Configure MC EM DB
    auto adsp = get_actual_dsp(dsp);
    la_status status = m_mc_common->configure_egress_rep_common(member, adsp, mc_copy_id);

    return status;
}

la_status
la_mpls_multicast_group_impl::teardown_egress_rep(const member_t& member, const la_system_port_wcptr& dsp)
{
    auto adsp = get_actual_dsp(dsp);
    la_status status = m_mc_common->teardown_egress_rep_common(member, adsp);

    return status;
}

la_status
la_mpls_multicast_group_impl::verify_parameters(const la_prefix_object_wcptr& pfx_obj, const la_system_port_wcptr& dsp) const
{
    if (pfx_obj == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(pfx_obj, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto l3_dest = pfx_obj->get_destination();

    if (l3_dest->type() != object_type_e::NEXT_HOP) {
        if (l3_dest->type() == object_type_e::MULTICAST_PROTECTION_GROUP) {
            // Parameter verification for protection groups is handled in the protection group object itself
            return LA_STATUS_SUCCESS;
        }
        log_err(HLD, "L3 destination %s is not supported", la_object_type_to_string(l3_dest->type()).c_str());
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    auto nh = static_cast<const la_next_hop*>(l3_dest);
    la_next_hop::nh_type_e nh_type;
    la_status status = nh->get_nh_type(nh_type);
    return_on_error(status);

    // We support non-normal NHs if the DSP is null
    if (nh_type != la_next_hop::nh_type_e::NORMAL) {
        if (dsp != nullptr) {
            return LA_STATUS_EINVAL;
        }
        return LA_STATUS_SUCCESS;
    }

    la_l3_port* l3_port = nullptr;
    status = nh->get_router_port(l3_port);
    if ((status != LA_STATUS_SUCCESS) || (l3_port == nullptr)) {
        log_err(HLD, "L3 port is not set");
        return LA_STATUS_EINVAL;
    }

    if (l3_port->type() == la_object::object_type_e::SVI_PORT) {
        log_err(HLD, "support for SVI ports is not implemented");
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    la_l3_ac_port* ac_port = static_cast<la_l3_ac_port*>(l3_port);
    auto eth = m_device->get_sptr(ac_port->get_ethernet_port());

    status = m_mc_common->verify_dsp(eth, dsp);

    return status;
}

la_status
la_mpls_multicast_group_impl::allocate_mc_copy_id(const member_t& member, const la_system_port_wcptr& dsp, uint64_t& out_mc_copy_id)
{
    la_slice_id_t dest_slice = get_actual_dsp_slice(dsp);
    bool is_wide = true;
    uint64_t cud_entry_index;
    la_status status = m_device->m_cud_range_manager[dest_slice]->allocate(is_wide, cud_entry_index);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "mc_copy_id allocation failed %s", la_status2str(status).c_str());
        return status;
    }

    uint64_t mc_copy_id = mc_copy_id_manager::cud_entry_index_2_mc_copy_id(cud_entry_index);
    dassert_crit(m_mc_copy_id_mapping[dest_slice].find(std::make_pair(member, dsp)) == m_mc_copy_id_mapping[dest_slice].end());
    m_mc_copy_id_mapping[dest_slice][std::make_pair(member, dsp)] = mc_copy_id;
    out_mc_copy_id = mc_copy_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::release_mc_copy_id(const member_t& member, const la_system_port_wcptr& dsp)
{
    la_slice_id_t dest_slice = get_actual_dsp_slice(dsp);
    const auto& mc_copy_id_it = m_mc_copy_id_mapping[dest_slice].find(std::make_pair(member, dsp));
    if (mc_copy_id_it == m_mc_copy_id_mapping[dest_slice].end()) {
        log_err(HLD, "member not found in mc_copy_id mapping");

        return LA_STATUS_EUNKNOWN;
    }

    uint64_t mc_copy_id = mc_copy_id_it->second;
    uint64_t cud_entry_index = mc_copy_id_manager::mc_copy_id_2_cud_entry_index(mc_copy_id);

    la_status status = m_device->m_cud_range_manager[dest_slice]->release(cud_entry_index);
    return_on_error(status);

    m_mc_copy_id_mapping[dest_slice].erase(mc_copy_id_it);

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::do_add(const member_t& member, const la_system_port_wcptr& dsp)
{
    transaction txn;

    bool protected_member = (member.prot_info.prot_group != nullptr);
    if (protected_member) {
        auto it = std::find(m_protected_members.begin(), m_protected_members.end(), member);
        if (it != m_protected_members.end()) {
            return LA_STATUS_EEXIST;
        }
    } else {
        auto it = std::find(m_members.begin(), m_members.end(), member);
        if (it != m_members.end()) {
            return LA_STATUS_EEXIST;
        }
    }

    if (dsp != nullptr && !m_mc_common->is_dsp_remote(dsp)) {
        // Protected backup members can be null - only program HW if not null
        // Protected members can be remote - only program HW if not remote

        uint64_t mc_copy_id;
        txn.status = allocate_mc_copy_id(member, dsp, mc_copy_id);
        return_on_error(txn.status);
        txn.on_fail([&]() { release_mc_copy_id(member, dsp); });

        la_slice_id_t dest_slice = get_actual_dsp_slice(dsp);

        txn.status = configure_cud_mapping(member, dest_slice, mc_copy_id);
        return_on_error(txn.status);
        txn.on_fail([&]() { teardown_cud_mapping(dest_slice, mc_copy_id); });

        txn.status = configure_egress_rep(member, dsp, mc_copy_id);
        return_on_error(txn.status);

        txn.status = process_slice_addition(dest_slice);
        return_on_error(txn.status);
    }

    // Object dependencies
    if (dsp != nullptr) {
        m_device->add_object_dependency(dsp, this);
    }
    m_device->add_object_dependency(member.prefix_object, this);

    // Store
    dassert_crit(m_dsp_mapping.find(member) == m_dsp_mapping.end());
    m_dsp_mapping[member] = dsp;

    if (protected_member) {
        m_protected_members.push_back(member);
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::MULTICAST_PROTECTION_GROUP_CHANGED);
        m_device->add_attribute_dependency(member.prot_info.prot_group, this, registered_attributes);
    } else {
        m_members.push_back(member);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::add(const la_prefix_object* prefix_object, const la_system_port* dsp)
{
    start_api_call("prefix_object=", prefix_object, "dsp=", dsp);

    transaction txn;

    la_prefix_object_wcptr prefix_object_wptr = m_device->get_sptr(prefix_object);
    la_system_port_base_wcptr dsp_wptr = la_system_port_base::upcast_from_api(m_device, dsp);

    txn.status = verify_parameters(prefix_object_wptr, dsp_wptr);
    return_on_error(txn.status);

    auto l3_dest = prefix_object->get_destination();
    if (l3_dest->type() == object_type_e::NEXT_HOP) {
        const member_t member(prefix_object_wptr);

        txn.status = do_add(member, dsp_wptr);
        return_on_error(txn.status);
    } else if (l3_dest->type() == object_type_e::MULTICAST_PROTECTION_GROUP) {
        if (dsp_wptr != nullptr) {
            return LA_STATUS_EINVAL;
        }

        // For protected entries, internally split up into two members, so we can handle primary and backup seperately
        const la_multicast_protection_group* prot_group = static_cast<const la_multicast_protection_group*>(l3_dest);
        const la_next_hop* primary_nh;
        const la_next_hop* backup_nh;
        const la_system_port* primary_sys_port;
        const la_system_port* backup_sys_port;
        const la_multicast_protection_monitor* monitor;
        txn.status = prot_group->get_primary_destination(primary_nh, primary_sys_port);
        return_on_error(txn.status);

        txn.status = prot_group->get_backup_destination(backup_nh, backup_sys_port);
        return_on_error(txn.status);

        txn.status = prot_group->get_monitor(monitor);
        return_on_error(txn.status);

        la_next_hop_wcptr primary_nh_wptr = m_device->get_sptr(primary_nh);
        la_next_hop_wcptr backup_nh_wptr = m_device->get_sptr(backup_nh);
        la_system_port_wcptr primary_sys_port_wptr = m_device->get_sptr(primary_sys_port);
        la_system_port_wcptr backup_sys_port_wptr = m_device->get_sptr(backup_sys_port);
        la_multicast_protection_monitor_wcptr monitor_wptr = m_device->get_sptr(monitor);
        la_multicast_protection_group_wcptr prot_group_wptr = m_device->get_sptr(prot_group);

        const member_t primary_member(prefix_object_wptr,
                                      prot_info_t(prot_group_wptr, primary_nh_wptr, true /* is_primary */, monitor_wptr));
        const member_t backup_member(prefix_object_wptr,
                                     prot_info_t(prot_group_wptr, backup_nh_wptr, false /* is_primary */, monitor_wptr));

        txn.status = do_add(primary_member, primary_sys_port_wptr);
        return_on_error(txn.status);
        txn.on_fail([&]() { do_remove(primary_member); });

        txn.status = do_add(backup_member, backup_sys_port_wptr);
        return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::allocate_mc_copy_id_recycle(const member_t& member,
                                                          const la_system_port_wcptr& dsp,
                                                          uint64_t& out_mc_copy_id)
{
    la_slice_id_t dest_slice = get_actual_dsp_slice(dsp);
    bool is_wide = true;
    uint64_t cud_entry_index, mc_copy_id;
    la_uint_t mldp_bud_refcnt;

    m_device->get_mldp_bud_refcnt(dest_slice, mldp_bud_refcnt);
    if (mldp_bud_refcnt == 0) {
        la_status status = m_device->m_cud_range_manager[dest_slice]->allocate(is_wide, cud_entry_index);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "mc_copy_id allocation failed %s", la_status2str(status).c_str());
            return status;
        }

        mc_copy_id = mc_copy_id_manager::cud_entry_index_2_mc_copy_id(cud_entry_index);
        m_device->set_mldp_bud_mpls_mc_copy_id(dest_slice, mc_copy_id);
    } else {
        m_device->get_mldp_bud_mpls_mc_copy_id(dest_slice, mc_copy_id);
    }

    dassert_crit(m_mc_copy_id_mapping[dest_slice].find(std::make_pair(member, dsp)) == m_mc_copy_id_mapping[dest_slice].end());
    m_mc_copy_id_mapping[dest_slice][std::make_pair(member, dsp)] = mc_copy_id;
    out_mc_copy_id = mc_copy_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::release_mc_copy_id_recycle(const member_t& member, const la_system_port_wcptr& dsp)
{
    la_slice_id_t dest_slice = get_actual_dsp_slice(dsp);
    const auto& mc_copy_id_it = m_mc_copy_id_mapping[dest_slice].find(std::make_pair(member, dsp));
    if (mc_copy_id_it == m_mc_copy_id_mapping[dest_slice].end()) {
        log_err(HLD, "member not found in mc_copy_id mapping");

        return LA_STATUS_EUNKNOWN;
    }

    uint64_t mc_copy_id = mc_copy_id_it->second;
    uint64_t cud_entry_index = mc_copy_id_manager::mc_copy_id_2_cud_entry_index(mc_copy_id);

    la_uint_t mldp_bud_refcnt;
    m_device->get_mldp_bud_refcnt(dest_slice, mldp_bud_refcnt);
    if (mldp_bud_refcnt == 0) {
        la_status status = m_device->m_cud_range_manager[dest_slice]->release(cud_entry_index);
        return_on_error(status);
    }

    m_mc_copy_id_mapping[dest_slice].erase(mc_copy_id_it);

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::configure_cud_mapping_recycle(const member_t& member, la_slice_id_t dest_slice, uint64_t mc_copy_id)
{
    la_status status;
    const auto& table(m_device->m_tables.mc_cud_table[dest_slice]);
    npl_mc_cud_table_key_t key;
    npl_mc_cud_table_value_t value;
    npl_mc_cud_table_entry_wptr_t entry = nullptr;

    la_uint_t mldp_bud_refcnt;
    m_device->get_mldp_bud_refcnt(dest_slice, mldp_bud_refcnt);
    if (mldp_bud_refcnt > 0) {
        return LA_STATUS_SUCCESS;
    }

    value.action = NPL_MC_CUD_TABLE_ACTION_UPDATE;

    npl_npu_encap_header_ip_host_t& payload_host(
        value.payloads.update.mapped_cud.app_mc_cud.npu_encap_data.mpls_mc_host_encap_header);

    la_mac_addr_t out_mac_addr;
    const auto& l3_ac = member.l3_port.weak_ptr_static_cast<const la_l3_ac_port_impl>();
    status = l3_ac->get_mac(out_mac_addr);
    uint64_t l3_port_gid = member.l3_port->get_gid();

    payload_host.l3_encapsulation_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_HOST_MAC;
    payload_host.next_hop.host_nh_mac.l3_dlp.properties.monitor_or_l3_dlp_ip_type.l3_dlp_ip_type = NPL_IPV4_L3_DLP;
    payload_host.next_hop.host_nh_mac.l3_dlp = get_l3_dlp_encap(l3_port_gid);
    payload_host.next_hop.host_nh_mac.host_mac = out_mac_addr.flat;

    key.cud_mapping_local_vars_exp_mc_copy_id_14_1_ = mc_copy_id_manager::get_mc_cud_table_key(mc_copy_id);

    status = table->set(key, value, entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::teardown_cud_mapping_recycle(la_slice_id_t dest_slice, uint64_t mc_copy_id)
{
    la_status status;

    const auto& table(m_device->m_tables.mc_cud_table[dest_slice]);
    npl_mc_cud_table_key_t key;

    la_uint_t mldp_bud_refcnt;
    m_device->get_mldp_bud_refcnt(dest_slice, mldp_bud_refcnt);
    if (mldp_bud_refcnt > 0) {
        return LA_STATUS_SUCCESS;
    }

    key.cud_mapping_local_vars_exp_mc_copy_id_14_1_ = mc_copy_id_manager::get_mc_cud_table_key(mc_copy_id);

    status = table->erase(key);

    return status;
}

la_status
la_mpls_multicast_group_impl::do_add_recycle_port(const member_t& member, const la_system_port_wcptr& dsp)
{
    transaction txn;

    auto it = std::find(m_members.begin(), m_members.end(), member);
    if (it != m_members.end()) {
        return LA_STATUS_EEXIST;
    }

    uint64_t mc_copy_id;
    txn.status = allocate_mc_copy_id_recycle(member, dsp, mc_copy_id);
    return_on_error(txn.status);
    txn.on_fail([&]() { release_mc_copy_id_recycle(member, dsp); });

    la_slice_id_t dest_slice = get_actual_dsp_slice(dsp);

    txn.status = configure_cud_mapping_recycle(member, dest_slice, mc_copy_id);
    return_on_error(txn.status);
    txn.on_fail([&]() { teardown_cud_mapping_recycle(dest_slice, mc_copy_id); });

    txn.status = configure_egress_rep(member, dsp, mc_copy_id);
    return_on_error(txn.status);

    m_device->incr_mldp_bud_refcnt(dest_slice);

    // Object dependencies
    if (dsp != nullptr) {
        m_device->add_object_dependency(dsp, this);
    }
    m_device->add_object_dependency(member.l3_port, this);

    // Store
    dassert_crit(m_dsp_mapping.find(member) == m_dsp_mapping.end());
    m_dsp_mapping[member] = dsp;

    m_members.push_back(member);

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::verify_parameters(const la_l3_port* l3_port) const
{
    if (l3_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (l3_port->get_device() != m_device) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    const la_l3_ac_port_impl* l3_ac = static_cast<const la_l3_ac_port_impl*>(l3_port);
    if (!is_recycle_ac(m_device->get_sptr(l3_ac))) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::add(const la_l3_port* l3_port)
{
    start_api_call("l3_port=", l3_port);

    transaction txn;

    txn.status = verify_parameters(l3_port);
    return_on_error(txn.status);

    const la_l3_ac_port* ac_port = static_cast<const la_l3_ac_port*>(l3_port);
    auto ethernet_port = m_device->get_sptr(ac_port->get_ethernet_port());
    if (ethernet_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    const la_system_port* dsp = ethernet_port->get_system_port();
    if (dsp == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_l3_port_wcptr l3_port_wptr = m_device->get_sptr(l3_port);
    la_system_port_wcptr dsp_wptr = m_device->get_sptr(dsp);

    const member_t member(l3_port_wptr);

    txn.status = do_add_recycle_port(member, dsp_wptr);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::do_remove_recycle_port(const member_t& member)
{
    transaction txn;

    std::vector<member_t>::iterator members_it;

    members_it = std::find(m_members.begin(), m_members.end(), member);
    if (members_it == m_members.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    // Get destination system port
    auto dsp_it = m_dsp_mapping.find(member);
    if (dsp_it == m_dsp_mapping.end()) {
        log_err(HLD, "member not found in dsp mapping");

        return LA_STATUS_EUNKNOWN;
    }

    auto dsp = dsp_it->second;

    if (dsp != nullptr) {
        // If member is null, skip teardown in HW, as it was never configured originally

        // Get MC copy ID
        la_slice_id_t dest_slice = get_actual_dsp_slice(dsp);
        auto mc_copy_id_it = m_mc_copy_id_mapping[dest_slice].find(std::make_pair(member, dsp));
        if (mc_copy_id_it == m_mc_copy_id_mapping[dest_slice].end()) {
            log_err(HLD, "member not found in mc_copy_id mapping");

            return LA_STATUS_EUNKNOWN;
        }
        uint64_t mc_copy_id = mc_copy_id_it->second;

        txn.status = teardown_egress_rep(member, dsp);
        return_on_error(txn.status);
        txn.on_fail([&]() { configure_egress_rep(member, dsp, mc_copy_id); });

        m_device->decr_mldp_bud_refcnt(dest_slice);
        txn.on_fail([&]() { m_device->incr_mldp_bud_refcnt(dest_slice); });

        // Teardown CUD mapping
        txn.status = teardown_cud_mapping_recycle(dest_slice, mc_copy_id);
        return_on_error(txn.status);
        txn.on_fail([&]() { configure_cud_mapping_recycle(member, dest_slice, mc_copy_id); });

        // Release MC copy ID
        txn.status = release_mc_copy_id_recycle(member, dsp);
        return_on_error(txn.status);
    }

    // Remove object dependencies
    if (dsp != nullptr) {
        m_device->remove_object_dependency(dsp, this);
    }
    m_device->remove_object_dependency(member.l3_port, this);

    m_dsp_mapping.erase(dsp_it);
    m_members.erase(members_it);

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::remove(const la_l3_port* l3_port)
{
    start_api_call("l3_port=", l3_port);

    transaction txn;

    txn.status = verify_parameters(l3_port);
    return_on_error(txn.status);

    la_l3_port_wcptr l3_port_wptr = m_device->get_sptr(l3_port);

    const member_t member(l3_port_wptr);

    txn.status = do_remove_recycle_port(member);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::configure_cud_mapping(const member_t& member, la_slice_id_t dest_slice, uint64_t mc_copy_id)
{
    la_status status;
    const auto& table(m_device->m_tables.mc_cud_table[dest_slice]);
    npl_mc_cud_table_key_t key;
    npl_mc_cud_table_value_t value;
    npl_mc_cud_table_entry_wptr_t entry = nullptr;

    value.action = NPL_MC_CUD_TABLE_ACTION_UPDATE;

    npl_npu_l3_encap_header_t& payload(value.payloads.update.mapped_cud.app_mc_cud.npu_encap_data.l3);

    if (member.prot_info.prot_group == nullptr) {
        // Non-protected entry
        auto destination = member.prefix_object->get_destination();
        auto nh = static_cast<const la_next_hop*>(destination);
        la_next_hop_gid_t nh_gid = nh->get_gid();
        la_l3_port* l3_port = nullptr;
        status = nh->get_router_port(l3_port);
        uint64_t l3_port_gid = l3_port->get_gid();

        payload.l3_common_encap.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE;
        payload.l3_common_encap.l3_dlp_nh_encap.npu_l3_common_dlp_nh_encap.l3_dlp = get_l3_dlp_encap(l3_port_gid);
        payload.l3_common_encap.l3_dlp_nh_encap.npu_l3_common_dlp_nh_encap.nh = nh_gid;
        payload.encap_ext.tunnel_headend.lsp_destination.lsp_dest_prefix = member.prefix_object->get_gid();
        payload.encap_ext.tunnel_headend.mldp_protection.sel = NPL_PROTECTION_SELECTOR_PRIMARY;

    } else {
        la_next_hop_gid_t nh_gid = member.prot_info.next_hop->get_gid();
        la_l3_port* l3_port = nullptr;
        status = member.prot_info.next_hop->get_router_port(l3_port);
        uint64_t l3_port_gid = l3_port->get_gid();
        const la_multicast_protection_monitor_base* monitor_base
            = static_cast<const la_multicast_protection_monitor_base*>(member.prot_info.monitor.get());

        payload.l3_common_encap.l3_encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE;
        payload.l3_common_encap.l3_dlp_nh_encap.npu_l3_common_dlp_nh_encap.l3_dlp = get_l3_dlp_encap(l3_port_gid);
        payload.l3_common_encap.l3_dlp_nh_encap.npu_l3_common_dlp_nh_encap.nh = nh_gid;
        payload.encap_ext.tunnel_headend.lsp_destination.lsp_dest_prefix = member.prefix_object->get_gid();
        payload.encap_ext.tunnel_headend.mldp_protection.id.id = monitor_base->get_gid();
        payload.encap_ext.tunnel_headend.mldp_protection.sel
            = (member.prot_info.is_primary ? NPL_PROTECTION_SELECTOR_PRIMARY : NPL_PROTECTION_SELECTOR_PROTECT);
    }

    key.cud_mapping_local_vars_exp_mc_copy_id_14_1_ = mc_copy_id_manager::get_mc_cud_table_key(mc_copy_id);

    status = table->set(key, value, entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::teardown_cud_mapping(la_slice_id_t dest_slice, uint64_t mc_copy_id)
{
    la_status status;

    const auto& table(m_device->m_tables.mc_cud_table[dest_slice]);
    npl_mc_cud_table_key_t key;

    key.cud_mapping_local_vars_exp_mc_copy_id_14_1_ = mc_copy_id_manager::get_mc_cud_table_key(mc_copy_id);

    status = table->erase(key);

    return status;
}

la_status
la_mpls_multicast_group_impl::do_remove(const member_t& member)
{
    transaction txn;

    if (member.l3_port != nullptr) {
        la_status status = do_remove_recycle_port(member);
        return status;
    }

    bool protected_member = (member.prot_info.prot_group != nullptr);
    std::vector<member_t>::iterator members_it;

    if (protected_member) {
        members_it = std::find(m_protected_members.begin(), m_protected_members.end(), member);
        if (members_it == m_protected_members.end()) {
            return LA_STATUS_ENOTFOUND;
        }
    } else {
        members_it = std::find(m_members.begin(), m_members.end(), member);
        if (members_it == m_members.end()) {
            return LA_STATUS_ENOTFOUND;
        }
    }

    // Get destination system port
    auto dsp_it = m_dsp_mapping.find(member);
    if (dsp_it == m_dsp_mapping.end()) {
        log_err(HLD, "member not found in dsp mapping");

        return LA_STATUS_EUNKNOWN;
    }

    auto dsp = dsp_it->second;

    if (dsp != nullptr && !m_mc_common->is_dsp_remote(dsp)) {
        // If member is null, skip teardown in HW, as it was never configured originally
        // If DSP is remote, skip teardown in HW - was never originally programmed in HW

        // Get MC copy ID
        la_slice_id_t dest_slice = get_actual_dsp_slice(dsp);
        auto mc_copy_id_it = m_mc_copy_id_mapping[dest_slice].find(std::make_pair(member, dsp));
        if (mc_copy_id_it == m_mc_copy_id_mapping[dest_slice].end()) {
            log_err(HLD, "member not found in mc_copy_id mapping");

            return LA_STATUS_EUNKNOWN;
        }
        uint64_t mc_copy_id = mc_copy_id_it->second;

        txn.status = teardown_egress_rep(member, dsp);
        return_on_error(txn.status);
        txn.on_fail([&]() { configure_egress_rep(member, dsp, mc_copy_id); });

        // Teardown CUD mapping
        txn.status = teardown_cud_mapping(dest_slice, mc_copy_id);
        return_on_error(txn.status);
        txn.on_fail([&]() { configure_cud_mapping(member, dest_slice, mc_copy_id); });

        // Release MC copy ID
        txn.status = release_mc_copy_id(member, dsp);
        return_on_error(txn.status);

        txn.status = process_slice_removal(dest_slice);
        return_on_error(txn.status);
    }

    // Remove object dependencies
    if (dsp != nullptr) {
        m_device->remove_object_dependency(dsp, this);
    }
    m_device->remove_object_dependency(member.prefix_object, this);

    m_dsp_mapping.erase(dsp_it);
    if (protected_member) {
        m_protected_members.erase(members_it);
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::MULTICAST_PROTECTION_GROUP_CHANGED);
        m_device->remove_attribute_dependency(member.prot_info.prot_group, this, registered_attributes);
    } else {
        m_members.erase(members_it);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::remove(const la_prefix_object* prefix_object)
{
    start_api_call("prefix_object=", prefix_object);

    transaction txn;

    if (prefix_object == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (prefix_object->get_device() != m_device) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_prefix_object_wcptr prefix_object_wptr = m_device->get_sptr(prefix_object);

    auto l3_dest = prefix_object->get_destination();
    if (l3_dest->type() == object_type_e::NEXT_HOP) {
        const member_t member(prefix_object_wptr);

        txn.status = do_remove(member);
        return_on_error(txn.status);
    } else if (l3_dest->type() == object_type_e::MULTICAST_PROTECTION_GROUP) {

        // For protected entries, internally split up into two members, so we can handle primary and backup seperately
        const la_multicast_protection_group* prot_group = static_cast<const la_multicast_protection_group*>(l3_dest);
        const la_next_hop* primary_nh;
        const la_next_hop* backup_nh;
        const la_multicast_protection_monitor* monitor;
        const la_system_port* dummy_sys_port;
        txn.status = prot_group->get_primary_destination(primary_nh, dummy_sys_port);
        return_on_error(txn.status);

        txn.status = prot_group->get_backup_destination(backup_nh, dummy_sys_port);
        return_on_error(txn.status);

        txn.status = prot_group->get_monitor(monitor);
        return_on_error(txn.status);

        la_next_hop_wcptr primary_nh_wptr = m_device->get_sptr(primary_nh);
        la_next_hop_wcptr backup_nh_wptr = m_device->get_sptr(backup_nh);
        la_multicast_protection_monitor_wcptr monitor_wptr = m_device->get_sptr(monitor);
        la_multicast_protection_group_wcptr prot_group_wptr = m_device->get_sptr(prot_group);

        const member_t primary_member(prefix_object_wptr,
                                      prot_info_t(prot_group_wptr, primary_nh_wptr, true /* is_primary */, monitor_wptr));
        const member_t backup_member(prefix_object_wptr,
                                     prot_info_t(prot_group_wptr, backup_nh_wptr, false /* is_primary */, monitor_wptr));

        txn.status = do_remove(primary_member);
        return_on_error(txn.status);
        txn.on_fail([&]() {
            auto dsp_it = m_dsp_mapping.find(primary_member);
            if (dsp_it == m_dsp_mapping.end()) {
                return;
            }
            auto dsp = dsp_it->second;
            do_add(primary_member, dsp);
        });

        txn.status = do_remove(backup_member);
        return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::get_member(size_t member_idx, la_mpls_multicast_group_member_info& out_member) const
{
    start_api_getter_call();
    size_t group_size;
    la_status status = get_size(group_size);
    return_on_error(status);

    if (member_idx >= group_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (member_idx >= m_members.size()) {
        member_idx = (member_idx - m_members.size()) / 2;
        out_member.prefix_object = m_protected_members[member_idx].prefix_object.get();
    } else {
        out_member.prefix_object = m_members[member_idx].prefix_object.get();
        out_member.l3_port = m_members[member_idx].l3_port.get();
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::get_size(size_t& out_size) const
{
    start_api_getter_call();
    out_size = m_members.size() + (m_protected_members.size() / 2);

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::get_replication_paradigm(la_replication_paradigm_e& out_replication_paradigm) const
{
    start_api_getter_call();
    out_replication_paradigm = m_rep_paradigm;
    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::get_destination_system_port(const la_prefix_object* prefix_object,
                                                          const la_system_port*& out_dsp) const
{
    start_api_getter_call();

    if (prefix_object == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(prefix_object, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (prefix_object->get_destination() != nullptr
        && prefix_object->get_destination()->type() == object_type_e::MULTICAST_PROTECTION_GROUP) {
        return LA_STATUS_EINVAL;
    }

    la_prefix_object_wcptr prefix_object_wptr = m_device->get_sptr(prefix_object);
    member_t member(prefix_object_wptr);

    auto dsp_it = m_dsp_mapping.find(member);
    if (dsp_it == m_dsp_mapping.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    auto dsp = dsp_it->second;

    out_dsp = dsp.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::set_destination_system_port(const la_prefix_object* prefix_object, const la_system_port* dsp)
{
    start_api_call("prefix_object=", prefix_object, "dsp=", dsp);

    if (prefix_object == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_prefix_object_wcptr prefix_object_wptr = m_device->get_sptr(prefix_object);
    auto dsp_wptr = la_system_port_base::upcast_from_api(m_device, dsp);
    if (!of_same_device(prefix_object_wptr, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (prefix_object->get_destination() != nullptr
        && prefix_object->get_destination()->type() == object_type_e::MULTICAST_PROTECTION_GROUP) {
        return LA_STATUS_EINVAL;
    }

    // Get the current DSP
    member_t member(prefix_object_wptr);
    auto dsp_it = m_dsp_mapping.find(member);
    if (dsp_it == m_dsp_mapping.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    auto curr_dsp = la_system_port_base::upcast_from_api(m_device, dsp_it->second);
    la_slice_id_t curr_slice = curr_dsp->get_slice();

    // Get the current MC copy ID
    auto mc_copy_id_it = m_mc_copy_id_mapping[curr_slice].find(std::make_pair(member, dsp_wptr));
    dassert_crit(mc_copy_id_it != m_mc_copy_id_mapping[curr_slice].end());
    uint64_t mc_copy_id = mc_copy_id_it->second;

    if (curr_slice == dsp_wptr->get_slice()) {
        // DSPs are on the same slice
        auto adsp = get_actual_dsp(dsp_wptr);
        la_status status = m_mc_common->set_member_dsp(member, curr_dsp, adsp, mc_copy_id, mc_copy_id);
        return_on_error(status);

        m_device->remove_object_dependency(curr_dsp, this);
        m_device->add_object_dependency(dsp_wptr, this);
        // Replace the current DSP
        m_dsp_mapping[member] = dsp_wptr;

        return LA_STATUS_SUCCESS;
    }

    // DSPs are not on the same slice. Need to configure CUD on the new slice
    uint64_t new_mc_copy_id;
    la_status status = allocate_mc_copy_id(member, dsp_wptr, new_mc_copy_id);
    return_on_error(status);

    status = configure_cud_mapping(member, dsp_wptr->get_slice(), new_mc_copy_id);
    return_on_error(status);

    auto adsp = get_actual_dsp(dsp_wptr);
    status = m_mc_common->set_member_dsp(member, curr_dsp, adsp, mc_copy_id, new_mc_copy_id);
    return_on_error(status);

    // Teardown old CUD mapping
    status = teardown_cud_mapping(curr_dsp->get_slice(), mc_copy_id);
    return_on_error(status);

    // Release old MC copy ID
    status = release_mc_copy_id(member, curr_dsp);
    return_on_error(status);

    status = process_slice_removal(curr_slice);
    return_on_error(status);
    status = process_slice_addition(adsp->get_slice());
    return_on_error(status);

    m_device->remove_object_dependency(curr_dsp, this);
    m_device->add_object_dependency(dsp_wptr, this);
    // Replace the current DSP
    m_dsp_mapping[member] = dsp_wptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::get_members_for_protection_group(const la_multicast_protection_group* protection_group,
                                                               member_t& primary_member,
                                                               member_t& backup_member)
{
    std::vector<member_t> temp_members;
    std::for_each(m_protected_members.begin(), m_protected_members.end(), [&](const member_t& member) {
        if (member.prot_info.prot_group == protection_group) {
            temp_members.push_back(member);
        }
    });
    if (temp_members.size() != 2) {
        return LA_STATUS_ENOTFOUND;
    }

    if (temp_members[0].prot_info.is_primary) {
        primary_member = temp_members[0];
        backup_member = temp_members[1];
    } else {
        primary_member = temp_members[1];
        backup_member = temp_members[0];
    }

    return LA_STATUS_SUCCESS;
}

bool
la_mpls_multicast_group_impl::check_protection_group_swap_case(const member_t& original_member,
                                                               const la_system_port* original_dsp,
                                                               const la_next_hop* new_nh,
                                                               const la_system_port* new_dsp)
{
    // If NH and DSP are the same, but is_primary differs, we can just toggle the is_primary bit/prot mon in CUD data
    // Since this is a protection group update case, the prefix object and protection group are the same always
    if (original_member.prot_info.next_hop == new_nh && original_dsp == new_dsp) {
        return true;
    } else {
        return false;
    }
}

la_status
la_mpls_multicast_group_impl::handle_protection_group_member_update(const member_t& member,
                                                                    const la_system_port* dsp,
                                                                    multicast_protection_group_change_details mcg_update,
                                                                    bool swap_case)
{
    transaction txn;
    la_slice_id_t dest_slice = 0;
    uint64_t mc_copy_id = 0xFFFF;
    la_system_port_base_wcptr dsp_wptr = la_system_port_base::upcast_from_api(m_device, dsp);

    // Get slice
    if (dsp != nullptr) {
        dest_slice = get_actual_dsp_slice(dsp_wptr);
    }

    // Get slice/mc_copy_id - if remote or null, no need as no HW programming is done
    if (dsp_wptr != nullptr && !m_mc_common->is_dsp_remote(dsp_wptr)) {
        const auto& mc_copy_id_it = m_mc_copy_id_mapping[dest_slice].find(std::make_pair(member, dsp_wptr));
        if (mc_copy_id_it == m_mc_copy_id_mapping[dest_slice].end()) {
            log_err(HLD, "member not found in mc_copy_id mapping");
            return LA_STATUS_EUNKNOWN;
        }
        mc_copy_id = mc_copy_id_it->second;
    }

    bool is_primary = member.prot_info.is_primary;
    auto new_dsp = (is_primary ? mcg_update.primary_sys_port : mcg_update.backup_sys_port);
    la_slice_id_t new_dest_slice = 0;
    la_system_port_wcptr new_dsp_wptr = m_device->get_sptr(new_dsp);

    // New DSP can be null - ignore if so
    if (new_dsp != nullptr) {
        new_dest_slice = get_actual_dsp_slice(new_dsp_wptr);
    }

    la_next_hop_wcptr primary_dest_wptr = m_device->get_sptr(mcg_update.primary_dest);
    la_next_hop_wcptr backup_dest_wptr = m_device->get_sptr(mcg_update.backup_dest);
    la_multicast_protection_monitor_wcptr monitor_wptr = m_device->get_sptr(mcg_update.monitor);

    // CUD only case: egress rep can be retained, so only update CUD data - all operations handled on same slice
    if (dsp == new_dsp) {
        // If swap case, invert the is_primary bit in CUD data
        la_multicast_protection_monitor_wcptr monitor_wptr = m_device->get_sptr(mcg_update.monitor);
        member_t new_member(member.prefix_object,
                            prot_info_t(member.prot_info.prot_group,
                                        (is_primary ? primary_dest_wptr : backup_dest_wptr),
                                        (swap_case) ? !is_primary : is_primary,
                                        monitor_wptr));

        // Only modify CUD data/MC copy id mapping if it exists (DSP is not remote and non-null)
        if (dsp != nullptr && !m_mc_common->is_dsp_remote(dsp_wptr)) {
            // dest_slice == new_dest_slice in this case
            txn.status = configure_cud_mapping(new_member, dest_slice, mc_copy_id);
            return_on_error(txn.status);
            txn.on_fail([&]() { configure_cud_mapping(member, dest_slice, mc_copy_id); });

            dassert_crit(m_mc_copy_id_mapping[dest_slice].find(std::make_pair(member, dsp_wptr))
                         != m_mc_copy_id_mapping[dest_slice].end());
            m_mc_copy_id_mapping[dest_slice].erase(std::make_pair(member, dsp_wptr));
            m_mc_copy_id_mapping[dest_slice][std::make_pair(new_member, dsp_wptr)] = mc_copy_id;

            // Update MC EM DB SW mappings
            // Since updating the member in mpls_multicast_group won't modify it in multicast_group_common, this is unfortunately
            // neccessary
            txn.status = m_mc_common->update_member_slice_data(member, new_member, dest_slice);
            return_on_error(txn.status);
        }

        // Replace old member in members list
        std::replace(m_protected_members.begin(), m_protected_members.end(), member, new_member);

        // Update DSP mapping
        dassert_crit(m_dsp_mapping.find(member) != m_dsp_mapping.end());
        m_dsp_mapping.erase(member);
        m_dsp_mapping[new_member] = new_dsp_wptr;

        return LA_STATUS_SUCCESS;
    }

    // Generic case: Must modify both CUD data and egress rep
    // If swap case, invert the is_primary bit in CUD data
    member_t new_member(member.prefix_object,
                        prot_info_t(member.prot_info.prot_group,
                                    (is_primary ? primary_dest_wptr : backup_dest_wptr),
                                    (swap_case) ? !is_primary : is_primary,
                                    monitor_wptr));

    if (new_dsp == nullptr || m_mc_common->is_dsp_remote(new_dsp_wptr)) {
        // If new DSP is remote/null, all we need to do is teardown old (if old is not also remote/null)
        if (dsp != nullptr && !m_mc_common->is_dsp_remote(dsp_wptr)) {
            txn.status = teardown_egress_rep(member, dsp_wptr);
            return_on_error(txn.status);
            txn.on_fail([&]() { configure_egress_rep(member, dsp_wptr, mc_copy_id); });

            // Teardown CUD mapping
            txn.status = teardown_cud_mapping(dest_slice, mc_copy_id);
            return_on_error(txn.status);
            txn.on_fail([&]() { configure_cud_mapping(member, dest_slice, mc_copy_id); });

            // Release MC copy ID
            txn.status = release_mc_copy_id(member, dsp_wptr);
            return_on_error(txn.status);

            // remove slice bitmap for old dsp
            txn.status = process_slice_removal(dest_slice);
            return_on_error(txn.status);
        }
    } else {
        // New DSP is not remote/null - program in HW
        // Make-before-break: Create a new CUD entry, modify egress rep to point to new entry, remove old entry
        uint64_t new_mc_copy_id;
        txn.status = allocate_mc_copy_id(new_member, new_dsp_wptr, new_mc_copy_id);
        return_on_error(txn.status);
        txn.on_fail([&]() { release_mc_copy_id(new_member, new_dsp_wptr); });

        txn.status = configure_cud_mapping(new_member, new_dest_slice, new_mc_copy_id);
        return_on_error(txn.status);
        txn.on_fail([&]() { teardown_cud_mapping(new_dest_slice, new_mc_copy_id); });

        // If the old dsp is remote/null, add a new egress rep. Else, modify the old one
        if (dsp == nullptr || m_mc_common->is_dsp_remote(dsp_wptr)) {
            txn.status = configure_egress_rep(new_member, new_dsp_wptr, new_mc_copy_id);
            return_on_error(txn.status);
        } else {
            txn.status = m_mc_common->set_member_dsp(member, dsp_wptr, new_dsp_wptr, mc_copy_id, new_mc_copy_id);
            return_on_error(txn.status);
            txn.on_fail([&]() { m_mc_common->set_member_dsp(member, new_dsp_wptr, dsp_wptr, new_mc_copy_id, mc_copy_id); });

            // Update MC EM DB SW mappings
            // Since updating the member in mpls_multicast_group won't modify it in multicast_group_common, this is unfortunately
            // neccessary
            txn.status = m_mc_common->update_member_slice_data(member, new_member, new_dest_slice);
            return_on_error(txn.status);
            txn.on_fail([&]() { m_mc_common->update_member_slice_data(new_member, member, new_dest_slice); });

            txn.status = teardown_cud_mapping(dest_slice, mc_copy_id);
            return_on_error(txn.status);
            txn.on_fail([&]() { configure_cud_mapping(member, dest_slice, mc_copy_id); });

            txn.status = release_mc_copy_id(member, dsp_wptr);
            return_on_error(txn.status);

            // remove slice bitmap for old dsp
            txn.status = process_slice_removal(dest_slice);
            return_on_error(txn.status);
        }

        // add slice bitmap for new dsp
        txn.status = process_slice_addition(new_dest_slice);
        return_on_error(txn.status);
    }

    // Replace old member in members list
    std::replace(m_protected_members.begin(), m_protected_members.end(), member, new_member);

    // Object dependencies
    if (new_dsp != nullptr) {
        m_device->add_object_dependency(new_dsp, this);
    }
    if (dsp != nullptr) {
        m_device->remove_object_dependency(dsp, this);
    }

    // Update DSP mapping
    dassert_crit(m_dsp_mapping.find(member) != m_dsp_mapping.end());
    m_dsp_mapping.erase(member);
    m_dsp_mapping[new_member] = new_dsp_wptr;

    // No need to update MC copy id mapping - that is handled above in this case

    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::handle_protection_group_update(const la_multicast_protection_group* protection_group,
                                                             multicast_protection_group_change_details mcg_update)
{
    // Each protection group internally has two members - fetch them
    member_t primary_member;
    member_t backup_member;

    la_status status = get_members_for_protection_group(protection_group, primary_member, backup_member);
    return_on_error(status);

    // Get destination system ports
    auto dsp_it = m_dsp_mapping.find(primary_member);
    if (dsp_it == m_dsp_mapping.end()) {
        log_err(HLD, "member not found in dsp mapping");

        return LA_STATUS_EUNKNOWN;
    }
    const la_system_port* primary_dsp = (dsp_it->second).get();

    dsp_it = m_dsp_mapping.find(backup_member);
    if (dsp_it == m_dsp_mapping.end()) {
        log_err(HLD, "member not found in dsp mapping");

        return LA_STATUS_EUNKNOWN;
    }
    const la_system_port* backup_dsp = (dsp_it->second).get();

    // Handle currently active member first - that way, worst case will be traffic drop rather than duplication
    bool primary_active;
    bool backup_active;

    status = primary_member.prot_info.monitor->get_state(primary_active, backup_active);
    return_on_error(status);

    // Handle special case - members are swapped
    // If this is the case, swap the updates + is_primary bit for the members
    // We do this in a special way to avoid any traffic loss, since we can re-use the data structures in this case
    bool swap_case = false;
    if (check_protection_group_swap_case(
            primary_member, mcg_update.backup_sys_port, mcg_update.backup_dest, mcg_update.backup_sys_port)
        || check_protection_group_swap_case(backup_member, backup_dsp, mcg_update.primary_dest, mcg_update.primary_sys_port)) {
        // Swap the primary and backup updates, so the primary and backup members use inverted updates
        // This lets us re-use entries in HW to avoid unneccessary traffic drops
        auto primary = mcg_update.primary_dest;
        auto primary_dsp = mcg_update.primary_sys_port;
        mcg_update.primary_dest = mcg_update.backup_dest;
        mcg_update.primary_sys_port = mcg_update.backup_sys_port;
        mcg_update.backup_dest = primary;
        mcg_update.backup_sys_port = primary_dsp;

        swap_case = true;
    }

    if (primary_active) {
        // Modify current primary first

        status = handle_protection_group_member_update(primary_member, primary_dsp, mcg_update, swap_case);
        return_on_error(status);

        status = handle_protection_group_member_update(backup_member, backup_dsp, mcg_update, swap_case);
        return_on_error(status);
    } else {
        // Modify current backup first

        status = handle_protection_group_member_update(backup_member, backup_dsp, mcg_update, swap_case);
        return_on_error(status);

        status = handle_protection_group_member_update(primary_member, primary_dsp, mcg_update, swap_case);
        return_on_error(status);
    }

    // m_protected_members is modified in-place in individual member updates
    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::notify_change(dependency_management_op op)
{
    switch (op.type_e) {

    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT: {
        if (op.dependee->type() == object_type_e::MULTICAST_PROTECTION_GROUP) {
            const la_multicast_protection_group* prot_group = static_cast<const la_multicast_protection_group*>(op.dependee);
            la_status status = handle_protection_group_update(prot_group, op.action.attribute_management.mcg_change);
            return_on_error(status);
        }
        return LA_STATUS_SUCCESS;
    }

    default:
        log_err(HLD,
                "la_mpls_multicast_group_impl::notify_change received unsupported notification (%s)",
                silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::set_punt_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_mpls_multicast_group_impl::get_punt_enabled(bool& out_enable) const
{
    out_enable = m_punt_enabled;

    return LA_STATUS_SUCCESS;
}

size_t
la_mpls_multicast_group_impl::get_slice_bitmap() const
{
    return m_mc_common->get_slice_bitmap();
}

la_status
la_mpls_multicast_group_impl::process_slice_addition(la_slice_id_t slice)
{
    la_status status = LA_STATUS_SUCCESS;
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
    return LA_STATUS_SUCCESS;
}

la_status
la_mpls_multicast_group_impl::process_slice_removal(la_slice_id_t slice)
{
    la_status status = LA_STATUS_SUCCESS;
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
    return LA_STATUS_SUCCESS;
}

bool
la_mpls_multicast_group_impl::add_slice_user(la_slice_id_t slice)
{
    bool new_slice_added = false;
    if (m_rep_paradigm == la_replication_paradigm_e::EGRESS) {
        if (m_slice_use_count[slice] == 0) {
            new_slice_added = true;
        }
        m_slice_use_count[slice]++;
    }
    return new_slice_added;
}

bool
la_mpls_multicast_group_impl::remove_slice_user(la_slice_id_t slice)
{
    bool slice_removed = false;
    if (m_rep_paradigm == la_replication_paradigm_e::EGRESS) {
        dassert_crit(m_slice_use_count[slice] != 0);
        m_slice_use_count[slice]--;

        if (m_slice_use_count[slice] == 0) {
            slice_removed = true;
        }
    }
    return slice_removed;
}

la_status
la_mpls_multicast_group_impl::notify_mcg_change_event(bool slice_added, la_slice_id_t slice)
{
    attribute_management_details amd;
    amd.op = attribute_management_op::MCG_MEMBER_LIST_CHANGED;
    amd.mcg_slice_update.slice_added = slice_added;
    amd.mcg_slice_update.slice = slice;

    la_amd_undo_callback_funct_t undo = [](attribute_management_details amd) { return amd; };
    la_mpls_multicast_group* mpls_mcg = static_cast<la_mpls_multicast_group*>(this);
    la_status status = m_device->notify_attribute_changed(mpls_mcg, amd, undo);
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

} // namespace silicon_one
