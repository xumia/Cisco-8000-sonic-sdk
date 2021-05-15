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

#include "la_l2_multicast_group_gibraltar.h"
#include "common/transaction.h"
#include "npu/mc_copy_id_manager.h"
#include "system/cud_range_manager.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

la_l2_multicast_group_gibraltar::la_l2_multicast_group_gibraltar(la_device_impl_wptr device) : la_l2_multicast_group_base(device)
{
}

la_l2_multicast_group_gibraltar::~la_l2_multicast_group_gibraltar()
{
}

la_status
la_l2_multicast_group_gibraltar::get_mc_copy_id(const member_t& member,
                                                const la_system_port_wcptr& dsp_sptr,
                                                bool is_wide,
                                                uint64_t& out_mc_copy_id)
{
    la_status status;
    auto adsp = get_actual_dsp(dsp_sptr);
    la_slice_id_t dest_slice = adsp->get_slice();

    if (member.stackport != nullptr) {
        return m_device->m_mc_copy_id_manager[dest_slice]->get_stack_mc_copy_id(out_mc_copy_id);
    }

    const la_l2_destination* destination = member.l2_dest.get();
    la_l2_destination_wcptr dest_wcptr = m_device->get_sptr(destination);

    if (member.vxlan_type != la_multicast_group_common_base::vxlan_type_e::INVALID) {
        uint64_t cud_entry_index;
        status = m_device->m_cud_range_manager[dest_slice]->allocate(true, cud_entry_index);
        return_on_error(status);
        out_mc_copy_id = mc_copy_id_manager::cud_entry_index_2_mc_copy_id(cud_entry_index);
        dassert_crit(m_mc_copy_id_mapping[dest_slice].find(member) == m_mc_copy_id_mapping[dest_slice].end());
        m_mc_copy_id_mapping[dest_slice][member] = out_mc_copy_id;
        return LA_STATUS_SUCCESS;
    }
    if (member.l3_port == nullptr) {
        // allocate copy id from L2_DLP range
        const la_l2_destination* destination = member.l2_dest.get();
        la_l2_destination_wcptr dest_wcptr = m_device->get_sptr(destination);
        const auto& ac_port = dest_wcptr.weak_ptr_static_cast<const la_l2_service_port_base>();

        status = m_device->m_mc_copy_id_manager[dest_slice]->get_mc_copy_id(ac_port, is_wide, out_mc_copy_id);

        if (ac_port->get_port_type() == la_l2_service_port_base::port_type_e::PWE) {
            dassert_crit(m_mc_copy_id_mapping[dest_slice].find(member) == m_mc_copy_id_mapping[dest_slice].end());
            m_mc_copy_id_mapping[dest_slice][member] = out_mc_copy_id;
        }
        return_on_error(status);
    } else {
        // allocate copy id from CUD Mapping range
        if ((member.l3_port == nullptr) || (member.l3_port->type() != object_type_e::SVI_PORT)) {
            log_err(HLD, "%s:%d: GID:0x%x: member.l3_port is invalid", __func__, __LINE__, get_gid());
            return LA_STATUS_EINVAL;
        }
        status = m_device->m_mc_copy_id_manager[dest_slice]->get_mc_copy_id(member.l3_port, is_wide, out_mc_copy_id);
        return_on_error(status);
        member_t amember(member.l2_dest); // actual member has only l2_dest
        dassert_crit(m_mc_copy_id_mapping[dest_slice].find(amember) == m_mc_copy_id_mapping[dest_slice].end());
        m_mc_copy_id_mapping[dest_slice][amember] = out_mc_copy_id;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_gibraltar::add_to_mc_copy_id_table(const member_t& member, const la_system_port_wcptr& dsp)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_gibraltar::remove_from_mc_copy_id_table(const member_t& member, const la_system_port_wcptr& dsp)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_gibraltar::allocate_mc_copy_id(const la_l2_destination* member,
                                                     const la_system_port_wcptr& dsp_wptr,
                                                     uint64_t& out_mc_copy_id)
{
    la_slice_id_t dest_slice = get_actual_dsp_slice(dsp_wptr);
    uint64_t cud_entry_index;
    auto member_sptr = m_device->get_sptr(member);
    la_multicast_group_common_base::group_member_desc amember(member_sptr);

    la_status status = m_device->m_cud_range_manager[dest_slice]->allocate(true, cud_entry_index);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "mc_copy_id allocation failed %s", la_status2str(status).c_str());
        return status;
    }

    uint64_t mc_copy_id = mc_copy_id_manager::cud_entry_index_2_mc_copy_id(cud_entry_index);
    dassert_crit(m_mc_copy_id_mapping[dest_slice].find(amember) == m_mc_copy_id_mapping[dest_slice].end());
    m_mc_copy_id_mapping[dest_slice][amember] = mc_copy_id;
    out_mc_copy_id = mc_copy_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_gibraltar::release_mc_copy_id(const member_t& member, const la_system_port_wcptr& dsp_sptr)
{
    la_status status;
    auto adsp = get_actual_dsp(dsp_sptr);
    la_slice_id_t dest_slice = adsp->get_slice();

    const la_l2_destination* destination = member.l2_dest.get();
    la_l2_destination_wcptr dest_wcptr = m_device->get_sptr(destination);
    const auto& ac_port = dest_wcptr.weak_ptr_static_cast<const la_l2_service_port_base>();

    if (member.l3_port == nullptr && ac_port->get_port_type() != la_l2_service_port_base::port_type_e::PWE) {
        return LA_STATUS_SUCCESS;
    }

    member_t amember(member.l2_dest); // actual member has only l2_dest
    const auto& mc_copy_id_it = m_mc_copy_id_mapping[dest_slice].find(amember);
    if (mc_copy_id_it == m_mc_copy_id_mapping[dest_slice].end()) {
        log_err(HLD,
                "%s:%d: GID:0x%x: cannot find <%s> in m_mc_copy_id_mapping list",
                __func__,
                __LINE__,
                get_gid(),
                amember.to_string().c_str());
        return LA_STATUS_EUNKNOWN;
    }
    uint64_t mc_copy_id = mc_copy_id_it->second;
    if (member.vxlan_type != la_multicast_group_common_base::vxlan_type_e::INVALID) {
        uint64_t cud_entry_index = mc_copy_id_manager::mc_copy_id_2_cud_entry_index(mc_copy_id);
        status = m_device->m_cud_range_manager[dest_slice]->release(cud_entry_index);
    } else {
        status = m_device->m_mc_copy_id_manager[dest_slice]->release_mc_copy_id(mc_copy_id);
    }
    return_on_error(status);
    m_mc_copy_id_mapping[dest_slice].erase(mc_copy_id_it);
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_gibraltar::add(const la_l2_destination* vxlan_port, la_next_hop* next_hop, const la_system_port* dsp)
{

    transaction txn;

    auto vxlan_port_sptr = m_device->get_sptr(vxlan_port);
    auto dsp_sptr = la_system_port_base::upcast_from_api(m_device, dsp);

    if ((vxlan_port_sptr == nullptr) || (dsp_sptr == nullptr)) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(vxlan_port_sptr, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (dsp->get_device() != m_device) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_multicast_group_common_base::group_member_desc member(vxlan_port_sptr);

    auto it = std::find(m_members.begin(), m_members.end(), member);
    if (it != m_members.end()) {
        return LA_STATUS_EEXIST;
    }

    if (vxlan_port_sptr->type() != la_object::object_type_e::L2_SERVICE_PORT) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    auto ac_port = std::static_pointer_cast<const la_l2_service_port_base>(vxlan_port_sptr);
    if (ac_port->get_port_type() != la_l2_service_port_base::port_type_e::VXLAN) {
        return LA_STATUS_EINVAL;
    }

    member.next_hop = m_device->get_sptr(next_hop);
    member.vxlan_type = la_multicast_group_common_base::vxlan_type_e::L2_VXLAN;

    uint64_t mc_copy_id;
    txn.status = get_mc_copy_id(member, dsp_sptr, false, mc_copy_id);
    return_on_error(txn.status);

    txn.status = configure_cud_mapping(member, dsp_sptr, mc_copy_id);
    return_on_error(txn.status);
    txn.on_fail([=]() { release_mc_copy_id(member, dsp_sptr); });

    txn.status = configure_egress_rep(member, dsp_sptr, mc_copy_id);
    return_on_error(txn.status);
    txn.on_fail([=]() { teardown_cud_mapping(member, dsp_sptr); });

    dassert_crit(m_dsp_mapping.find(member) == m_dsp_mapping.end());
    m_dsp_mapping[member] = dsp_sptr;

    auto adsp = get_actual_dsp(dsp_sptr);
    la_slice_id_t dest_slice = adsp->get_slice();
    txn.status = process_slice_addition(dest_slice);
    return_on_error(txn.status);

    m_device->add_object_dependency(dsp_sptr, this);
    m_device->add_object_dependency(vxlan_port_sptr, this);
    m_members.push_back(member);
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_gibraltar::remove_cud_table_entry(const la_l2_destination* destination, const la_system_port_wcptr& dsp)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_l2_multicast_group_gibraltar::configure_stack_copy_cud_mapping(la_slice_id_t slice, uint64_t mc_copy_id)
{
    const auto& table(m_device->m_tables.mc_cud_table[slice]);
    npl_mc_cud_table_key_t key;
    npl_mc_cud_table_value_t value;
    npl_mc_cud_table_entry_wptr_t entry;
    npl_l2_mc_cud_narrow_t payload;

    key.cud_mapping_local_vars_exp_mc_copy_id_14_1_ = mc_copy_id_manager::get_mc_cud_table_key(mc_copy_id);
    value.action = NPL_MC_CUD_TABLE_ACTION_UPDATE;
    payload.l2_encapsulation_type = NPL_NPU_ENCAP_L2_HEADER_TYPE_SVL;
    payload.l2_ac_encdap.l2_dlp.l2_dlp.id = 0;

    la_status status = table->lookup(key, entry);
    if ((status != LA_STATUS_SUCCESS) && (status != LA_STATUS_ENOTFOUND)) {
        // Unexpected failure
        return status;
    }

    if (status == LA_STATUS_SUCCESS) {
        value = entry->value();
    }

    value.payloads.update.mapped_cud_is_narrow = 1;

    npl_l2_mc_cud_narrow_t& target_encap_header = ((mc_copy_id & 1) == 0)
                                                      ? value.payloads.update.mapped_cud.app_mc_cud_narrow_odd_and_even.even.l2
                                                      : value.payloads.update.mapped_cud.app_mc_cud_narrow_odd_and_even.odd.l2;
    target_encap_header = payload;

    return table->set(key, value, entry);
}

} // namespace silicon_one
