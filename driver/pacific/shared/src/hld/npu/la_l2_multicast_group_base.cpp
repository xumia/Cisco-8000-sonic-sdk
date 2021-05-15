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

#include "la_l2_multicast_group_base.h"
#include "api/system/la_spa_port.h"
#include "common/transaction.h"
#include "npu/la_ac_port_common.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_stack_port_base.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"
#include <sstream>

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "la_strings.h"

namespace silicon_one
{

la_l2_multicast_group_base::la_l2_multicast_group_base(la_device_impl_wptr device)
    : m_device(device), m_gid((la_multicast_group_gid_t)-1), m_slice_use_count{0}, m_mmcg_l3_port(nullptr), m_ref_count(0)
{
}

la_l2_multicast_group_base::~la_l2_multicast_group_base()
{
}

la_status
la_l2_multicast_group_base::initialize(la_object_id_t oid,
                                       la_multicast_group_gid_t multicast_gid,
                                       la_replication_paradigm_e rep_paradigm)
{

    if (rep_paradigm == la_replication_paradigm_e::INGRESS) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    m_oid = oid;
    m_gid = multicast_gid;
    m_rep_paradigm = rep_paradigm;
    m_mmcg_l3_port = nullptr;

    la_status status = m_device->create_multicast_group_common(m_mc_common);
    return_on_error(status);

    status = m_mc_common->initialize(multicast_gid, multicast_gid, rep_paradigm, false /* is_scale_mode_smcid */);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_base::destroy()
{
    la_status status;
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    std::vector<member_t> temp(m_members);
    std::reverse_iterator<std::vector<member_t>::iterator> rit;

    for (rit = temp.rbegin(); rit != temp.rend(); rit++) {
        auto member = *rit;
        status = remove(member.l2_dest.get());
        return_on_error(status);
    }

    status = m_mc_common->destroy();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_l2_multicast_group_base::type() const
{
    return la_object::object_type_e::L2_MULTICAST_GROUP;
}

std::string
la_l2_multicast_group_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_l2_multicast_group_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_l2_multicast_group_base::oid() const
{
    return m_oid;
}

const la_device*
la_l2_multicast_group_base::get_device() const
{
    return m_device.get();
}

la_multicast_group_gid_t
la_l2_multicast_group_base::get_gid() const
{
    return m_gid;
}

la_status
la_l2_multicast_group_base::add(const la_l2_destination* destination, const la_system_port* dsp)
{
    start_api_call("destination=", destination, "dsp=", dsp);

    la_status status;

    auto destination_sptr = m_device->get_sptr(destination);
    auto dsp_sptr = la_system_port_base::upcast_from_api(m_device, dsp);

    if (destination_sptr == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(destination_sptr, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_multicast_group_common_base::group_member_desc member(destination_sptr);

    auto it = std::find(m_members.begin(), m_members.end(), member);
    if (it != m_members.end()) {
        return LA_STATUS_EEXIST;
    }

    if (destination_sptr->type() != la_object::object_type_e::L2_SERVICE_PORT) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    auto ac_port = std::static_pointer_cast<const la_l2_service_port_base>(destination_sptr);
    if (ac_port->get_port_type() == la_l2_service_port_base::port_type_e::AC) {
        auto eth = ac_port->get_ethernet_port();
        status = m_mc_common->verify_dsp(eth, dsp_sptr);
        return_on_error(status);
    } else if (ac_port->get_port_type() != la_l2_service_port_base::port_type_e::PWE) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    uint64_t mc_copy_id;
    if (m_mmcg_l3_port == nullptr) {
        if (ac_port->get_port_type() == la_l2_service_port_base::port_type_e::AC) {
            status = get_mc_copy_id(member, dsp_sptr, false, mc_copy_id);
            return_on_error(status);
            status = configure_egress_rep(member, dsp_sptr, mc_copy_id);
            return_on_error(status);
            status = add_to_mc_copy_id_table(member, dsp_sptr);
            return_on_error(status);
        } else if (ac_port->get_port_type() == la_l2_service_port_base::port_type_e::PWE) {
            add_pwe(member, dsp_sptr);
        } else {
            return LA_STATUS_ENOTIMPLEMENTED;
        }

    } else {
        if (ac_port->get_port_type() == la_l2_service_port_base::port_type_e::PWE) {
            return LA_STATUS_ENOTIMPLEMENTED;
        }
        member_t tmp_member(m_mmcg_l3_port, destination_sptr);
        status = get_mc_copy_id(tmp_member, dsp_sptr, false, mc_copy_id);
        return_on_error(status);
        status = configure_cud_mapping(tmp_member, dsp_sptr, mc_copy_id);
        return_on_error(status);
        status = configure_egress_rep(member, dsp_sptr, mc_copy_id);
        return_on_error(status);
    }

    auto adsp = get_actual_dsp(dsp_sptr);
    la_slice_id_t dest_slice = adsp->get_slice();
    status = process_slice_addition(dest_slice);
    return_on_error(status);

    dassert_crit(m_dsp_mapping.find(member) == m_dsp_mapping.end());
    m_dsp_mapping[member] = dsp_sptr;

    m_device->add_object_dependency(destination_sptr, this);
    m_device->add_object_dependency(dsp_sptr, this);
    m_members.push_back(member);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_base::add_pwe(const member_t& member, const la_system_port_wcptr& dsp_sptr)
{
    la_status status;
    transaction txn;

    uint64_t mc_copy_id;
    txn.status = get_mc_copy_id(member, dsp_sptr, true, mc_copy_id);
    return_on_error(txn.status);
    txn.on_fail([&]() { /*release_mc_copy_id(member, dsp); */ });

    txn.status = configure_cud_mapping(member, dsp_sptr, mc_copy_id);
    return_on_error(txn.status);
    txn.on_fail([&]() { teardown_cud_mapping(member, dsp_sptr); });

    status = configure_egress_rep(member, dsp_sptr, mc_copy_id);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_base::add(const la_stack_port* stackport, const la_system_port* dsp)
{
    start_api_call("stackport=", stackport, "dsp=", dsp);
    la_status status;

    auto stackport_sptr = m_device->get_sptr(stackport);
    auto dsp_sptr = la_system_port_base::upcast_from_api(m_device, dsp);

    if (stackport_sptr == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(stackport_sptr, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_multicast_group_common_base::group_member_desc member(stackport_sptr);

    auto it = std::find(m_members.begin(), m_members.end(), member);
    if (it != m_members.end()) {
        return LA_STATUS_EEXIST;
    }

    if (dsp_sptr == nullptr) {
        return LA_STATUS_EINVAL;
    }

    auto stackport_base = m_device->get_sptr<la_stack_port_base>(stackport);
    if (!stackport_base->is_member(dsp_sptr)) {
        return LA_STATUS_EINVAL;
    }

    uint64_t mc_copy_id;
    status = get_mc_copy_id(member, dsp_sptr, false, mc_copy_id);
    return_on_error(status);

    auto adsp = get_actual_dsp(dsp_sptr);
    la_slice_id_t dest_slice = adsp->get_slice();

    status = configure_stack_copy_cud_mapping(dest_slice, mc_copy_id);
    return_on_error(status);

    status = m_mc_common->configure_egress_rep_common(member, adsp, mc_copy_id);
    return_on_error(status);

    status = process_slice_addition(dest_slice);
    return_on_error(status);

    dassert_crit(m_dsp_mapping.find(member) == m_dsp_mapping.end());
    m_dsp_mapping[member] = dsp_sptr;

    m_device->add_object_dependency(stackport_sptr, this);
    m_device->add_object_dependency(dsp_sptr, this);
    m_members.push_back(member);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_base::remove(const la_l2_destination* destination)
{
    start_api_call("destination=", destination);

    auto destination_sptr = m_device->get_sptr(destination);
    if (destination_sptr == nullptr) {
        return LA_STATUS_EINVAL;
    }

    auto ac_port = std::static_pointer_cast<const la_l2_service_port_base>(destination_sptr);
    la_multicast_group_common_base::group_member_desc member(destination_sptr);

    auto it = std::find(m_members.begin(), m_members.end(), member);
    if (it == m_members.end()) {
        log_err(HLD, "la_l2_multicast_group_base::remove: member not found %s\n", silicon_one::to_string(destination_sptr).c_str());
        return LA_STATUS_ENOTFOUND;
    }

    auto dsp_it = m_dsp_mapping.find(member);
    if (dsp_it == m_dsp_mapping.end()) {
        log_err(HLD, "la_l2_multicast_group_base::remove: dsp not found\n");
        return LA_STATUS_EUNKNOWN;
    }

    const auto& dsp = dsp_it->second;

    m_device->remove_object_dependency(dsp, this);
    m_device->remove_object_dependency(destination_sptr, this);

    la_status status;
    if (ac_port->get_port_type() == la_l2_service_port_base::port_type_e::VXLAN
        || ac_port->get_port_type() == la_l2_service_port_base::port_type_e::PWE) {
        status = teardown_egress_rep(member, dsp);
        return_on_error(status);
        status = teardown_cud_mapping(member, dsp);
        return_on_error(status);
        status = release_mc_copy_id(member, dsp);
        return_on_error(status);
    } else {
        if (m_mmcg_l3_port == nullptr) {
            status = remove_from_mc_copy_id_table(member, dsp);
            return_on_error(status);
            status = teardown_egress_rep(member, dsp);
            return_on_error(status);
            status = release_mc_copy_id(member, dsp);
            return_on_error(status);
        } else {
            member_t tmp_member(m_mmcg_l3_port, destination_sptr);
            status = teardown_egress_rep(member, dsp);
            return_on_error(status);
            status = teardown_cud_mapping(tmp_member, dsp);
            return_on_error(status);
            status = release_mc_copy_id(tmp_member, dsp);
            return_on_error(status);
        }
    }

    auto adsp = get_actual_dsp(dsp);
    la_slice_id_t dest_slice = adsp->get_slice();
    status = process_slice_removal(dest_slice);
    return_on_error(status);

    m_members.erase(it);
    m_dsp_mapping.erase(dsp_it);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_base::remove(const la_stack_port* stackport)
{
    start_api_call("stackport=", stackport);

    auto stackport_sptr = m_device->get_sptr(stackport);
    if (stackport_sptr == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_multicast_group_common_base::group_member_desc member(stackport_sptr);

    auto it = std::find(m_members.begin(), m_members.end(), member);
    if (it == m_members.end()) {
        log_err(HLD, "la_l2_multicast_group_base::remove: member not found %s\n", silicon_one::to_string(stackport_sptr).c_str());
        return LA_STATUS_ENOTFOUND;
    }

    auto dsp_it = m_dsp_mapping.find(member);
    if (dsp_it == m_dsp_mapping.end()) {
        log_err(HLD, "la_l2_multicast_group_base::remove: dsp not found\n");
        return LA_STATUS_EUNKNOWN;
    }

    const auto& dsp = dsp_it->second;

    m_device->remove_object_dependency(dsp, this);
    m_device->remove_object_dependency(stackport_sptr, this);

    la_status status = teardown_egress_rep(member, dsp);
    return_on_error(status);

    auto adsp = get_actual_dsp(dsp);
    la_slice_id_t dest_slice = adsp->get_slice();
    status = process_slice_removal(dest_slice);
    return_on_error(status);

    m_members.erase(it);
    m_dsp_mapping.erase(dsp_it);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_base::configure_egress_rep(const member_t& member, const la_system_port_wcptr& dsp, uint64_t mc_copy_id)
{
    la_status status = m_mc_common->configure_egress_rep_common(member, get_actual_dsp(dsp), mc_copy_id);
    return_on_error(status);

    return status;
}

la_status
la_l2_multicast_group_base::teardown_egress_rep(const member_t& member, const la_system_port_wcptr& dsp)
{
    la_status status = m_mc_common->teardown_egress_rep_common(member, get_actual_dsp(dsp));
    return_on_error(status);

    return status;
}

la_status
la_l2_multicast_group_base::get_member(size_t member_idx, const la_l2_destination*& out_destination) const
{
    start_api_getter_call();

    if (member_idx >= m_members.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    out_destination = m_members[member_idx].l2_dest.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_base::get_members(la_l2_destination_vec_t& out_l2_mcg_members) const
{
    start_api_getter_call();

    out_l2_mcg_members.clear();
    for (auto m : m_members) {
        out_l2_mcg_members.push_back(m.l2_dest.get());
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_base::get_size(size_t& out_size) const
{
    start_api_getter_call();

    out_size = m_members.size();
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_base::get_replication_paradigm(la_replication_paradigm_e& out_replication_paradigm) const
{
    start_api_getter_call();

    out_replication_paradigm = m_rep_paradigm;
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_base::set_destination_system_port(const la_l2_destination* destination, const la_system_port* dsp)
{
    start_api_call("destination=", destination, "dsp=", dsp);

    auto destination_sptr = m_device->get_sptr(destination);
    auto dsp_sptr = la_system_port_base::upcast_from_api(m_device, dsp);
    const auto& adsp = get_actual_dsp(dsp_sptr);

    if (destination_sptr == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_multicast_group_common_base::group_member_desc member(destination_sptr);

    auto ac_port = std::static_pointer_cast<const la_l2_service_port_base>(destination_sptr);
    auto eth = ac_port->get_ethernet_port();
    la_status status = m_mc_common->verify_dsp(eth, dsp_sptr);
    return_on_error(status);

    // Get the current DSP
    auto dsp_it = m_dsp_mapping.find(member);
    if (dsp_it == m_dsp_mapping.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    auto curr_dsp = la_system_port_base::upcast_from_api(m_device, dsp_it->second);
    la_slice_id_t curr_slice = curr_dsp->get_slice();
    uint64_t mc_copy_id = ac_port->get_gid();

    if (m_mmcg_l3_port == nullptr) {
        if (curr_slice != dsp_sptr->get_slice()) {
            status = m_device->add_to_mc_copy_id_table(ac_port, dsp_sptr);
            return_on_error(status);
        }

        const member_t dsp_member(nullptr, destination_sptr);
        status = m_mc_common->set_member_dsp(dsp_member, curr_dsp, adsp, mc_copy_id, mc_copy_id);
        return_on_error(status);

        if (curr_slice != dsp_sptr->get_slice()) {
            status = remove_from_mc_copy_id_table(member, curr_dsp);
            return_on_error(status);
        }
    } else {
        status = set_member_dsp(member, curr_dsp, dsp_sptr);
        return_on_error(status);
    }

    status = process_slice_removal(curr_slice);
    return_on_error(status);
    status = process_slice_addition(adsp->get_slice());
    return_on_error(status);

    m_device->remove_object_dependency(curr_dsp, this);
    m_device->add_object_dependency(dsp_sptr, this);
    m_dsp_mapping[member] = dsp_sptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_base::set_member_dsp(member_t member,
                                           const la_system_port_wcptr& curr_dsp_in,
                                           const la_system_port_wcptr& new_dsp_in)
{
    // This function is called only when m_mmcg_l3_port is non-null
    auto curr_dsp = la_system_port_base::upcast_from_api(m_device, curr_dsp_in);
    auto new_dsp = la_system_port_base::upcast_from_api(m_device, new_dsp_in);
    la_slice_id_t curr_slice = curr_dsp->get_slice();
    la_slice_id_t new_slice = new_dsp->get_slice();

    auto mc_copy_id_it = m_mc_copy_id_mapping[curr_slice].find(member);
    if (mc_copy_id_it == m_mc_copy_id_mapping[curr_slice].end()) {
        log_err(HLD,
                "%s:%d: GID:0x%x: cannot find <%s> in mc_copy_id_mapping list",
                __func__,
                __LINE__,
                get_gid(),
                member.to_string().c_str());
        return LA_STATUS_EUNKNOWN;
    }
    uint64_t mc_copy_id = mc_copy_id_it->second;
    auto adsp = get_actual_dsp(new_dsp);

    if (curr_slice == new_slice) {
        la_status status = m_mc_common->set_member_dsp(member, curr_dsp, adsp, mc_copy_id, mc_copy_id);
        return_on_error(status);
    } else {
        uint64_t new_mc_copy_id;
        member_t tmp_member(m_mmcg_l3_port, member.l2_dest);
        la_status status = get_mc_copy_id(tmp_member, new_dsp, false, new_mc_copy_id);
        return_on_error(status);
        status = configure_cud_mapping(tmp_member, new_dsp, new_mc_copy_id);
        return_on_error(status);
        status = m_mc_common->set_member_dsp(member, curr_dsp, adsp, mc_copy_id, new_mc_copy_id);
        return_on_error(status);
        status = teardown_cud_mapping(tmp_member, curr_dsp);
        return_on_error(status);
        status = release_mc_copy_id(tmp_member, curr_dsp);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_base::get_destination_system_port(const la_l2_destination* l2_destination,
                                                        const la_system_port*& out_dsp) const
{
    start_api_getter_call();

    auto l2_destination_sptr = m_device->get_sptr(l2_destination);

    if (l2_destination_sptr == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_multicast_group_common_base::group_member_desc member(l2_destination_sptr);

    auto dsp_it = m_dsp_mapping.find(member);
    if (dsp_it == m_dsp_mapping.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    const auto& dsp = dsp_it->second;
    out_dsp = dsp.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_base::transition_copyid_range(la_l3_port_wcptr l3_port)
{
    transaction txn;

    if (l3_port == nullptr) {
        m_ref_count--;
        if (m_ref_count != 0) {
            log_debug(
                HLD, "GID:0x%x, m_ref_count[%lu] is not zero, conitnue in CUD mapping range, return SUCCESS", m_gid, m_ref_count);
            return LA_STATUS_SUCCESS;
        }

        log_debug(HLD, "GID: 0x%x, m_ref_count[%lu], transition to L2_DLP range", m_gid, m_ref_count);
        txn.on_fail([=]() { m_ref_count++; });
    } else {
        if (m_ref_count != 0) {
            log_debug(HLD,
                      "GID:0x%x, has already transistioned to CUD mapping range, m_ref_count[%lu], return SUCCESS",
                      m_gid,
                      m_ref_count);
            m_ref_count++;
            return LA_STATUS_SUCCESS;
        }

        log_debug(HLD, "GID: 0x%x, m_ref_count[%lu], transition to CUD mapping range", m_gid, m_ref_count);
        m_ref_count++;
        txn.on_fail([=]() { m_ref_count--; });
    }

    uint64_t mc_copy_id, old_copy_id;

    for (member_t& member : m_members) {

        // skip for stack port
        if (member.stackport != nullptr) {
            continue;
        }

        auto dsp_it = m_dsp_mapping.find(member);
        if (dsp_it == m_dsp_mapping.end()) {
            log_err(HLD,
                    "%s:%d: GID:0x%x: cannot find <%s> in dsp_mapping list",
                    __func__,
                    __LINE__,
                    get_gid(),
                    member.to_string().c_str());
            return LA_STATUS_EUNKNOWN;
        }
        auto dsp = la_system_port_base::upcast_from_api(m_device, dsp_it->second);
        auto adsp = get_actual_dsp(dsp);
        la_slice_id_t dest_slice = adsp->get_slice();

        if (l3_port == nullptr) {
            auto mc_copy_id_it = m_mc_copy_id_mapping[dest_slice].find(member);
            if (mc_copy_id_it == m_mc_copy_id_mapping[dest_slice].end()) {
                log_err(HLD,
                        "%s:%d: GID:0x%x: cannot find <%s> in m_mc_copy_id_mapping list",
                        __func__,
                        __LINE__,
                        get_gid(),
                        member.to_string().c_str());
                return LA_STATUS_EUNKNOWN;
            }
            old_copy_id = mc_copy_id_it->second;

            if (member.vxlan_type != la_multicast_group_common_base::vxlan_type_e::INVALID) {
                member.vxlan_type = la_multicast_group_common_base::vxlan_type_e::L2_VXLAN;
                la_status status = configure_cud_mapping(member, dsp, old_copy_id);
                return_on_error(status);
            } else {
                /*transition mc_copy_id from cud range to l2_dlp range*/
                member_t tmp_member(m_mmcg_l3_port, member.l2_dest);
                txn.status = get_mc_copy_id(member, dsp, false, mc_copy_id);
                return_on_error(txn.status);
                txn.on_fail([=]() { release_mc_copy_id(member, dsp); });

                txn.status = m_mc_common->reconfigure_mcemdb_entry(member, dsp, mc_copy_id);
                return_on_error(txn.status);
                txn.on_fail([=]() { m_mc_common->reconfigure_mcemdb_entry(member, dsp, old_copy_id); });

                txn.status = add_to_mc_copy_id_table(member, dsp);
                return_on_error(txn.status);
                txn.on_fail([=]() { remove_from_mc_copy_id_table(member, dsp); });

                txn.status = teardown_cud_mapping(tmp_member, dsp);
                return_on_error(txn.status);
                txn.on_fail([=]() { configure_cud_mapping(tmp_member, dsp, old_copy_id); });

                // release mc_copy_id - done outside the loop, so rollback is easy.
                // If mc_copy_id is released inside the loop then, there no guarantee
                // the same copy_id will be allocated.
                // And old_mc_copy_id cannot be used in rollback
            }
        } else {
            if (member.vxlan_type != la_multicast_group_common_base::vxlan_type_e::INVALID) {
                auto mc_copy_id_it = m_mc_copy_id_mapping[dest_slice].find(member);
                if (mc_copy_id_it == m_mc_copy_id_mapping[dest_slice].end()) {
                    log_err(HLD,
                            "%s:%d: GID:0x%x: cannot find <%s> in m_mc_copy_id_mapping list",
                            __func__,
                            __LINE__,
                            get_gid(),
                            member.to_string().c_str());
                    return LA_STATUS_EUNKNOWN;
                }
                old_copy_id = mc_copy_id_it->second;

                member.vxlan_type = la_multicast_group_common_base::vxlan_type_e::L3_VXLAN;
                la_status status = configure_cud_mapping(member, dsp, old_copy_id);
                return_on_error(status);
            } else {
                const la_l2_destination* destination = member.l2_dest.get();
                la_l2_destination_wcptr dest_wcptr = m_device->get_sptr(destination);
                const auto& ac_port = dest_wcptr.weak_ptr_static_cast<const la_l2_service_port_base>();
                old_copy_id = ac_port->get_gid();

                /*transition mc_copy_id from l2_dlp range to cud range*/
                member_t tmp_member(l3_port, member.l2_dest);
                txn.status = get_mc_copy_id(tmp_member, dsp, false, mc_copy_id);
                return_on_error(txn.status);
                txn.on_fail([=]() { release_mc_copy_id(tmp_member, dsp); });

                txn.status = configure_cud_mapping(tmp_member, dsp, mc_copy_id);
                return_on_error(txn.status);
                txn.on_fail([=]() { teardown_cud_mapping(tmp_member, dsp); });

                txn.status = m_mc_common->reconfigure_mcemdb_entry(member, dsp, mc_copy_id);
                return_on_error(txn.status);
                txn.on_fail([=]() { m_mc_common->reconfigure_mcemdb_entry(member, dsp, old_copy_id); });

                txn.status = remove_from_mc_copy_id_table(member, dsp);
                return_on_error(txn.status);
                txn.on_fail([=]() { add_to_mc_copy_id_table(member, dsp); });

                txn.status = release_mc_copy_id(member, dsp);
                return_on_error(txn.status);
            }
        }
    }

    if (l3_port == nullptr) {
        for (member_t& member : m_members) {
            if (member.vxlan_type != la_multicast_group_common_base::vxlan_type_e::INVALID) {
                continue;
            }
            auto dsp_it = m_dsp_mapping.find(member);
            if (dsp_it == m_dsp_mapping.end()) {
                log_err(HLD,
                        "%s:%d: GID:0x%x: cannot find <%s> in dsp_mapping list",
                        __func__,
                        __LINE__,
                        get_gid(),
                        member.to_string().c_str());
                return LA_STATUS_EUNKNOWN;
            }
            auto dsp = dsp_it->second;
            member_t tmp_member(m_mmcg_l3_port, member.l2_dest);

            txn.status = release_mc_copy_id(tmp_member, dsp);
            return_on_error(txn.status);
        }
    }

    m_mmcg_l3_port = l3_port;
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_base::configure_cud_mapping(const member_t& member, const la_system_port_wcptr& dsp_sptr, uint64_t mc_copy_id)
{
    auto adsp = get_actual_dsp(dsp_sptr);
    la_slice_id_t dest_slice = adsp->get_slice();

    la_status status = m_mc_common->configure_cud_mapping(member, dest_slice, mc_copy_id);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_base::teardown_cud_mapping(const member_t& member, const la_system_port_wcptr& dsp_sptr)
{
    auto adsp = get_actual_dsp(dsp_sptr);
    la_slice_id_t dest_slice = adsp->get_slice();

    member_t amember(member.l2_dest); // actual member has only l2_dest
    auto mc_copy_id_it = m_mc_copy_id_mapping[dest_slice].find(amember);
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

    la_status status = m_mc_common->teardown_cud_mapping(member, dest_slice, mc_copy_id);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

size_t
la_l2_multicast_group_base::get_slice_bitmap() const
{
    return m_mc_common->get_slice_bitmap();
}

la_status
la_l2_multicast_group_base::process_slice_addition(la_slice_id_t slice)
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
la_l2_multicast_group_base::process_slice_removal(la_slice_id_t slice)
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
la_l2_multicast_group_base::add_slice_user(la_slice_id_t slice)
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
la_l2_multicast_group_base::remove_slice_user(la_slice_id_t slice)
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
la_l2_multicast_group_base::notify_mcg_change_event(bool slice_added, la_slice_id_t slice)
{
    attribute_management_details amd;
    amd.op = attribute_management_op::MCG_MEMBER_LIST_CHANGED;
    amd.mcg_slice_update.slice_added = slice_added;
    amd.mcg_slice_update.slice = slice;
    amd.mcg_slice_update.l3_port = m_mmcg_l3_port.get();

    la_amd_undo_callback_funct_t undo = [](attribute_management_details amd) { return amd; };
    la_l2_multicast_group* l2_mcg = static_cast<la_l2_multicast_group*>(this);
    la_status status = m_device->notify_attribute_changed(l2_mcg, amd, undo);
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
