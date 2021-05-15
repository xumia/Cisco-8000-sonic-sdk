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

#include "la_l2_multicast_group_pacific.h"
#include "system/cud_range_manager.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

la_l2_multicast_group_pacific::la_l2_multicast_group_pacific(la_device_impl_wptr device) : la_l2_multicast_group_base(device)
{
}

la_l2_multicast_group_pacific::~la_l2_multicast_group_pacific()
{
}

la_status
la_l2_multicast_group_pacific::get_mc_copy_id(const member_t& member,
                                              const la_system_port_wcptr& dsp_sptr,
                                              bool is_wide,
                                              uint64_t& out_mc_copy_id)
{
    if (member.stackport != nullptr) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    la_status status;
    auto adsp = get_actual_dsp(dsp_sptr);
    la_slice_id_t dest_slice = adsp->get_slice();

    if (member.l3_port == nullptr) {
        // get mc_copy_id from L2_DLP range
        const la_l2_destination* destination = member.l2_dest.get();
        la_l2_destination_wcptr dest_wcptr = m_device->get_sptr(destination);
        const auto& ac_port = dest_wcptr.weak_ptr_static_cast<const la_l2_service_port_base>();

        if (ac_port == nullptr) {
            return LA_STATUS_EINVAL;
        }

        if (ac_port->get_port_type() == la_l2_service_port_base::port_type_e::PWE) {
            uint64_t cud_entry_index;
            status = m_device->m_cud_range_manager[dest_slice]->allocate(is_wide, cud_entry_index);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "mc_copy_id allocation failed %s", la_status2str(status).c_str());
                return status;
            }

            out_mc_copy_id = mc_copy_id_manager::cud_entry_index_2_mc_copy_id(cud_entry_index);

            member_t amember(member.l2_dest); // actual member has only l2_dest
            dassert_crit(m_mc_copy_id_mapping[dest_slice].find(amember) == m_mc_copy_id_mapping[dest_slice].end());
            m_mc_copy_id_mapping[dest_slice][amember] = out_mc_copy_id;

        } else {
            out_mc_copy_id = ac_port->get_gid();
            return LA_STATUS_SUCCESS;
        }

    } else {
        // get mc_copy_id from CUD Mapping range
        if ((member.l3_port == nullptr) || (member.l3_port->type() != object_type_e::SVI_PORT)) {
            return LA_STATUS_EINVAL;
        }
        uint64_t cud_entry_index;
        status = m_device->m_cud_range_manager[dest_slice]->allocate(is_wide, cud_entry_index);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "mc_copy_id allocation failed %s", la_status2str(status).c_str());
            return status;
        }

        out_mc_copy_id = mc_copy_id_manager::cud_entry_index_2_mc_copy_id(cud_entry_index);

        member_t amember(member.l2_dest); // actual member has only l2_dest
        dassert_crit(m_mc_copy_id_mapping[dest_slice].find(amember) == m_mc_copy_id_mapping[dest_slice].end());
        m_mc_copy_id_mapping[dest_slice][amember] = out_mc_copy_id;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_pacific::release_mc_copy_id(const member_t& member, const la_system_port_wcptr& dsp_sptr)
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

    // release mc_copy_id from CUD Mapping range
    member_t amember(member.l2_dest);
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
    uint64_t cud_entry_index = mc_copy_id_manager::mc_copy_id_2_cud_entry_index(mc_copy_id);
    status = m_device->m_cud_range_manager[dest_slice]->release(cud_entry_index);
    return_on_error(status);

    m_mc_copy_id_mapping[dest_slice].erase(mc_copy_id_it);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_multicast_group_pacific::add_to_mc_copy_id_table(const member_t& member, const la_system_port_wcptr& dsp)
{
    const la_l2_destination* destination = member.l2_dest.get();
    la_l2_destination_wcptr dest_wcptr = m_device->get_sptr(destination);
    const auto& ac_port = dest_wcptr.weak_ptr_static_cast<const la_l2_service_port_base>();
    return m_device->add_to_mc_copy_id_table(ac_port, dsp);
}

la_status
la_l2_multicast_group_pacific::remove_from_mc_copy_id_table(const member_t& member, const la_system_port_wcptr& dsp)
{
    const la_l2_destination* destination = member.l2_dest.get();
    la_l2_destination_wcptr dest_wcptr = m_device->get_sptr(destination);
    const auto& ac_port = dest_wcptr.weak_ptr_static_cast<const la_l2_service_port_base>();
    return m_device->remove_from_mc_copy_id_table(ac_port, dsp);
}

la_status
la_l2_multicast_group_pacific::add(const la_l2_destination* vxlan_port, la_next_hop* next_hop, const la_system_port* dsp)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_l2_multicast_group_pacific::remove_cud_table_entry(const la_l2_destination* destination, const la_system_port_wcptr& dsp)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_l2_multicast_group_pacific::configure_stack_copy_cud_mapping(la_slice_id_t slice, uint64_t mc_copy_id)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

} // namespace silicon_one
