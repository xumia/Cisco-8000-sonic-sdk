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

#include "api/system/la_spa_port.h"
#include "api/types/la_ethernet_types.h"
#include "npu/la_counter_set_impl.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_ip_multicast_group_pacific.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_svi_port_base.h"
#include "npu/resolution_utils.h"
#include "system/counter_allocation.h"
#include "system/cud_range_manager.h"
#include "system/la_device_impl.h"
#include "system/la_system_port_pacific.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "la_strings.h"

namespace silicon_one
{

la_ip_multicast_group_pacific::la_ip_multicast_group_pacific(la_device_impl_wptr device) : la_ip_multicast_group_base(device)
{
}

la_ip_multicast_group_pacific::~la_ip_multicast_group_pacific()
{
}

la_status
la_ip_multicast_group_pacific::allocate_mc_copy_id(const member_t& member, la_slice_id_t dest_slice, uint64_t& out_mc_copy_id)
{
    uint64_t mc_copy_id;
    la_status status;

    if (member.counter != nullptr) { // MCG counter member case
        counter_allocation allocation;
        const auto& counter = member.counter.weak_ptr_static_cast<const la_counter_set_impl>();
        status = counter->get_allocation(dest_slice, COUNTER_DIRECTION_EGRESS, allocation);

        size_t bank_id = allocation.get_bank_id();
        size_t ptr_offset = allocation.get_index();
        size_t bank_profile;
        status = m_device->m_counter_bank_manager->get_mcg_bank_profile(bank_id, dest_slice, bank_profile);
        return_on_error_log(
            status, HLD, ERROR, "No allocated bank profile for MCG counter. slice = %u, bank_id = %lu", dest_slice, bank_id);

        mc_copy_id = (COUNTER_MC_COPY_ID_PREFIX << (COUNTER_PTR_BANK_PROFILE_WIDTH + COUNTER_PTR_WIDTH));
        mc_copy_id |= (bank_profile << COUNTER_PTR_WIDTH);
        mc_copy_id |= ptr_offset;

        status = m_device->add_to_mc_copy_id_table(dest_slice, mc_copy_id, bank_id);
        return_on_error(status);
    } else if ((member.l3_port != nullptr) && (member.l3_port->type() == object_type_e::L3_AC_PORT) && (member.is_punt == false)) {
        const auto& l3ac = member.l3_port.weak_ptr_static_cast<const la_l3_ac_port_impl>();
        mc_copy_id = (L3_AC_MC_COPY_ID_PREFIX
                      << (la_device_impl::L3_PORT_GID_NAMESPACE_WIDTH + la_device_impl::L3_PORT_GID_PROPERTIES_WIDTH))
                     | get_l3_dlp_value_from_gid(l3ac->get_gid());
        status = m_device->add_to_mc_copy_id_table(dest_slice, mc_copy_id);
        return_on_error(status);
    } else {
        bool is_wide = false;
        uint64_t cud_entry_index;
        status = m_device->m_cud_range_manager[dest_slice]->allocate(is_wide, cud_entry_index);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "mc_copy_id allocation failed %s", la_status2str(status).c_str());
            return status;
        }

        mc_copy_id = mc_copy_id_manager::cud_entry_index_2_mc_copy_id(cud_entry_index);
    }

    dassert_crit(m_mc_copy_id_mapping[dest_slice].find(member) == m_mc_copy_id_mapping[dest_slice].end());
    m_mc_copy_id_mapping[dest_slice][member] = mc_copy_id;
    out_mc_copy_id = mc_copy_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_pacific::release_mc_copy_id(const member_t& member, la_slice_id_t dest_slice)
{
    la_status status;
    const auto& mc_copy_id_it = m_mc_copy_id_mapping[dest_slice].find(member);
    if (mc_copy_id_it == m_mc_copy_id_mapping[dest_slice].end()) {
        log_err(HLD, "member not found in mc_copy_id mapping");

        return LA_STATUS_EUNKNOWN;
    }

    uint64_t mc_copy_id = mc_copy_id_it->second;

    if (((member.l3_port != nullptr) && (member.l3_port->type() == object_type_e::L3_AC_PORT) && (member.is_punt == false))
        || (member.counter != nullptr)) {
        status = m_device->remove_from_mc_copy_id_table(dest_slice, mc_copy_id);
        return_on_error(status);
    } else {
        uint64_t cud_entry_index = mc_copy_id_manager::mc_copy_id_2_cud_entry_index(mc_copy_id);

        status = m_device->m_cud_range_manager[dest_slice]->release(cud_entry_index);
        return_on_error(status);
    }

    m_mc_copy_id_mapping[dest_slice].erase(mc_copy_id_it);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_pacific::configure_cud_mapping(const member_t& member, la_slice_id_t dest_slice, uint64_t mc_copy_id)
{
    la_status status = m_mc_common->configure_cud_mapping(member, dest_slice, mc_copy_id);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_pacific::teardown_cud_mapping(const member_t& member, la_slice_id_t dest_slice, uint64_t mc_copy_id)
{
    la_status status = m_mc_common->teardown_cud_mapping(member, dest_slice, mc_copy_id);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
