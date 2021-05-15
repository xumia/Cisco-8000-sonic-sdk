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
#include "npu/la_ethernet_port_base.h"
#include "npu/la_ip_multicast_group_akpg.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_svi_port_base.h"
#include "npu/mc_copy_id_manager.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"
#include "system/la_system_port_akpg.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "la_strings.h"

namespace silicon_one
{

la_ip_multicast_group_akpg::la_ip_multicast_group_akpg(const la_device_impl_wptr& device) : la_ip_multicast_group_base(device)
{
}

la_ip_multicast_group_akpg::~la_ip_multicast_group_akpg()
{
}

la_status
la_ip_multicast_group_akpg::allocate_mc_copy_id(const member_t& member, la_slice_id_t dest_slice, uint64_t& out_mc_copy_id)
{
    const auto& l2_ac = member.l2_dest.weak_ptr_static_cast<const la_l2_service_port_base>();
    if ((l2_ac != nullptr) && (l2_ac->get_port_type() != la_l2_service_port_base::port_type_e::VXLAN)) {
        dassert_crit(member.l3_port != nullptr);
    }

    la_l3_port_wcptr l3_port = member.is_punt ? nullptr : member.l3_port;
    bool is_wide = false; // narrow for SVI and punt, don't care for L3-AC
    la_status status = m_device->m_mc_copy_id_manager[dest_slice]->get_mc_copy_id(l3_port, is_wide, out_mc_copy_id);
    return_on_error(status);

    dassert_crit(m_mc_copy_id_mapping[dest_slice].find(member) == m_mc_copy_id_mapping[dest_slice].end());
    m_mc_copy_id_mapping[dest_slice][member] = out_mc_copy_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_akpg::release_mc_copy_id(const member_t& member, la_slice_id_t dest_slice)
{
    const auto& mc_copy_id_it = m_mc_copy_id_mapping[dest_slice].find(member);
    if (mc_copy_id_it == m_mc_copy_id_mapping[dest_slice].end()) {
        log_err(HLD, "member not found in mc_copy_id mapping");

        return LA_STATUS_EUNKNOWN;
    }

    uint64_t mc_copy_id = mc_copy_id_it->second;

    la_status status = m_device->m_mc_copy_id_manager[dest_slice]->release_mc_copy_id(mc_copy_id);
    return_on_error(status);

    m_mc_copy_id_mapping[dest_slice].erase(mc_copy_id_it);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_akpg::configure_cud_mapping(const member_t& member, la_slice_id_t dest_slice, uint64_t mc_copy_id)
{
    if ((member.l3_port != nullptr) && (member.l3_port->type() == la_object::object_type_e::L3_AC_PORT)
        && (member.is_punt == false)) {
        // No CUD mapping is needed for L3-AC if not egress punt
        return LA_STATUS_SUCCESS;
    }

    if (member.stackport != nullptr) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    la_status status = m_mc_common->configure_cud_mapping(member, dest_slice, mc_copy_id);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_multicast_group_akpg::teardown_cud_mapping(const member_t& member, la_slice_id_t dest_slice, uint64_t mc_copy_id)
{
    la_status status = m_mc_common->teardown_cud_mapping(member, dest_slice, mc_copy_id);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}
} // namespace silicon_one
