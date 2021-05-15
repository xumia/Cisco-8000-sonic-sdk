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

#include <algorithm>

#include "api/npu/la_l3_port.h"
#include "api/npu/la_mpls_nhlfe.h"
#include "api/types/la_ip_types.h"
#include "la_asbr_lsp_impl.h"
#include "la_destination_pe_impl.h"
#include "la_ip_tunnel_destination_impl.h"
#include "la_l3_fec_impl.h"
#include "la_l3_protection_group_impl.h"
#include "la_te_tunnel_impl.h"
#include "nplapi/npl_constants.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_next_hop_base.h"
#include "npu/la_pbts_group_impl.h"
#include "npu/la_prefix_object_base.h"
#include "resolution_utils.h"
#include "system/la_device_impl.h"
#include "system/la_pbts_map_profile_impl.h"

#include "hld_types.h"
#include "hld_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

using namespace std;
namespace silicon_one
{

la_pbts_group_impl::la_pbts_group_impl(const la_device_impl_wptr& device) : m_device(device), m_profile(nullptr)
{
}

la_pbts_group_impl::~la_pbts_group_impl()
{
}

la_status
la_pbts_group_impl::initialize(la_object_id_t oid, la_pbts_map_profile* profile)
{
    m_oid = oid;
    m_profile = m_device->get_sptr<la_pbts_map_profile_impl>(const_cast<la_pbts_map_profile*>(profile));

    return LA_STATUS_SUCCESS;
}

la_status
la_pbts_group_impl::destroy()
{
    return LA_STATUS_SUCCESS;
}

destination_id
la_pbts_group_impl::get_destination_id(resolution_step_e prev_step) const
{
    uint64_t profile_id;
    m_profile->get_profile_id(profile_id);
    return destination_id(NPL_DESTINATION_MASK_CE_PTR | m_first_dest_gid | profile_id);
}

lpm_destination_id
la_pbts_group_impl::get_lpm_destination_id(resolution_step_e prev_step) const
{
    uint64_t profile_id;
    m_profile->get_profile_id(profile_id);
    return lpm_destination_id(NPL_LPM_COMPRESSED_DESTINATION_CE_PTR_MASK | m_first_dest_gid | profile_id);
}

la_status
la_pbts_group_impl::uninstantiate(resolution_step_e prev_step)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_pbts_group_impl::instantiate(resolution_step_e prev_step)
{
    return LA_STATUS_SUCCESS;
}

void
la_pbts_group_impl::add_dependency(const la_l3_destination_wcptr& destination)
{
}

void
la_pbts_group_impl::remove_dependency(const la_l3_destination_wcptr& destination)
{
}

void
la_pbts_group_impl::register_attribute_dependency(const la_l3_destination_wcptr& destination)
{
}

void
la_pbts_group_impl::deregister_attribute_dependency(const la_l3_destination_wcptr& destination)
{
}

la_status
la_pbts_group_impl::update_dependent_attributes(dependency_management_op op)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_pbts_group_impl::notify_change(dependency_management_op op)
{
    return LA_STATUS_SUCCESS;
}

const la_pbts_map_profile*
la_pbts_group_impl::get_profile() const
{
    return m_profile.get();
}

la_status
la_pbts_group_impl::get_member(la_pbts_destination_offset offset, const la_l3_destination*& out_member) const
{
    start_api_getter_call("");

    return LA_STATUS_SUCCESS;
}

la_status
la_pbts_group_impl::set_member(la_pbts_destination_offset offset, const la_l3_destination* member)
{
    start_api_call("offset=", offset, "member", member);

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_pbts_group_impl::type() const
{
    return object_type_e::PBTS_GROUP;
}

std::string
la_pbts_group_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_pbts_group_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_pbts_group_impl::oid() const
{
    return m_oid;
}

la_device*
la_pbts_group_impl::get_device() const
{
    return m_device.get();
}
}
