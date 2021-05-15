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

    m_device->add_object_dependency(m_profile, m_device->get_sptr(this));

    la_pbts_destination_offset offset;
    la_status status = profile->get_size(offset);
    return_on_error(status);

    m_l3_destinations.assign(offset.value + 1, nullptr);

    return LA_STATUS_SUCCESS;
}

la_status
la_pbts_group_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    uint64_t profile_id;
    m_profile->get_profile_id(profile_id);
    auto lpm_gid = lpm_destination_id(NPL_LPM_COMPRESSED_DESTINATION_CE_PTR_MASK | m_first_dest_gid | profile_id);
    m_device->m_l3_destinations[lpm_gid.val] = nullptr;

    for (const auto& dest : m_l3_destinations) {
        if (dest != nullptr) {
            deregister_attribute_dependency(dest);
            remove_dependency(dest);

            la_status status = uninstantiate_resolution_object(dest, RESOLUTION_STEP_STAGE0_PBTS_GROUP);
            return_on_error(status);
        }
    }

    m_device->remove_object_dependency(m_profile, m_device->get_sptr(this));
    return LA_STATUS_SUCCESS;
}

la_status
la_pbts_group_impl::uninstantiate(resolution_step_e prev_step)
{
    if (m_user_count > 0) {
        m_user_count--;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_pbts_group_impl::instantiate(resolution_step_e prev_step)
{
    transaction txn;

    if ((prev_step != RESOLUTION_STEP_FORWARD_L3) && (prev_step != RESOLUTION_STEP_FORWARD_MPLS)) {
        return LA_STATUS_EINVAL;
    }

    if (m_user_count > 0) {
        m_user_count++;
        return LA_STATUS_SUCCESS;
    }

    la_fwd_class_id fcid;
    la_pbts_destination_offset offset;

    for (int value = 0; value < 8; value++) {
        fcid.value = value;
        m_profile->get_mapping(fcid, offset);

        if (m_l3_destinations[offset.value] == nullptr) {
            log_err(HLD, "One or more destinations in the PBTS Group is invalid");
            return LA_STATUS_EINVAL;
        }
    }

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

void
la_pbts_group_impl::add_dependency(const la_l3_destination_wcptr& destination)
{
    m_device->add_object_dependency(destination, m_device->get_sptr(this));
    register_attribute_dependency(destination);
}

void
la_pbts_group_impl::remove_dependency(const la_l3_destination_wcptr& destination)
{
    deregister_attribute_dependency(destination);
    m_device->remove_object_dependency(destination, m_device->get_sptr(this));
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

    if (offset.value >= m_l3_destinations.size()) {
        log_err(HLD, "Failed flow (member_idx >= m_l3_destinations.size()), returning EOUTOFRANGE");
        return LA_STATUS_EOUTOFRANGE;
    }

    out_member = m_l3_destinations[offset.value].get();
    return LA_STATUS_SUCCESS;
}

la_status
la_pbts_group_impl::set_member(la_pbts_destination_offset offset, const la_l3_destination* member)
{
    start_api_call("offset=", offset, "member", member);

    if (offset.value >= m_l3_destinations.size()) {
        log_err(HLD, "Failed flow (member_idx >= m_l3_destinations.size()), returning EOUTOFRANGE");
        return LA_STATUS_EOUTOFRANGE;
    }

    if (member->get_device() != m_device) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if ((member->type() != la_object::object_type_e::PREFIX_OBJECT)
        && (member->type() != la_object::object_type_e::DESTINATION_PE)) {
        log_err(HLD, "Unsupported Member Type");
        return LA_STATUS_EINVAL;
    }

    const la_prefix_object_base* pfx = static_cast<const la_prefix_object_base*>(member);

    if (!pfx->is_pbts_eligible()) {
        log_err(HLD, "Member GID out of supported range");
        return LA_STATUS_EINVAL;
    }

    la_l3_destination_gid_t gid = pfx->get_gid();
    uint MASK = 0x3; // LSB Two bits
    if ((gid & MASK) != (offset.value & MASK)) {
        log_err(HLD, "Member GID LSB doesn't match offset");
        return LA_STATUS_EINVAL;
    }

    int index = offset.value;
    if (m_gid_valid == false) {
        // Initialize the GID range for this Group.
        m_first_dest_gid = (gid - index);
        m_gid_valid = true;

        uint64_t profile_id;
        m_profile->get_profile_id(profile_id);
        auto lpm_gid = lpm_destination_id(NPL_LPM_COMPRESSED_DESTINATION_CE_PTR_MASK | m_first_dest_gid | profile_id);
        m_device->m_l3_destinations[lpm_gid.val] = m_device->get_sptr(this);

    } else {
        // Check if destination GID is valid at the given offset.
        if ((offset.value + m_first_dest_gid) != gid) {
            return LA_STATUS_EOUTOFRANGE;
        }
    }

    la_status status = instantiate_resolution_object(m_device->get_sptr(member), RESOLUTION_STEP_STAGE0_PBTS_GROUP);
    return_on_error(status);

    auto l3_destination_sptr = m_device->get_sptr<const la_l3_destination>(member);
    if (m_l3_destinations[index] != nullptr) {
        // Clear old destination mappings
        deregister_attribute_dependency(m_l3_destinations[index]);
        remove_dependency(m_l3_destinations[index]);
    }

    add_dependency(l3_destination_sptr);
    register_attribute_dependency(l3_destination_sptr);

    m_l3_destinations[index] = l3_destination_sptr;

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
