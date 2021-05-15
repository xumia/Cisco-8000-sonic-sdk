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

#include "la_pbts_map_profile_impl.h"
#include "api_tracer.h"
#include "common/logger.h"
#include "la_strings.h"
#include "npu/la_pbts_group_impl.h"

#include <sstream>

namespace silicon_one
{

la_pbts_map_profile_impl::la_pbts_map_profile_impl(const la_device_impl_wptr& device)
    : m_device(device), m_level(la_pbts_map_profile::level_e::LEVEL_0)
{
}

la_pbts_map_profile_impl::~la_pbts_map_profile_impl()
{
}

la_status
la_pbts_map_profile_impl::initialize(la_object_id_t oid, la_pbts_map_profile::level_e level, la_pbts_destination_offset max_offset)
{

    m_oid = oid;
    m_level = level;
    m_max_offset = max_offset;

    m_profile_id = 0;
    clear_profile();

    return LA_STATUS_SUCCESS;
}

la_status
la_pbts_map_profile_impl::destroy()
{
    clear_profile();

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_pbts_map_profile_impl::type() const
{
    return object_type_e::PBTS_MAP_PROFILE;
}

const la_device*
la_pbts_map_profile_impl::get_device() const
{
    return m_device.get();
}

la_object_id_t
la_pbts_map_profile_impl::oid() const
{
    return m_oid;
}

std::string
la_pbts_map_profile_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_pbts_map_profile(oid=" << m_oid << ")";
    return log_message.str();
}

la_status
la_pbts_map_profile_impl::clear_profile()
{
    la_fwd_class_id fcid;
    la_pbts_destination_offset offset;

    // Program all FCID to offset 0
    offset.value = 0;

    for (int i = 0; i < FCID_MAX_ID; i++) {
        fcid.value = i;
        set_mapping(fcid, offset);
    }

    return LA_STATUS_SUCCESS;
}

bool
la_pbts_map_profile_impl::valid_user_destinations(la_pbts_destination_offset offset)
{
    return true;
}

la_status
la_pbts_map_profile_impl::set_mapping(la_fwd_class_id fcid, la_pbts_destination_offset offset)
{
    start_api_call("fcid=", fcid, "offset=", offset);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_pbts_map_profile_impl::program_mapping_table(la_fwd_class_id fcid, la_pbts_destination_offset offset)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_pbts_map_profile_impl::get_mapping(la_fwd_class_id fcid, la_pbts_destination_offset& out_pbts_offset) const
{
    start_api_call("fcid=");

    return LA_STATUS_SUCCESS;
}

la_status
la_pbts_map_profile_impl::get_size(la_pbts_destination_offset& out_max_offset) const
{
    start_api_getter_call();
    out_max_offset = m_max_offset;
    return LA_STATUS_SUCCESS;
}

la_status
la_pbts_map_profile_impl::get_level(la_pbts_map_profile::level_e& out_level) const
{
    start_api_getter_call();
    out_level = m_level;
    return LA_STATUS_SUCCESS;
}

la_status
la_pbts_map_profile_impl::get_profile_id(uint64_t& out_profile_id) const
{
    start_api_getter_call();
    out_profile_id = m_profile_id;
    return LA_STATUS_SUCCESS;
}
}
