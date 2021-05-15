// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "la_acl_command_profile_base.h"
#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

la_acl_command_profile_base::la_acl_command_profile_base(const la_device_impl_wptr& device) : m_device(device)
{
}

la_acl_command_profile_base::~la_acl_command_profile_base()
{
}

la_status
la_acl_command_profile_base::initialize(la_object_id_t oid, const la_acl_command_def_vec_t& command_def)
{
    m_oid = oid;
    la_acl_command_def_vec_t command_profile;
    m_acl_command = command_def;
    bool found_traffic_class = false;
    bool found_color = false;
    for (auto action : command_def) {
        switch (action.type) {
        case la_acl_action_type_e::TRAFFIC_CLASS:
            found_traffic_class = true;
            break;
        case la_acl_action_type_e::COLOR:
            found_color = true;
            break;
        default:
            break;
        }
    }

    if (found_traffic_class && !found_color) {
        log_err(HLD, "la_acl_command_profile_base::%s TRAFFIC_CLASS action can't be applied without COLOR action", __func__);
        return LA_STATUS_EINVAL;
    }
    if (!found_traffic_class && found_color) {
        log_err(HLD, "la_acl_command_profile_base::%s COLOR action can't be applied without TRAFFIC_CLASS action", __func__);
        return LA_STATUS_EINVAL;
    }
    for (int i = 0; i < NUM_ACL_COMMAND_PROFILES; i++) {
        m_device->get_acl_command_profile(i, command_profile);
        if (is_command_actions_subset(command_def, command_profile)) {
            return LA_STATUS_SUCCESS;
        }
/// TBD Yaniv - enable code when rtf_result_profile_1_t - rtf_result_profile_3_t are supported
#if 0
        if (is_command_actions_subset(command_profile, command_def)) {
            m_device->set_acl_command_profile(i, command_def);
            return LA_STATUS_SUCCESS;
        }
#endif
    }
    log_err(HLD, "la_acl_command_profile_base::%s failed, includes unsupported action", __func__);
    return LA_STATUS_EUNKNOWN;
}

la_status
la_acl_command_profile_base::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    return LA_STATUS_SUCCESS;
}

// la_object API-s
la_object::object_type_e
la_acl_command_profile_base::type() const
{
    return object_type_e::ACL_COMMAND_PROFILE;
}

const la_device*
la_acl_command_profile_base::get_device() const
{
    return m_device.get();
}

uint64_t
la_acl_command_profile_base::oid() const
{
    return m_oid;
}

std::string
la_acl_command_profile_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_acl_command_profile_base(oid=" << m_oid << ")";
    return log_message.str();
}

// la_acl_command_profile API-s
la_status
la_acl_command_profile_base::get_command_definition(la_acl_command_def_vec_t& out_command_def_vec) const
{
    out_command_def_vec = m_acl_command;

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_command_profile_base::get_hw_command_profile(uint32_t& out_hw_command_profile) const
{
    la_acl_command_def_vec_t command_profile;
    for (uint32_t i = 0; i < NUM_ACL_COMMAND_PROFILES; i++) {
        m_device->get_acl_command_profile(i, command_profile);
        if (is_command_actions_subset(m_acl_command, command_profile)) {
            out_hw_command_profile = i;
            return LA_STATUS_SUCCESS;
        }
    }
    return LA_STATUS_EINVAL;
}

// Implementation
bool
la_acl_command_profile_base::is_command_actions_subset(const la_acl_command_def_vec_t& command_def_vec1,
                                                       const la_acl_command_def_vec_t& command_def_vec2) const
{
    if (command_def_vec1.size() > command_def_vec2.size()) {
        return false;
    }
    for (auto action1 : command_def_vec1) {
        bool found = false;
        for (auto action2 : command_def_vec2) {
            if (action1.type == action2.type) {
                found = true;
            }
        }
        if (found == false) {
            return false;
        }
    }
    return true;
}

} // namespace silicon_one
