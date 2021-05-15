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

#include "npu/la_protection_monitor_impl.h"
#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "resolution_utils.h"
#include "system/la_device_impl.h"

#include <sstream>

namespace silicon_one
{

#define start_protection_monitor_call() api_lock_guard<std::recursive_mutex> prot_lock(this->m_device, __func__)

#define start_protection_monitor_api_call(...)                                                                                     \
    start_protection_monitor_call();                                                                                               \
    bool is_recursive = (get_device_id_use_count() > 1);                                                                           \
    log_device_message_template(la_logger_component_e::API, la_logger_level_e::DEBUG, this, __func__, is_recursive, __VA_ARGS__);  \
    start_scoped_profiler("API call")

la_protection_monitor_impl::la_protection_monitor_impl(const la_device_impl_wptr& device)
    : m_device(device), m_gid(LA_PROTECTION_MONITOR_GID_INVALID), m_state(monitor_state_e::UNTRIGGERED)
{
}

la_protection_monitor_impl::~la_protection_monitor_impl()
{
}

la_status
la_protection_monitor_impl::initialize(la_object_id_t oid, la_protection_monitor_gid_t protection_monitor_gid)
{
    m_oid = oid;
    start_protection_monitor_call();

    m_gid = protection_monitor_gid;

    return LA_STATUS_SUCCESS;
}

la_status
la_protection_monitor_impl::destroy()
{
    start_protection_monitor_call();

    return LA_STATUS_SUCCESS;
}

la_protection_monitor_impl::resolution_data::resolution_data()
{
    for (resolution_step_e res_step = RESOLUTION_STEP_FIRST; res_step < RESOLUTION_STEP_LAST;
         res_step = (resolution_step_e)(res_step + 1)) {
        users_for_step[res_step] = 0;
    }
}

resolution_step_e
la_protection_monitor_impl::get_next_resolution_step(resolution_step_e prev_step) const
{
    if (prev_step == RESOLUTION_STEP_STAGE0_PROTECTION) {
        return RESOLUTION_STEP_STAGE0_PROTECTION;
    }

    if (prev_step == RESOLUTION_STEP_STAGE1_PROTECTION) {
        return RESOLUTION_STEP_STAGE1_PROTECTION;
    }

    return RESOLUTION_STEP_INVALID;
}

la_status
la_protection_monitor_impl::instantiate(resolution_step_e prev_step)
{
    start_protection_monitor_call();
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    if (cur_step == RESOLUTION_STEP_INVALID) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (m_resolution_data.users_for_step[cur_step] > 0) {
        m_resolution_data.users_for_step[cur_step]++;
        return LA_STATUS_SUCCESS;
    }

    m_resolution_data.users_for_step[cur_step]++;

    return configure_resolution_step(cur_step);
}

la_status
la_protection_monitor_impl::configure_resolution_step(resolution_step_e cur_step)
{
    int stage = res_step_to_stage(cur_step);
    if (stage == RESOLUTION_INVALID_STAGE) {
        return LA_STATUS_EUNKNOWN;
    }
    la_status status = m_device->m_resolution_configurators[stage].configure_protection_monitor(
        m_gid, monitor_state_to_npl_protection_selector(m_state));

    return status;
}

la_status
la_protection_monitor_impl::uninstantiate(resolution_step_e prev_step)
{
    start_protection_monitor_call();
    resolution_step_e cur_step = get_next_resolution_step(prev_step);

    if (cur_step == RESOLUTION_STEP_INVALID) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (m_resolution_data.users_for_step[cur_step] > 1) {
        m_resolution_data.users_for_step[cur_step]--;
        return LA_STATUS_SUCCESS;
    }

    la_status status = teardown_resolution_step(cur_step);
    return_on_error(status);

    m_resolution_data.users_for_step[cur_step]--;
    return LA_STATUS_SUCCESS;
}

la_status
la_protection_monitor_impl::teardown_resolution_step(resolution_step_e cur_step)
{
    int stage = res_step_to_stage(cur_step);
    if (stage == RESOLUTION_INVALID_STAGE) {
        return LA_STATUS_EUNKNOWN;
    }
    la_status status = m_device->m_resolution_configurators[stage].unconfigure_protection_monitor(m_gid);

    return status;
}

la_l3_destination_gid_t
la_protection_monitor_impl::get_gid() const
{
    return m_gid;
}

la_status
la_protection_monitor_impl::set_state(monitor_state_e state)
{
    start_protection_monitor_api_call("state=", state);

    for (resolution_step_e res_step = RESOLUTION_STEP_FIRST; res_step < RESOLUTION_STEP_LAST;
         res_step = (resolution_step_e)(res_step + 1)) {

        if (m_resolution_data.users_for_step[res_step] == 0) {
            continue;
        }

        if (res_step == RESOLUTION_STEP_STAGE0_PROTECTION || res_step == RESOLUTION_STEP_STAGE1_PROTECTION) {

            int stage = res_step_to_stage(res_step);
            npl_resolution_protection_selector_e selector = monitor_state_to_npl_protection_selector(state);
            la_status status = m_device->m_resolution_configurators[stage].configure_protection_monitor(m_gid, selector);
            return_on_error(status);
        }

        else {
            return LA_STATUS_ENOTIMPLEMENTED;
        }
    }

    m_state = state;
    return LA_STATUS_SUCCESS;
}

la_status
la_protection_monitor_impl::get_state(monitor_state_e& out_state) const
{
    out_state = m_state;
    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_protection_monitor_impl::type() const
{
    return object_type_e::PROTECTION_MONITOR;
}

std::string
la_protection_monitor_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_protection_monitor_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_protection_monitor_impl::oid() const
{
    return m_oid;
}

const la_device*
la_protection_monitor_impl::get_device() const
{
    return m_device.get();
}

} // namespace silicon_one
