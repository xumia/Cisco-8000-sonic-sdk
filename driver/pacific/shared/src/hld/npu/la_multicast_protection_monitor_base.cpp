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

#include <sstream>

#include "la_multicast_protection_monitor_base.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

namespace silicon_one
{

#define start_protection_monitor_call() api_lock_guard<std::recursive_mutex> prot_lock(this->m_device, __func__)

#define start_protection_monitor_api_call(...)                                                                                     \
    start_protection_monitor_call();                                                                                               \
    bool is_recursive = (get_device_id_use_count() > 1);                                                                           \
    log_device_message_template(la_logger_component_e::API, la_logger_level_e::DEBUG, this, __func__, is_recursive, __VA_ARGS__);  \
    start_scoped_profiler("API call")

la_multicast_protection_monitor_base::la_multicast_protection_monitor_base(const la_device_impl_wptr& device)
    : m_device(device), m_primary_state(true), m_backup_state(false)
{
}

la_multicast_protection_monitor_base::~la_multicast_protection_monitor_base()
{
}

la_status
la_multicast_protection_monitor_base::initialize(la_object_id_t oid, la_uint_t protection_monitor_gid)
{
    m_oid = oid;
    start_protection_monitor_call();

    // Defaults: primary active, backup disabled
    m_primary_state = true;
    m_backup_state = false;
    m_monitor_gid = protection_monitor_gid;

    la_status status = configure_mldp_protection_table(m_primary_state, m_backup_state);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_protection_monitor_base::destroy()
{
    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_multicast_protection_monitor_base::type() const
{
    return la_object::object_type_e::MULTICAST_PROTECTION_MONITOR;
}

std::string
la_multicast_protection_monitor_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_multicast_protection_monitor_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_multicast_protection_monitor_base::oid() const
{
    return m_oid;
}

const la_device*
la_multicast_protection_monitor_base::get_device() const
{
    return m_device.get();
}

la_uint_t
la_multicast_protection_monitor_base::get_gid() const
{
    return m_monitor_gid;
}

la_status
la_multicast_protection_monitor_base::set_state(bool primary_active, bool backup_active)
{
    start_protection_monitor_api_call("primary_active=", primary_active, "backup_active=", backup_active);

    if (primary_active == m_primary_state && backup_active == m_backup_state) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = configure_mldp_protection_table(primary_active, backup_active);
    return_on_error(status);

    m_primary_state = primary_active;
    m_backup_state = backup_active;

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_protection_monitor_base::get_state(bool& out_primary_active, bool& out_backup_active) const
{
    start_api_getter_call();

    out_primary_active = m_primary_state;
    out_backup_active = m_backup_state;

    return LA_STATUS_SUCCESS;
}

la_status
la_multicast_protection_monitor_base::configure_mldp_protection_table(bool primary_active, bool backup_active)
{
    for (la_slice_id_t slice : m_device->get_used_slices()) {
        const auto& table(m_device->m_tables.mldp_protection_table[slice]);
        npl_mldp_protection_table_key_t key;
        npl_mldp_protection_table_value_t value;
        npl_mldp_protection_table_entry_t* entry = nullptr;

        key.mlp_protection.id = m_monitor_gid;

        value.payloads.mld_entry.drop_primary.val = primary_active ? NPL_FALSE_VALUE : NPL_TRUE_VALUE;
        value.payloads.mld_entry.drop_protect.val = backup_active ? NPL_FALSE_VALUE : NPL_TRUE_VALUE;

        value.action = NPL_MLDP_PROTECTION_TABLE_ACTION_WRITE;

        la_status status = table->set(key, value, entry);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
