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

#include "cem_em.h"
#include "em_utils.h"
#include "hw_tables/arc_cpu_common.h"

#include "common/logger.h"

#include "lld/ll_device.h"
#include "lld/pacific_tree.h"

namespace silicon_one
{

cem_em::cem_em(const ll_device_sptr& ldevice, const cem_sptr& cem_db, cem::entry_type_e type)
    : m_ll_device(ldevice), m_cem(cem_db), m_type(type)
{
}

la_status
cem_em::insert(const bit_vector& key, const bit_vector& payload)
{
    switch (m_type) {
    case cem::entry_type_e::SINGLE_ENTRY:
        return m_cem->insert_table_single_entry(key, payload);
    case cem::entry_type_e::DOUBLE_ENTRY:
        return m_cem->insert_table_double_entry(key, payload);
    }

    return LA_STATUS_SUCCESS;
}

la_status
cem_em::update(const bit_vector& key, const bit_vector& payload)
{
    switch (m_type) {
    case cem::entry_type_e::SINGLE_ENTRY:
        return m_cem->update_table_single_entry(key, payload);
    case cem::entry_type_e::DOUBLE_ENTRY:
        return m_cem->update_table_double_entry(key, payload);
    }

    return LA_STATUS_SUCCESS;
}

la_status
cem_em::erase(const bit_vector& key)
{
    switch (m_type) {
    case cem::entry_type_e::SINGLE_ENTRY:
        return m_cem->erase_table_single_entry(key);
    case cem::entry_type_e::DOUBLE_ENTRY:
        return m_cem->erase_table_double_entry(key);
    }

    return LA_STATUS_SUCCESS;
}

size_t
cem_em::max_size() const
{
    return m_cem->max_size();
}

la_status
cem_em::get_physical_usage(size_t num_of_table_logical_entries, size_t& out_physical_usage) const
{
    la_status status = m_cem->get_physical_usage(m_type, num_of_table_logical_entries, out_physical_usage);
    return status;
}
la_status
cem_em::get_available_entries(size_t& out_available_entries) const
{
    la_status status = m_cem->get_available_entries(m_type, out_available_entries);
    return status;
}

la_status
cem_em::set_resource_monitor(const resource_monitor_sptr& monitor)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
cem_em::get_resource_monitor(resource_monitor_sptr& out_monitor) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

size_t
cem_em::size() const
{
    return 0;
}

la_status
cem_em::erase(const bit_vector& key, size_t payload_width)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

bool
cem_em::is_flexible_entry_supported() const
{
    return false;
}

} // namespace silicon_one
