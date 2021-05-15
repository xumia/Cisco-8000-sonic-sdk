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

#include <algorithm>

#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "hw_tables/composite_em.h"

namespace silicon_one
{

composite_em::composite_em(const std::vector<logical_em_sptr>& ems) : m_ems(ems)
{
}

composite_em::~composite_em()
{
}

la_status
composite_em::insert(const bit_vector& key, const bit_vector& payload)
{
    transaction txn;
    for (logical_em_sptr em : m_ems) {
        txn.status = em->insert(key, payload);
        return_on_error(txn.status);
        txn.on_fail([=] {
            la_status status = em->erase(key);
            if (status != LA_STATUS_SUCCESS) {
                log_err(TABLES, "failed to erase em entry while rolling back on error, status = %s", la_status2str(status).c_str());
            }
            dassert_crit(status == LA_STATUS_SUCCESS);
        });
    }
    return LA_STATUS_SUCCESS;
}

la_status
composite_em::update(const bit_vector& key, const bit_vector& payload)
{
    for (const logical_em_sptr& em : m_ems) {
        la_status status = em->update(key, payload);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
composite_em::erase(const bit_vector& key)
{
    for (const logical_em_sptr& em : m_ems) {
        la_status status = em->erase(key);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

size_t
composite_em::max_size() const
{
    auto logical_em = std::min_element(m_ems.begin(), m_ems.end(), [](logical_em_sptr const& lhs, logical_em_sptr const& rhs) {
        return lhs->max_size() < rhs->max_size();
    });

    return (*logical_em)->max_size();
}

la_status
composite_em::get_physical_usage(size_t num_of_table_logical_entries, size_t& out_physical_usage) const
{
    size_t max_physical_usage = 0;
    size_t curr_physical_usage;
    for (const auto& logical_em : m_ems) {
        la_status status = logical_em->get_physical_usage(num_of_table_logical_entries, curr_physical_usage);
        return_on_error(status);
        max_physical_usage = std::max(max_physical_usage, curr_physical_usage);
    }

    out_physical_usage = max_physical_usage;
    return LA_STATUS_SUCCESS;
}

la_status
composite_em::get_available_entries(size_t& out_available_entries) const
{
    size_t min_available_entries = std::numeric_limits<size_t>::max();
    size_t curr_available_entries;
    for (const auto& logical_em : m_ems) {
        la_status status = logical_em->get_available_entries(curr_available_entries);
        return_on_error(status);
        curr_available_entries = std::min(min_available_entries, curr_available_entries);
    }

    out_available_entries = min_available_entries;
    return LA_STATUS_SUCCESS;
}

la_status
composite_em::set_resource_monitor(const resource_monitor_sptr& monitor)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
composite_em::get_resource_monitor(resource_monitor_sptr& out_monitor) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

size_t
composite_em::size() const
{
    return 0;
}

la_status
composite_em::erase(const bit_vector& key, size_t payload_width)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

bool
composite_em::is_flexible_entry_supported() const
{
    return false;
}

} // namespace silicon_one
