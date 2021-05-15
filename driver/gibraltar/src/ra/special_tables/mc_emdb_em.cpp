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

#include "mc_emdb_em.h"
#include "common/defines.h"
#include "common/logger.h"
#include "em_utils.h"
#include "hw_tables/em_core.h"
#include "hw_tables/logical_em.h"

#include "lld/ll_device.h"
#include "lld/pacific_tree.h"

namespace silicon_one
{

enum {
    // TODO defining these here until I find a better way to get rx_pdr_mc_db size.
    MC_EMDB_NUM_TABLES = 2,                  // MC_EMDB uses 2 rx_pdr_mc_db tables.
    MC_EMDB_NUM_ENTRIES_PER_TABLE = 1 << 16, // 64k entries per rx_pdr_mc_db table.
};

mc_emdb::mc_emdb(const ll_device_sptr& ldevice, const std::vector<logical_em_sptr>& ems)
    : m_ll_device(ldevice), m_ems(ems), m_resource_monitor(nullptr), m_num_entries(0)
{
}

// Operations are different than regular composite EM
// Composite EM loops through all EMs in the vector while
// we use table selection logic to pick a specific EM to operate
la_status
mc_emdb::insert(const bit_vector& key, const bit_vector& payload)
{
    auto tbl = which_em(key);
    la_status status = m_ems[tbl]->insert(key, payload);
    return_on_error(status);

    ++m_num_entries;
    if (m_resource_monitor != nullptr) {
        size_t current_size = size();
        m_resource_monitor->update_size(current_size);
    }

    return status;
}

la_status
mc_emdb::update(const bit_vector& key, const bit_vector& payload)
{
    auto tbl = which_em(key);
    la_status status = m_ems[tbl]->update(key, payload);
    return status;
}

la_status
mc_emdb::erase(const bit_vector& key)
{
    auto tbl = which_em(key);
    la_status status = m_ems[tbl]->erase(key);
    return_on_error(status);

    --m_num_entries;
    if (m_resource_monitor != nullptr) {
        size_t current_size = size();
        m_resource_monitor->update_size(current_size);
    }

    return status;
}

size_t
mc_emdb::max_size() const
{
    return MC_EMDB_NUM_TABLES * MC_EMDB_NUM_ENTRIES_PER_TABLE;
}

la_status
mc_emdb::get_physical_usage(size_t num_of_table_logical_entries, size_t& out_physical_usage) const
{
    out_physical_usage = 0;
    return LA_STATUS_ENOTIMPLEMENTED;
};

la_status
mc_emdb::get_available_entries(size_t& out_available_entries) const
{
    out_available_entries = 0;
    return LA_STATUS_ENOTIMPLEMENTED;
};

la_status
mc_emdb::set_resource_monitor(const resource_monitor_sptr& monitor)
{
    m_resource_monitor = monitor;

    return LA_STATUS_SUCCESS;
}

la_status
mc_emdb::get_resource_monitor(resource_monitor_sptr& out_monitor) const
{
    out_monitor = m_resource_monitor;

    return LA_STATUS_SUCCESS;
}

size_t
mc_emdb::size() const
{
    return m_num_entries;
}

size_t
mc_emdb::which_em(const bit_vector& key) const
{
    // Refer to Pacific Registers and Memories, section 34.2.3 SharedDb
    //
    // Table selection logic in hardware is implmeneted as,
    //
    // XOR{MCID[15:0],Entr[10:0]}
    //
    // MCID located at [26, 11]
    // Entr located at [10, 0]
    bit_vector parity_bv = key.bits(26, 0);

    uint64_t input = parity_bv.get_value();
    return (bit_utils::get_parity(input));
}

la_status
mc_emdb::erase(const bit_vector& key, size_t payload_width)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

bool
mc_emdb::is_flexible_entry_supported() const
{
    return false;
}
} // namespace silicon_one
