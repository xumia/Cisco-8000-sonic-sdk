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

#include "ctm_mgr.h"
#include "api/types/la_acl_types.h"
#include "common/logger.h"
#include "ctm/ctm_config.h"
#include "hw_tables/memory_tcam.h"
#include "lld/ll_device.h"

#include <iostream>

namespace silicon_one
{

ctm_mgr::ctm_mgr(const ll_device_sptr& ldevice, engine_block_mapper block_mapper, size_t number_of_slices)
    : m_num_of_slices(number_of_slices), m_ll_device(ldevice), m_block_mapper(block_mapper)
{
}

void
ctm_mgr::start_ctm_mgr_api_call(const table_desc& table_id) const
{
    m_current_group = get_group_for_table(table_id);
}

void
ctm_mgr::register_table_to_group(group_desc group_id, table_desc table_id, size_t logical_db_id)
{
    m_group_to_tables_mapping[group_id].push_back(table_id);
    m_table_to_group_mapping[table_id] = group_id;
    add_table(group_id, table_id, logical_db_id);
}

group_desc
ctm_mgr::get_group_for_table(const table_desc& table) const
{
    map_alloc<table_desc, group_desc>::const_iterator group_it = m_table_to_group_mapping.find(table);
    dassert_crit(group_it != m_table_to_group_mapping.end());

    return group_it->second;
}

ctm_mgr::table_vec
ctm_mgr::get_tables_for_group(const group_desc& desc) const
{
    map_alloc<group_desc, table_vec>::const_iterator tables_it = m_group_to_tables_mapping.find(desc);

    dassert_crit(desc.slice_idx != IDX_INVAL
                 || tables_it == m_group_to_tables_mapping.end()); // If the desc is invalid then we must not find ii in the map.

    if (tables_it != m_group_to_tables_mapping.end()) {
        return tables_it->second;
    } else {
        return table_vec();
    }
}

bool
ctm_mgr::is_table_wide(const table_desc& table) const
{
    const group_desc& group = get_group_for_table(table);
    return group.is_wide();
}

} // namespace silicon_one
