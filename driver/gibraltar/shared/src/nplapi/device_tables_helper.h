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

#ifndef __DEVICE_TABLES_HELPER_H__
#define __DEVICE_TABLES_HELPER_H__

#include <memory>

#include "common/la_status.h"
#include "nplapi/npl_tables_static_init.h"
#include "nplapi/nplapi_tables.h"
#include "nplapi/translator_creator.h"

#ifndef NPLAPI_NUM_SLICES
#error NPLAPI_NUM_SLICES must be defined
#endif

namespace silicon_one
{

enum class table_allocation_e { SLICE, SLICE_PAIR, DEVICE };

// Helper functions to add static data to table
template <class _Table>
la_status
get_contexts_to_configure(std::shared_ptr<_Table> table,
                          translator_creator& creator,
                          const std::vector<size_t>& indices,
                          table_allocation_e allocation,
                          std::vector<npl_context_e>& out_contexts_to_configure)
{
    typename _Table::key_type dummy_key;

    // TODO - this doesn't support static configuration on NPL_NONE_CONTEXT

    // Verify that there is no more than one static config (which is per context) on the slices this table resides.
    // Get the set of contexts on which this table has static config
    std::vector<npl_context_e> static_config_contexts_vec
        = nplapi_tables_static_init::get_contexts_used_in_static_entries(dummy_key);
    std::set<npl_context_e> static_config_contexts_set(static_config_contexts_vec.begin(), static_config_contexts_vec.end());

    // Build a vector of the actual slices this table resides on
    std::vector<size_t> table_slices;
    switch (allocation) {
    case table_allocation_e::DEVICE: {
        for (size_t slice = 0; slice < NPLAPI_NUM_SLICES; slice++) {
            table_slices.push_back(slice);
        }
        break;
    }
    case table_allocation_e::SLICE_PAIR: {
        for (size_t slice_pair : indices) {
            table_slices.push_back(slice_pair * 2);
            if ((slice_pair * 2 + 1) < NPLAPI_NUM_SLICES) {
                // Only add 2nd slice in pair if it's in range
                // [example: Asic5 has only 1 slice, so a "pair" degenerates to single slice]
                table_slices.push_back(slice_pair * 2 + 1);
            }
        }
        break;
    }
    case table_allocation_e::SLICE: {
        table_slices = indices;
        break;
    }
    }

    // Get the contexts of the slices this table resides on
    std::set<npl_context_e> table_slice_contexts;
    for (size_t table_slice : table_slices) {
        npl_context_e slice_context = creator.get_slice_context(table_slice);
        table_slice_contexts.insert(slice_context);
    }

    // Get the contexts that should be statically configured for this table on the requested slices, by finding the set intersection
    // between the static config contexts and the table context
    std::set_intersection(static_config_contexts_set.begin(),
                          static_config_contexts_set.end(),
                          table_slice_contexts.begin(),
                          table_slice_contexts.end(),
                          std::back_inserter(out_contexts_to_configure));

    // If there is more than one context to configure then error - can't put configurations of more than a single context into a
    // single logical table.
    if (out_contexts_to_configure.size() > 1) {
        log_err(TABLES,
                "Table %s has %lu active contextes",
                _Table::trait_type::get_table_name().c_str(),
                out_contexts_to_configure.size());
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
set_static_entries(std::shared_ptr<npl_table<_Trait> > table,
                   translator_creator& creator,
                   const std::vector<size_t>& indices,
                   table_allocation_e allocation)
{
    dassert_crit(!indices.empty());

    typedef npl_table<_Trait> _Table;
    typename _Table::key_type dummy_key;

    std::vector<npl_context_e> contexts_to_configure;

    la_status status = get_contexts_to_configure(table, creator, indices, allocation, contexts_to_configure);
    return_on_error(status);

    // If nothing to configure bail
    if (contexts_to_configure.empty()) {
        return LA_STATUS_SUCCESS;
    }

    // Exactly one context to configure
    dassert_crit(contexts_to_configure.size() == 1);
    npl_context_e context = contexts_to_configure[0];

    // variable to define the type of the table

    typename _Table::entry_pointer_type dummy_entry;
    auto static_values_vec = nplapi_tables_static_init::get_static_entries(context, dummy_key);
    for (auto entry : static_values_vec) {
        typename _Table::key_type key = std::get<0>(entry);
        typename _Table::value_type value = std::get<1>(entry);
        la_status status = table->insert(key, value, dummy_entry);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD,
                    "%s::%d %s(...); err: %s for key:\n%s\n value:\n%s\n;",
                    __FILE__,
                    __LINE__,
                    __func__,
                    la_status2str(status).c_str(),
                    to_string(key).c_str(),
                    to_string(value).c_str());
            return status;
        }
    }
    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
set_static_entries(std::shared_ptr<npl_ternary_table<_Trait> > table,
                   translator_creator& creator,
                   const std::vector<size_t>& indices,
                   table_allocation_e allocation)
{
    typedef npl_ternary_table<_Trait> _Table;

    std::vector<npl_context_e> contexts_to_configure;

    la_status status = get_contexts_to_configure(table, creator, indices, allocation, contexts_to_configure);
    return_on_error(status);

    // If nothing to configure bail
    if (contexts_to_configure.empty()) {
        return LA_STATUS_SUCCESS;
    }

    // Exactly one context to configure
    dassert_crit(contexts_to_configure.size() == 1);
    npl_context_e context = contexts_to_configure[0];

    // variable to define the type of the table
    typename _Table::key_type dummy_key;
    typename _Table::entry_pointer_type dummy_entry;
    auto static_values_vec = nplapi_tables_static_init::get_static_entries(context, dummy_key);
    for (auto entry : static_values_vec) {
        size_t line = std::get<0>(entry);
        typename _Table::key_type key = std::get<1>(entry);
        typename _Table::key_type mask = std::get<2>(entry);
        typename _Table::value_type value = std::get<3>(entry);
        la_status status = table->insert(line, key, mask, value, dummy_entry);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD,
                    "%s::%d %s(...); err: %s for\nline:%zu\nkey:\n%s\nmask:\n%s\nvalue:\n%s\n;",
                    __FILE__,
                    __LINE__,
                    __func__,
                    la_status2str(status).c_str(),
                    line,
                    to_string(key).c_str(),
                    to_string(mask).c_str(),
                    to_string(value).c_str());
            return status;
        };
    }

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
set_static_entries(std::shared_ptr<npl_lpm_table<_Trait> > table,
                   translator_creator& creator,
                   const std::vector<size_t>& indices,
                   table_allocation_e allocation)
{
    return LA_STATUS_SUCCESS;
}

// Helper functions for table initialization
template <class _Table>
la_status
init_table(translator_creator& creator,
           std::shared_ptr<_Table> table,
           const std::vector<size_t>& indices,
           table_allocation_e allocation)
{
    la_status status = creator.initialize_table(table.get(), table->get_table_type(), indices);
    return_on_error(status);

    return set_static_entries(table, creator, indices, allocation);
}

template <class _Table>
la_status
init_table(translator_creator& creator, std::shared_ptr<_Table> table, size_t idx, table_allocation_e allocation)
{
    std::vector<size_t> indices;
    indices.push_back(idx);
    return init_table(creator, table, indices, allocation);
}
}

#endif /* __DEVICE_TABLES_HELPER_H__ */
