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

#ifndef __NPL_NPL_TABLE_TRANSLATOR_BASE_H__
#define __NPL_NPL_TABLE_TRANSLATOR_BASE_H__

#include "common/la_status.h"
#include "nplapi/npl_lpm_bulk_types.h"
#include "nplapi/npl_tables_enum.h"

namespace silicon_one
{

/// @brief Base class of table translator.
///
/// The translator acts as a middle layer between the application and the low
/// level objects that are strongly tied to the device.
/// It is responsible for changing the format of the Key and Value
/// parameters from host format (C structures) into a format that the device
/// can work with. After refomating the data the translator passes execution
/// control to lower-level objects for further processing.
template <class _Trait>
class npl_lpm_table_translator_base
{

public:
    typedef typename _Trait::key_type key_type;
    typedef typename _Trait::value_type value_type;

    virtual ~npl_lpm_table_translator_base()
    {
    }

    /// @brief Modify the value of a specific entry in the table
    ///
    /// @param[in]  key                         The key of the modified entry
    /// @param[in]  length                      Length of the prefix to use for matching the entry.
    /// @param[in]  value                       The new value
    ///
    /// @retval     LA_STATUS_SUCCESS           Success
    /// @retval     LA_STATUS_EUNKNOWN          Internal error
    virtual la_status set_entry_value(const key_type& key, size_t length, const value_type& value) = 0;

    /// @brief Remove a specific entry in the table
    ///
    /// @param[in]  key                         The key of the removed entry
    /// @param[in]  length                      Length of the prefix to use for matching the entry.
    ///
    /// @retval     LA_STATUS_SUCCESS           Success
    /// @retval     LA_STATUS_EUNKNOWN          Internal error
    virtual la_status erase(const key_type& key, size_t length, const value_type& value) = 0;

    /// @brief Add a new entry to the table
    ///
    /// @param[in]  key                        The key of the modified entry
    /// @param[in]  length                     Length of the prefix to use for matching the entry.
    /// @param[in]  value                      The new value
    ///
    /// @retval     LA_STATUS_SUCCESS           Success
    /// @retval     LA_STATUS_EUNKNOWN          Internal error
    virtual la_status insert(const key_type& key, size_t length, const value_type& value) = 0;

    /// @brief Bulk update to the table
    ///
    /// @param[in]  lpm_entries                LPM entries to program.
    /// @param[out] out_count_success          Count of entries successfully programmed.
    ///
    /// @retval     LA_STATUS_SUCCESS          Success
    /// @retval     LA_STATUS_EUNKNOWN         Internal error
    virtual la_status bulk_updates(const npl_lpm_bulk_entries_vec<_Trait>& lpm_entries, size_t& out_count_success) = 0;

    /// @brief Retrieve maximum table size.
    ///
    /// @retval Maximum number of entries supported by table.
    virtual size_t max_size() const = 0;

    /// @brief Retrieve percentage of the physical usage out of the total physical resource based on the number of
    /// logical entries.
    ///
    /// @param[in]  number_of_logical_entries_in_table      Number of logical entries in the table, this is essential
    /// for the occupancy calculation.
    ///
    /// @retval Percentage of the physical usage.
    virtual size_t get_physical_usage(size_t number_of_logical_entries_in_table) const = 0;

    /// @brief Retrieve the number of available entried for the table.
    ///
    /// @retval Number of available entried for the table
    virtual size_t get_available_entries() const = 0;

    /// @brief Serilzation function
    ///
    /// @param[in] Archive to serialize from/to
    template <class Archive>
    void serialize(Archive& ar)
    {
    }
};

}; // namespace silicon_one

#endif // __NPL_NPL_TABLE_TRANSLATOR_BASE_H__
