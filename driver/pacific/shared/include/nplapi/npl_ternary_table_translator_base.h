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

#ifndef __NPL_TERNARY_TABLE_TRANSLATOR_BASE_H__
#define __NPL_TERNARY_TABLE_TRANSLATOR_BASE_H__

#include "common/la_status.h"
#include "nplapi/npl_tables_enum.h"

namespace silicon_one
{

/// @brief Base class of ternary-table translator.
///
/// The translator acts as a middle layer between the application and the low
/// level objects that are strongly tied to the device.
/// It is responsible for changing the format of the Key and Value
/// parameters from host format (C structures) into a format that the device
/// can work with. After re-formatting the data the translator passes execution
/// control to lower-level objects for further processing.
template <class _Trait>
class npl_ternary_table_translator_base
{

public:
    typedef typename _Trait::key_type key_type;
    typedef typename _Trait::value_type value_type;

    /// @brief table entry information.
    struct npl_translator_entry_desc {
        key_type key;     ///< Entry key.
        key_type mask;    ///< Entry mask.
        value_type value; ///< Entry value.
    };

    virtual ~npl_ternary_table_translator_base()
    {
    }

    /// @brief Initialize translator.
    ///
    /// @retval     LA_STATUS_SUCCESS           Success.
    /// @retval     LA_STATUS_EUNKNOWN          Internal error.
    virtual la_status initialize() = 0;

    /// @brief Update an entry in the table.
    ///
    /// @param[in]  line                        The row into which the entry should be inserted.
    /// @param[in]  key                         The key of the new entry.
    /// @param[in]  mask                        The mask of the new entry.
    /// @param[in]  value                       The value of the new entry.
    ///
    /// @retval     LA_STATUS_SUCCESS           Success.
    /// @retval     LA_STATUS_EUNKNOWN          Internal error.
    virtual la_status set_entry_value(size_t line, const key_type& key, const key_type& mask, const value_type& value) = 0;

    /// @brief Insert a new entry to the table.
    ///
    /// @param[in]  line                        The row into which the entry should be inserted.
    /// @param[in]  key                         The key of the new entry.
    /// @param[in]  mask                        The mask of the new entry.
    /// @param[in]  value                       The value of the new entry.
    ///
    /// @retval     LA_STATUS_SUCCESS           Success.
    /// @retval     LA_STATUS_EUNKNOWN          Internal error.
    virtual la_status insert(size_t line, const key_type& key, const key_type& mask, const value_type& value) = 0;

    /// @brief Insert a new entry to the table, pushing entries down to make space for it if necessary.
    ///
    /// @param[in]  line                         The row into which the entry should be inserted.
    /// @param[in]  free_slot                    The row, up to which, the entries will be pushed.
    /// @param[in]  key                          The key of the new entry.
    /// @param[in]  mask                         The mask of the new entry.
    /// @param[in]  value                        The value of the new entry.
    /// @param[out] out_entry                    Host representation of the new entry.
    ///
    /// @retval     LA_STATUS_SUCCESS            Success.
    /// @retval     LA_STATUS_ENOTINITIALIZED    Table object was not initialized.
    /// @retval     LA_STATUS_ERESOURCE          No free entries in the table.
    /// @retval     LA_STATUS_EOUTOFRANGE        Given location is out of bound.
    /// @retval     LA_STATUS_EUNKNOWN           Internal error.
    virtual la_status push(size_t line, size_t free_slot, const key_type& key, const key_type& mask, const value_type& value) = 0;

    /// @brief Insert new entries to the table, pushing entries down to make space for them if necessary.
    ///
    /// @param[in]  first_line                   The row from which the entries should be inserted.
    /// @param[in]  bulk_size                    The number of entries to be inserted.
    /// @param[in]  entries                          The keys, masks and values of the new entries.
    ///
    /// @retval     LA_STATUS_SUCCESS            Success.
    /// @retval     LA_STATUS_ENOTINITIALIZED    Table object was not initialized.
    /// @retval     LA_STATUS_ERESOURCE          Not enough free entries in the table.
    /// @retval     LA_STATUS_EOUTOFRANGE        Given location is out of bound.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED    Function not yet implemented.
    /// @retval     LA_STATUS_EUNKNOWN           Internal error.
    virtual la_status insert_bulk(size_t first_line, size_t bulk_size, const vector_alloc<npl_translator_entry_desc>& entries) = 0;

    /// @brief Remove a specific entry in the table
    ///
    /// @param[in]  line                        The row into which the entry should be inserted.
    ///
    /// @retval     LA_STATUS_SUCCESS           Success.
    /// @retval     LA_STATUS_EUNKNOWN          Internal error.
    virtual la_status erase(size_t line) = 0;

    /// @brief Moving all entries from first_line uptil last_line to destination starting
    /// from dst_line.
    ///
    /// @param[in]  dst_line                    The first destination row where entry would be moved.
    /// @param[in]  src_line                    The first row which will be moved to dst_line.
    /// @param[in]  count                       The count of entries which will be moved.
    ///
    /// @retval     LA_STATUS_SUCCESS           Success.
    /// @retval     LA_STATUS_ENOTINITIALIZED   Table object was not initialized.
    /// @retval     LA_STATUS_EOUTOFRANGE       Given location is out of bound.
    /// @retval     LA_STATUS_EUNKNOWN          Internal error.
    virtual la_status move(size_t dst_line, size_t src_line, size_t count) = 0;

    /// @brief Remove a specific entry in the table, moving all following to cover its space.
    /// If entry is empty, just moving the following entries up.
    ///
    /// @param[in]  line                       The row where the entry should be removed.
    ///
    /// @retval     LA_STATUS_SUCCESS           Success.
    /// @retval     LA_STATUS_ENOTINITIALIZED   Table object was not initialized.
    /// @retval     LA_STATUS_EOUTOFRANGE       Given location is out of bound.
    /// @retval     LA_STATUS_EUNKNOWN          Internal error.
    virtual la_status pop(size_t line) = 0;

    /// @brief Retrieve maximum table size.
    ///
    /// @retval Maximum number of entries supported by table.
    virtual size_t max_size() const = 0;

    virtual la_status set_trans_info(void* trans_info) = 0;

    /// @brief Retrieve maximum scale for table (maximum amount of entries that can be added).
    ///
    /// @param[out]  out_max_scale               Maximum scale for table
    ///
    /// @retval     LA_STATUS_SUCCESS           Success
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Function not yet implemented.
    virtual la_status get_max_available_space(size_t& out_available_space) const = 0;

    /// @brief Retrieve the current number of entries in table
    ///
    /// @param[out]  out_physical_usage               num of entries.
    ///
    /// @retval     LA_STATUS_SUCCESS           Success
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Function not yet implemented.
    virtual la_status get_physical_usage(size_t& out_physical_usage) const = 0;

    /// @brief Serilzation function
    ///
    /// @param[in] Archive to serialize from/to
    template <class Archive>
    void serialize(Archive& ar)
    {
    }
};

}; // namespace silicon_one

#endif // __NPL_TERNARY_TABLE_TRANSLATOR_BASE_H__
