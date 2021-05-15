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

#ifndef __RA_EMPTY_TRANSLATORS_H__
#define __RA_EMPTY_TRANSLATORS_H__

#include "nplapi/npl_table_translator_base.h"
#include "nplapi/npl_ternary_table_translator_base.h"
#include "nplapi_translator/npl_table_entry_translation.h"

namespace silicon_one
{

/// @file Empty implementations of NPL translators till we have all tables placed.
///

/// @brief Empty direct translator
template <class _Trait>
class ra_empty_direct_translator : public npl_table_translator_base<_Trait>
{
public:
    typedef typename _Trait::key_type key_type;
    typedef typename _Trait::value_type value_type;

    virtual la_status set_entry_value(const key_type& key, const value_type& value);
    virtual la_status erase(const key_type& key, const value_type& value);
    virtual la_status insert(const key_type& key, const value_type& value);
    virtual size_t max_size() const;
    virtual la_status get_physical_usage(size_t number_of_logical_entries_in_table, size_t& out_physical_usage) const;
    virtual la_status get_available_entries(size_t& out_available_entries) const;
};

template <class _Trait>
la_status
ra_empty_direct_translator<_Trait>::set_entry_value(const key_type& key, const value_type& value)
{
    log_debug(RA,
              "ra_empty_direct_translator::set_entry_value(%s, %s, %s)",
              _Trait::get_table_name().c_str(),
              key.pack().to_string().c_str(),
              value.pack().to_string().c_str());

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_empty_direct_translator<_Trait>::insert(const key_type& key, const value_type& value)
{
    log_debug(RA,
              "ra_empty_direct_translator::insert(%s, %s, %s)",
              _Trait::get_table_name().c_str(),
              key.pack().to_string().c_str(),
              value.pack().to_string().c_str());

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_empty_direct_translator<_Trait>::erase(const key_type& key, const value_type& value)
{
    // there is no erase operation for SRAM tables
    return LA_STATUS_SUCCESS;
}

template <class _Trait>
size_t
ra_empty_direct_translator<_Trait>::max_size() const
{
    // Quite big and meaningless number.
    return 32768;
}

template <class _Trait>
la_status
ra_empty_direct_translator<_Trait>::get_available_entries(size_t& out_available_entries) const
{
    out_available_entries = 0;
    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_empty_direct_translator<_Trait>::get_physical_usage(size_t number_of_logical_entries_in_table, size_t& out_physical_usage) const
{
    out_physical_usage = number_of_logical_entries_in_table;
    return LA_STATUS_SUCCESS;
}

/// @brief Empty direct translator
template <class _Trait>
class ra_empty_ternary_translator : public npl_ternary_table_translator_base<_Trait>
{
public:
    typedef typename _Trait::key_type key_type;
    typedef typename _Trait::value_type value_type;
    typedef typename npl_ternary_table_translator_base<_Trait>::npl_translator_entry_desc npl_translator_entry_desc;

    virtual la_status initialize();
    virtual la_status set_entry_value(size_t line, const key_type& key, const key_type& mask, const value_type& value);
    virtual la_status insert(size_t line, const key_type& key, const key_type& mask, const value_type& value);
    virtual la_status insert_bulk(size_t first_line, size_t bulk_size, const vector_alloc<npl_translator_entry_desc>& entries);
    virtual la_status push(size_t line, size_t free_slot, const key_type& key, const key_type& mask, const value_type& value);
    virtual la_status erase(size_t line);
    virtual la_status move(size_t dst_line, size_t src_line, size_t count);
    virtual la_status pop(size_t line);
    virtual size_t max_size() const;
    virtual la_status get_max_available_space(size_t& out_available_space) const;
    virtual la_status set_trans_info(void* trans_info);
    virtual la_status get_physical_usage(size_t& out_physical_usage) const;
};

template <class _Trait>
la_status
ra_empty_ternary_translator<_Trait>::initialize()
{
    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_empty_ternary_translator<_Trait>::set_entry_value(size_t line,
                                                     const key_type& key,
                                                     const key_type& mask,
                                                     const value_type& value)
{
    log_debug(RA,
              "ra_empty_ternary_translator::set_entry_value(%s, %d, %s, %s, %s)",
              _Trait::get_table_name().c_str(),
              (int)line,
              key.pack().to_string().c_str(),
              mask.pack().to_string().c_str(),
              value.pack().to_string().c_str());

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_empty_ternary_translator<_Trait>::insert(size_t line, const key_type& key, const key_type& mask, const value_type& value)
{
    log_debug(RA,
              "ra_empty_ternary_translator::insert(%s, %d, %s, %s, %s)",
              _Trait::get_table_name().c_str(),
              (int)line,
              key.pack().to_string().c_str(),
              mask.pack().to_string().c_str(),
              value.pack().to_string().c_str());

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_empty_ternary_translator<_Trait>::insert_bulk(size_t first_line,
                                                 size_t bulk_size,
                                                 const vector_alloc<npl_translator_entry_desc>& entries)
{
    log_debug(
        RA, "ra_empty_ternary_translator::insert_bulk(%s, %lu, %lu)", _Trait::get_table_name().c_str(), first_line, bulk_size);

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_empty_ternary_translator<_Trait>::push(size_t line,
                                          size_t free_slot,
                                          const key_type& key,
                                          const key_type& mask,
                                          const value_type& value)
{
    log_debug(RA,
              "ra_empty_ternary_translator::push(%s, %d, %s, %s, %s)",
              _Trait::get_table_name().c_str(),
              (int)line,
              key.pack().to_string().c_str(),
              mask.pack().to_string().c_str(),
              value.pack().to_string().c_str());

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_empty_ternary_translator<_Trait>::erase(size_t line)
{
    log_debug(RA, "ra_empty_ternary_translator::erase(%s, %d)", _Trait::get_table_name().c_str(), (int)line);

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_empty_ternary_translator<_Trait>::move(size_t dst_line, size_t src_line, size_t count)
{
    log_debug(RA,
              "ra_empty_ternary_translator::move(%s, dst_line:%lu, src_line: %lu, count:%lu)",
              _Trait::get_table_name().c_str(),
              dst_line,
              src_line,
              count);

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_empty_ternary_translator<_Trait>::pop(size_t line)
{
    log_debug(RA, "ra_empty_ternary_translator::pop(%s, %d)", _Trait::get_table_name().c_str(), (int)line);

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
size_t
ra_empty_ternary_translator<_Trait>::max_size() const
{
    // Quite big and meaningless number.
    return 32768;
}

template <class _Trait>
la_status
ra_empty_ternary_translator<_Trait>::get_max_available_space(size_t& out_available_space) const
{
    // For an empty translator return 0?
    out_available_space = 0;
    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_empty_ternary_translator<_Trait>::get_physical_usage(size_t& out_physical_usage) const
{
    out_physical_usage = 0;
    return LA_STATUS_SUCCESS;
}

/// @brief npl_lpm_translator interface implementation for LPM NPL tables.
template <class _Trait>
class ra_empty_lpm_translator : public npl_lpm_table_translator_base<_Trait>
{
public:
    typedef typename _Trait::key_type key_type;
    typedef typename _Trait::value_type value_type;

    virtual la_status set_entry_value(const key_type& key, size_t length, const value_type& value);
    virtual la_status erase(const key_type& key, size_t length, const value_type& value);
    virtual la_status insert(const key_type& key, size_t length, const value_type& value);
    virtual la_status bulk_updates(const npl_lpm_bulk_entries_vec<_Trait>& lpm_entries, size_t& out_count_success);
};

template <class _Trait>
la_status
ra_empty_lpm_translator<_Trait>::insert(const key_type& key, size_t length, const value_type& value)
{
    log_debug(RA,
              "ra_empty_lpm_translator::insert(%s, %s, %zd, %s)",
              _Trait::get_table_name().c_str(),
              key.pack().to_string().c_str(),
              length,
              value.pack().to_string().c_str());

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_empty_lpm_translator<_Trait>::set_entry_value(const key_type& key, size_t length, const value_type& value)
{
    log_debug(RA,
              "ra_empty_lpm_translator::set_entry_value(%s, %s, %zd, %s)",
              _Trait::get_table_name().c_str(),
              key.pack().to_string().c_str(),
              length,
              value.pack().to_string().c_str());

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_empty_lpm_translator<_Trait>::erase(const key_type& key, size_t length, const value_type& value)
{
    log_debug(RA,
              "ra_empty_lpm_translator::erase(%s, %s, %zd, %s)",
              _Trait::get_table_name().c_str(),
              key.pack().to_string().c_str(),
              length,
              value.pack().to_string().c_str());

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_empty_lpm_translator<_Trait>::bulk_updates(const npl_lpm_bulk_entries_vec<_Trait>& lpm_entries, size_t& out_count_success)
{
    log_debug(RA, "ra_empty_lpm_translator::bulk_updates(%s)", _Trait::get_table_name().c_str());

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_empty_ternary_translator<_Trait>::set_trans_info(void* trans_info)
{
    return LA_STATUS_SUCCESS;
}

}; // namespace silicon_one

#endif // __RA_EMPTY_TRANSLATORS_H__
