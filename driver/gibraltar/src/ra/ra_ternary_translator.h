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

//

#ifndef __RA_TERNARY_TRANSLATOR_H__
#define __RA_TERNARY_TRANSLATOR_H__

#include "common/defines.h"
#include "hw_tables/tcam_types.h"
#include "nplapi/npl_ternary_table_translator_base.h"
#include "nplapi/nplapi_fwd.h"
#include "nplapi_translator/npl_table_entry_translation.h"

#include <memory>

namespace silicon_one
{

class logical_tcam;

/// @brief npl_ternary_translator interface implementation for Ternary NPL tables.
///
/// Template parameters:
/// _Trait      Corresponding NPL table trait.
///
template <class _Trait>
class ra_ternary_translator : public npl_ternary_table_translator_base<_Trait>
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    typedef typename _Trait::key_type key_type;
    typedef typename _Trait::value_type value_type;
    typedef typename npl_ternary_table_translator_base<_Trait>::npl_translator_entry_desc npl_translator_entry_desc;

    ra_ternary_translator(const ll_device_sptr& ll_dev,
                          npl_context_e context,
                          size_t replication_idx,
                          bool has_default_value,
                          const logical_tcam_sptr& tcam,
                          const udk_translation_info_sptr& trans_info);

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

    template <class Archive>
    void serialize(Archive& ar)
    {
        ar(m_ref_model,
           m_ll_device,
           m_context_id,
           m_replication_idx,
           m_has_default_value,
           m_tcam,
           m_translation_info,
           m_npu_features);
        m_npu_features.trans_info = m_translation_info.get();
    }

private:
    ra_ternary_translator() = default; // For serialization purposes only.

    // line translator results
    typedef std::vector<ternary_table_generic_entry_t> lt_result_vec_t;

    // forbid copy
    ra_ternary_translator(const ra_ternary_translator&);
    ra_ternary_translator& operator=(const ra_ternary_translator&);

private:
    struct entry {
        entry() : is_valid(false)
        {
        }
        template <class Archive>
        void serialize(Archive& ar)
        {
            ar(is_valid, key, mask, value);
        }
        bool is_valid;
        key_type key;
        key_type mask;
        value_type value;
    };

    std::vector<entry> m_ref_model;

    // Low-level device
    ll_device_sptr m_ll_device;

    // Context of the replication.
    npl_context_e m_context_id;

    // Index of the current replication within the same context.
    size_t m_replication_idx;

    // Whether table has default value.
    bool m_has_default_value;

    // Physical resource access
    logical_tcam_sptr m_tcam;

    udk_translation_info_sptr m_translation_info;
    npu_features_t m_npu_features;
};

template <class _Trait>
ra_ternary_translator<_Trait>::ra_ternary_translator(const ll_device_sptr& ll_dev,
                                                     npl_context_e context,
                                                     size_t replication_idx,
                                                     bool has_default_value,
                                                     const logical_tcam_sptr& tcam,
                                                     const udk_translation_info_sptr& trans_info)
    : m_ll_device(ll_dev),
      m_context_id(context),
      m_replication_idx(replication_idx),
      m_has_default_value(has_default_value),
      m_tcam(tcam),
      m_translation_info(trans_info),
      m_npu_features()
{
    dassert_crit(tcam);

    bool alternate_next_engine_bits = (m_ll_device->get_device_revision() == la_device_revision_e::PACIFIC_A0);
    m_npu_features.alternate_next_engine_bits = alternate_next_engine_bits;
    m_npu_features.trans_info = m_translation_info.get();
    m_ref_model.resize(max_size());
}

template <class _Trait>
la_status
ra_ternary_translator<_Trait>::initialize()
{
    if (m_has_default_value) {
        key_type dummy_key; // needed as type
        ternary_table_generic_entry_t entry
            = nplapi_table_entry_translation::default_action(m_context_id, m_replication_idx, dummy_key);
        size_t default_val_line = m_tcam->size(); // writing default value at the next after last entry

        log_debug(RA,
                  "ra_ternary_translator(%d, %zd)::default_action(%s, %zd, %s, %s, %s)",
                  m_context_id,
                  m_replication_idx,
                  _Trait::get_table_name().c_str(),
                  default_val_line,
                  entry.key.to_string().c_str(),
                  entry.mask.to_string().c_str(),
                  entry.payload.to_string().c_str());

        // Central TCAM needs to add default value for each ctm tcam in order to resolve db merger hw issue
        // This default is initiated by sdk and doesn't have npl support, therefor if a default key
        // was not generated (since the default action is not defined), the key is generated using npl translate_ternary_entry.
        if (entry.key.get_width() == 0) {
            lt_result_vec_t lt_res_vec;
            const key_type key;
            const key_type mask;
            const value_type val;
            nplapi_table_entry_translation::translate_ternary_entry(
                m_context_id, m_replication_idx, key, mask, val, lt_res_vec, &m_npu_features);
            entry = lt_res_vec.back();
        }

        return m_tcam->set_default_value(entry.key, entry.mask, entry.payload);
    }

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_ternary_translator<_Trait>::set_trans_info(void* trans_info)
{
    m_npu_features.trans_info = static_cast<udk_translation_info*>(trans_info);

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_ternary_translator<_Trait>::set_entry_value(size_t line, const key_type& key, const key_type& mask, const value_type& value)
{
    log_debug(RA,
              "ra_ternary_translator(%d, %zd)::set_entry_value(%s, %zd, %s, %s, %s)",
              m_context_id,
              m_replication_idx,
              _Trait::get_table_name().c_str(),
              line,
              key.pack().to_string().c_str(),
              mask.pack().to_string().c_str(),
              value.pack().to_string().c_str());

    dassert_crit(line < m_ref_model.size());
    dassert_crit(m_ref_model[line].is_valid);

    lt_result_vec_t lt_res_vec;
    nplapi_table_entry_translation::translate_ternary_entry(
        m_context_id, m_replication_idx, key, mask, value, lt_res_vec, &m_npu_features);

    dassert_crit(lt_res_vec.size() <= 1);

    if (lt_res_vec.empty()) {
        // Line translation gave nothing for this context/replication idx. No error should be issued.
        return LA_STATUS_SUCCESS;
    }

    const ternary_table_generic_entry_t& entry = lt_res_vec.back();

    la_status status = m_tcam->update(line, entry.payload);
    return_on_error(status);

    // Update ref model.
    m_ref_model[line].value = value;

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_ternary_translator<_Trait>::insert(size_t line, const key_type& key, const key_type& mask, const value_type& value)
{
    log_debug(RA,
              "ra_ternary_translator(%d, %zd)::insert(%s, %zd, %s, %s, %s)",
              m_context_id,
              m_replication_idx,
              _Trait::get_table_name().c_str(),
              line,
              key.pack().to_string().c_str(),
              mask.pack().to_string().c_str(),
              value.pack().to_string().c_str());

    lt_result_vec_t lt_res_vec;
    nplapi_table_entry_translation::translate_ternary_entry(
        m_context_id, m_replication_idx, key, mask, value, lt_res_vec, &m_npu_features);

    dassert_crit(lt_res_vec.size() <= 1);

    if (lt_res_vec.empty()) {
        // Line translation gave nothing for this context/replication idx. No error should be issued.
        return LA_STATUS_SUCCESS;
    }

    if (line >= m_ref_model.size()) {
        return LA_STATUS_EUNKNOWN;
    }

    const ternary_table_generic_entry_t& entry = lt_res_vec.back();

    la_status status = m_tcam->write(line, entry.key, entry.mask, entry.payload);
    return_on_error(status);

    // Update ref model.
    m_ref_model[line].key = key;
    m_ref_model[line].mask = mask;
    m_ref_model[line].value = value;
    m_ref_model[line].is_valid = true;

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_ternary_translator<_Trait>::insert_bulk(size_t first_line,
                                           size_t bulk_size,
                                           const vector_alloc<npl_translator_entry_desc>& entries)
{
    la_status status = LA_STATUS_SUCCESS;

    log_debug(RA,
              "ra_ternary_translator(%d, %zd)::insert_bulk(%s, %zd, %zd)",
              m_context_id,
              m_replication_idx,
              _Trait::get_table_name().c_str(),
              first_line,
              bulk_size);

    // ternary entries translation
    vector_alloc<tcam_entry_desc> translated_entries(bulk_size);
    for (size_t i = 0; i < bulk_size; i++) {
        lt_result_vec_t lt_res_vec;
        nplapi_table_entry_translation::translate_ternary_entry(
            m_context_id, m_replication_idx, entries[i].key, entries[i].mask, entries[i].value, lt_res_vec, &m_npu_features);

        dassert_crit(lt_res_vec.size() <= 1);

        if (lt_res_vec.empty()) {
            // Line translation gave nothing for this context/replication idx. No error should be issued.
            return LA_STATUS_SUCCESS;
        }

        ternary_table_generic_entry_t& entry = lt_res_vec.back();
        translated_entries[i].key = entry.key;
        translated_entries[i].mask = entry.mask;
        translated_entries[i].value = entry.payload;
    }

    if (first_line + bulk_size > m_ref_model.size()) {
        return LA_STATUS_EUNKNOWN;
    }

    // Write entries to the freed lines.
    log_debug(RA,
              "ra_ternary_translator(%d, %zd)::insert_bulk(%s)::write_bulk(%zd, %zd)",
              m_context_id,
              m_replication_idx,
              _Trait::get_table_name().c_str(),
              first_line,
              bulk_size);

    status = m_tcam->write_bulk(first_line, bulk_size, translated_entries);
    return_on_error(status);

    // Now insert the new lines
    for (size_t i = 0; i < bulk_size; i++) {
        m_ref_model[first_line + i].key = entries[i].key;
        m_ref_model[first_line + i].mask = entries[i].mask;
        m_ref_model[first_line + i].value = entries[i].value;
        m_ref_model[first_line + i].is_valid = true;
    }

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_ternary_translator<_Trait>::push(size_t line,
                                    size_t free_slot,
                                    const key_type& key,
                                    const key_type& mask,
                                    const value_type& value)
{
    la_status status = LA_STATUS_SUCCESS;

    dassert_crit(free_slot > line);

    log_debug(RA,
              "ra_ternary_translator(%d, %zd)::push(%s, %zd, %zd, %s, %s, %s)",
              m_context_id,
              m_replication_idx,
              _Trait::get_table_name().c_str(),
              line,
              free_slot,
              key.pack().to_string().c_str(),
              mask.pack().to_string().c_str(),
              value.pack().to_string().c_str());

    lt_result_vec_t lt_res_vec;
    nplapi_table_entry_translation::translate_ternary_entry(
        m_context_id, m_replication_idx, key, mask, value, lt_res_vec, &m_npu_features);

    dassert_crit(lt_res_vec.size() <= 1);

    if (lt_res_vec.empty()) {
        // Line translation gave nothing for this context/replication idx. No error should be issued.
        return LA_STATUS_SUCCESS;
    }

    // Update ref model's size.
    if (free_slot >= m_ref_model.size()) {
        return LA_STATUS_EUNKNOWN;
    }

    const ternary_table_generic_entry_t& entry = lt_res_vec.back();

    // Move entries starting from bottom.
    for (size_t dest_line = free_slot; dest_line > line; --dest_line) {
        // All entries should be valid.
        dassert_crit(m_ref_model[dest_line - 1].is_valid);

        size_t src_line = dest_line - 1;
        log_debug(RA,
                  "ra_ternary_translator(%d, %zd)::push(%s)::move(%zd,%zd)",
                  m_context_id,
                  m_replication_idx,
                  _Trait::get_table_name().c_str(),
                  src_line,
                  dest_line);
        status = m_tcam->move(src_line, dest_line);
        return_on_error(status);

        // Update ref model.
        m_ref_model[dest_line] = m_ref_model[dest_line - 1];
    }

    // Finished pushing entries.
    // Insert entry to the freed line.
    log_debug(RA,
              "ra_ternary_translator(%d, %zd)::push(%s)::write(%zd)",
              m_context_id,
              m_replication_idx,
              _Trait::get_table_name().c_str(),
              line);

    status = m_tcam->write(line, entry.key, entry.mask, entry.payload);
    return_on_error(status);

    // Now insert the new line
    m_ref_model[line].key = key;
    m_ref_model[line].mask = mask;
    m_ref_model[line].value = value;
    m_ref_model[line].is_valid = true;

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_ternary_translator<_Trait>::erase(size_t line)
{
    log_debug(RA,
              "ra_ternary_translator(%d, %zd)::erase(%s, %zd)",
              m_context_id,
              m_replication_idx,
              _Trait::get_table_name().c_str(),
              line);

    dassert_crit(line < m_ref_model.size());

    la_status status = m_tcam->invalidate(line);
    return_on_error(status);

    // Update ref model.
    m_ref_model[line] = entry();

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_ternary_translator<_Trait>::move(size_t dst_line, size_t src_line, size_t count)
{
    log_debug(RA,
              "ra_ternary_translator(%d, %zd)::move(%s, dst_line:%zd, src_line:%zd, count:%zd)",
              m_context_id,
              m_replication_idx,
              _Trait::get_table_name().c_str(),
              dst_line,
              src_line,
              count);

    dassert_crit((dst_line < m_ref_model.size()) && (src_line < m_ref_model.size()) && ((dst_line + count) < m_ref_model.size()));

    if (!count) {
        return LA_STATUS_SUCCESS;
    }

    // Remove the line, if occupied.
    if (m_ref_model[dst_line].is_valid) {

        log_debug(RA,
                  "ra_ternary_translator(%d, %zd)::move(%s, invalidate line %zd)",
                  m_context_id,
                  m_replication_idx,
                  _Trait::get_table_name().c_str(),
                  dst_line);

        la_status status = m_tcam->invalidate(dst_line);
        return_on_error(status);

        // Update ref model.
        m_ref_model[dst_line] = entry();
    }

    // Go top down from the next line and shift the entries up to the
    // invalidated line.
    size_t dest_line = dst_line;
    for (size_t curr_line = src_line; curr_line < (src_line + count); ++curr_line, ++dest_line) {
        if (!m_ref_model[curr_line].is_valid) {
            continue;
        }

        log_debug(RA,
                  "ra_ternary_translator(%d, %zd)::move(%s)::move(%zd,%zd)",
                  m_context_id,
                  m_replication_idx,
                  _Trait::get_table_name().c_str(),
                  curr_line,
                  dest_line);
        la_status status = m_tcam->move(curr_line, dest_line);
        return_on_error(status);

        // Update ref model.
        m_ref_model[dest_line] = m_ref_model[curr_line];
        m_ref_model[curr_line] = entry();
    }

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
ra_ternary_translator<_Trait>::pop(size_t line)
{
    return move(line, line + 1, m_ref_model.size() - line - 1);
}

template <class _Trait>
size_t
ra_ternary_translator<_Trait>::max_size() const
{
    return m_tcam->size();
}

template <class _Trait>
la_status
ra_ternary_translator<_Trait>::get_max_available_space(size_t& out_available_space) const
{
    la_status status = m_tcam->get_max_available_space(out_available_space);
    return status;
}

template <class _Trait>
la_status
ra_ternary_translator<_Trait>::get_physical_usage(size_t& out_physical_usage) const
{

    la_status ret_status = m_tcam->get_physical_usage(out_physical_usage);
    return ret_status;
}

}; // namespace silicon_one

#endif // __RA_TERNARY_TRANSLATOR_H__
