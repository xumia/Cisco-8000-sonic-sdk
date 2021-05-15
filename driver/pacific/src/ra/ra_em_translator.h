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

#ifndef __RA_EM_TRANSLATOR_H__
#define __RA_EM_TRANSLATOR_H__

#include "hw_tables/hw_tables_fwd.h"
#include "hw_tables/logical_em.h"
#include "nplapi/npl_table_translator_base.h"
#include "nplapi_translator/npl_table_entry_translation.h"

#include "common/logger.h"

namespace silicon_one
{

/// @brief npl_translator interface implementation for Exact Match NPL tables.
template <class _Trait>
class ra_em_translator : public npl_table_translator_base<_Trait>
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    typedef typename _Trait::key_type key_type;
    typedef typename _Trait::value_type value_type;

    // C'tors
    ra_em_translator(const ll_device_sptr& ll_dev,
                     npl_context_e context,
                     size_t replication_idx,
                     const logical_em_sptr& em,
                     size_t em_key_width,
                     size_t em_payload_width,
                     size_t em_application_specific_fields_width);

    virtual la_status set_entry_value(const key_type& key, const value_type& value);
    virtual la_status erase(const key_type& key, const value_type& value);
    virtual la_status insert(const key_type& key, const value_type& value);
    virtual size_t max_size() const;
    virtual la_status get_physical_usage(size_t number_of_logical_entries_in_table, size_t& out_physical_usage) const;
    virtual la_status get_available_entries(size_t& out_available_entries) const;

    template <class Archive>
    void serialize(Archive& ar)
    {
        ar(m_ll_device,
           m_context_id,
           m_replication_idx,
           m_em,
           m_em_key_width,
           m_em_payload_width,
           m_em_application_specific_fields_width,
           m_npu_features);
    }

private:
    ra_em_translator() = default; // For serialization purposes only.

    // line translator results
    typedef std::vector<table_generic_entry_t> lt_result_vec_t;

    // forbid copy
    ra_em_translator(const ra_em_translator&);
    ra_em_translator& operator=(const ra_em_translator&);

private:
    // Low-level device
    ll_device_sptr m_ll_device;

    // Context of the current replication.
    npl_context_e m_context_id;

    // Index of the current replication within the same context.
    size_t m_replication_idx;

    // Physical resource access
    logical_em_sptr m_em;

    // Width of the underlying EM key - should be greater than table key.
    size_t m_em_key_width;

    // Width of the underlying EM payload - should be greater than table value.
    size_t m_em_payload_width;

    // Width of application-specific result fields that are not programmed to
    // the EM, and should be discounted from size computations such as single
    // vs double-entry. Example: MAC age field which is 1:1 with the CEM location
    // but is in a separate hw resource.
    size_t m_em_application_specific_fields_width;

    npu_features_t m_npu_features;
};

template <class _Trait>
ra_em_translator<_Trait>::ra_em_translator(const ll_device_sptr& ll_dev,
                                           npl_context_e context_id,
                                           size_t replication_idx,
                                           const logical_em_sptr& em,
                                           size_t em_key_width,
                                           size_t em_payload_width,
                                           size_t em_application_specific_fields_width)
    : m_ll_device(ll_dev),
      m_context_id(context_id),
      m_replication_idx(replication_idx),
      m_em(em),
      m_em_key_width(em_key_width),
      m_em_payload_width(em_payload_width),
      m_em_application_specific_fields_width(em_application_specific_fields_width),
      m_npu_features()
{
    dassert_crit(em);

    bool alternate_next_engine_bits = (m_ll_device->get_device_revision() == la_device_revision_e::PACIFIC_A0);
    m_npu_features.alternate_next_engine_bits = alternate_next_engine_bits;
}

template <class _Trait>
la_status
ra_em_translator<_Trait>::set_entry_value(const key_type& key, const value_type& value)
{
    log_debug(RA,
              "ra_em_translator(%d, %zd)::set_entry_value(%s, %s, %s)",
              m_context_id,
              m_replication_idx,
              _Trait::get_table_name().c_str(),
              key.pack().to_string().c_str(),
              value.pack().to_string().c_str());

    lt_result_vec_t lt_res_vec;
    nplapi_table_entry_translation::translate_entry(m_context_id, m_replication_idx, key, value, lt_res_vec, &m_npu_features);

    // multi-line insert is not supported in this translator
    dassert_crit(lt_res_vec.size() <= 1);

    if (lt_res_vec.empty()) {
        // Line translation gave nothing for this context/replication idx. No error should be issued.
        return LA_STATUS_SUCCESS;
    }

    table_generic_entry_t lt_res = lt_res_vec.back();

    dassert_crit(lt_res.key.get_width() <= m_em_key_width);
    lt_res.key.resize(m_em_key_width);
    dassert_crit(lt_res.payload.get_minimal_width() <= m_em_payload_width);
    lt_res.payload.resize(m_em_payload_width);

    la_status ret = m_em->update(lt_res.key, lt_res.payload);

    return ret;
}

template <class _Trait>
la_status
ra_em_translator<_Trait>::erase(const key_type& key, const value_type& value)
{
    log_debug(RA,
              "ra_em_translator(%d, %zd)::erase(%s, %s, %s)",
              m_context_id,
              m_replication_idx,
              _Trait::get_table_name().c_str(),
              key.pack().to_string().c_str(),
              value.pack().to_string().c_str());

    lt_result_vec_t lt_res_vec;
    nplapi_table_entry_translation::translate_entry(m_context_id, m_replication_idx, key, value, lt_res_vec, &m_npu_features);

    // multi-line insert is not supported in this translator
    dassert_crit(lt_res_vec.size() <= 1);

    if (lt_res_vec.empty()) {
        // Line translation gave nothing for this context/replication idx. No error should be issued.
        return LA_STATUS_SUCCESS;
    }

    table_generic_entry_t lt_res = lt_res_vec.back();

    dassert_crit(lt_res.key.get_width() <= m_em_key_width);
    lt_res.key.resize(m_em_key_width);

    la_status ret;
    if (m_em->is_flexible_entry_supported()) {
        ret = m_em->erase(lt_res.key, m_em_payload_width);
    } else {
        ret = m_em->erase(lt_res.key);
    }

    return ret;
}

template <class _Trait>
la_status
ra_em_translator<_Trait>::insert(const key_type& key, const value_type& value)
{
    log_debug(RA,
              "ra_em_translator(%d, %zd)::insert(%s, %s, %s)",
              m_context_id,
              m_replication_idx,
              _Trait::get_table_name().c_str(),
              key.pack().to_string().c_str(),
              value.pack().to_string().c_str());

    lt_result_vec_t lt_res_vec;
    nplapi_table_entry_translation::translate_entry(m_context_id, m_replication_idx, key, value, lt_res_vec, &m_npu_features);

    // multi-line insert is not supported in this translator
    dassert_crit(lt_res_vec.size() <= 1);

    if (lt_res_vec.empty()) {
        // Line translation gave nothing for this context/replication idx. No error should be issued.
        return LA_STATUS_SUCCESS;
    }

    table_generic_entry_t lt_res = lt_res_vec.back();

    dassert_crit(lt_res.key.get_width() <= m_em_key_width);
    lt_res.key.resize(m_em_key_width);
    dassert_crit(lt_res.payload.get_minimal_width() <= m_em_payload_width);
    lt_res.payload.resize(m_em_payload_width);

    la_status ret = m_em->insert(lt_res.key, lt_res.payload);

    return ret;
}

template <class _Trait>
size_t
ra_em_translator<_Trait>::max_size() const
{
    return m_em->max_size();
}

template <class _Trait>
la_status
ra_em_translator<_Trait>::get_physical_usage(size_t number_of_logical_entries_in_table, size_t& out_physical_usage) const
{
    la_status status = m_em->get_physical_usage(number_of_logical_entries_in_table, out_physical_usage);
    return status;
}

template <class _Trait>
la_status
ra_em_translator<_Trait>::get_available_entries(size_t& out_available_entries) const
{
    la_status status = m_em->get_available_entries(out_available_entries);
    return status;
}

}; // namespace silicon_one

#endif // __RA_EM_TRANSLATOR_H__
