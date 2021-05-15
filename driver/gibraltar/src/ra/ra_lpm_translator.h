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

#ifndef __RA_LPM_TRANSLATOR_H__
#define __RA_LPM_TRANSLATOR_H__

#include "hw_tables/lpm_types.h"
#include "nplapi/npl_lpm_table_translator_base.h"
#include "nplapi_translator/npl_table_entry_translation.h"
#include "special_tables/lpm_db.h"

namespace silicon_one
{

/// @brief npl_lpm_translator interface implementation for LPM NPL tables.
template <class _Trait>
class ra_lpm_translator : public npl_lpm_table_translator_base<_Trait>
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    typedef typename _Trait::key_type key_type;
    typedef typename _Trait::value_type value_type;

    // C'tor
    ra_lpm_translator(std::unique_ptr<lpm_db> db);

    virtual la_status set_entry_value(const key_type& key, size_t length, const value_type& value);
    virtual la_status erase(const key_type& key, size_t length, const value_type& value);
    virtual la_status insert(const key_type& key, size_t length, const value_type& value);
    virtual la_status bulk_updates(const npl_lpm_bulk_entries_vec<_Trait>& lpm_entries, size_t& out_count_success);
    virtual size_t max_size() const;
    virtual size_t get_physical_usage(size_t number_of_logical_entries_in_table) const;
    virtual size_t get_available_entries() const;

    template <class Archive>
    void serialize(Archive& ar)
    {
        ar(m_db, m_actions, m_npu_features);
    }

private:
    ra_lpm_translator() = default; // For serialization purposes only.

    // line translator results
    typedef std::vector<table_generic_entry_t> lt_result_vec_t;

    // forbid copy
    ra_lpm_translator(const ra_lpm_translator&);
    ra_lpm_translator& operator=(const ra_lpm_translator&);
    void prefix_translate(const key_type& key, const value_type& value, lt_result_vec_t& out_lt_res_vec);
    void action_translate(const npl_action_e ip_action, lpm_action_e& out_action) const;

private:
    // Physical resource access
    std::unique_ptr<lpm_db> m_db;

    // LPM bulk actions vector
    lpm_db::lpm_db_action_desc_vec_t m_actions;

    npu_features_t m_npu_features;
};

template <class _Trait>
ra_lpm_translator<_Trait>::ra_lpm_translator(std::unique_ptr<lpm_db> db) : m_db(std::move(db)), m_npu_features()
{
    m_npu_features.alternate_next_engine_bits = 1;
}

template <class _Trait>
void
ra_lpm_translator<_Trait>::prefix_translate(const key_type& key, const value_type& value, lt_result_vec_t& out_lt_res_vec)
{
    out_lt_res_vec.clear();

    nplapi_table_entry_translation::translate_entry(
        NPL_NONE_CONTEXT, 0 /*replication_id*/, key, value, out_lt_res_vec, &m_npu_features);

    // multi-line is not supported in this translator
    dassert_crit(out_lt_res_vec.size() <= 1);
}

template <class _Trait>
la_status
ra_lpm_translator<_Trait>::insert(const key_type& key, size_t length, const value_type& value)
{
    log_debug(RA,
              "ra_lpm_translator::insert(%s, %s, %zd, %s)",
              _Trait::get_table_name().c_str(),
              key.pack().to_string().c_str(),
              length,
              value.pack().to_string().c_str());

    lt_result_vec_t lt_res_vec;
    prefix_translate(key, value, lt_res_vec);

    if (lt_res_vec.empty()) {
        // Line translation gave nothing for this context/replication idx. No error should be issued.
        return LA_STATUS_SUCCESS;
    }

    const table_generic_entry_t& lt_res = lt_res_vec.back();

    la_status ret = m_db->insert(lt_res.key, length, lt_res.payload);

    return ret;
}

template <class _Trait>
la_status
ra_lpm_translator<_Trait>::set_entry_value(const key_type& key, size_t length, const value_type& value)
{
    log_debug(RA,
              "ra_lpm_translator::set_entry_value(%s, %s, %zd, %s)",
              _Trait::get_table_name().c_str(),
              key.pack().to_string().c_str(),
              length,
              value.pack().to_string().c_str());

    lt_result_vec_t lt_res_vec;
    prefix_translate(key, value, lt_res_vec);

    if (lt_res_vec.empty()) {
        // Line translation gave nothing for this context/replication idx. No error should be issued.
        return LA_STATUS_SUCCESS;
    }

    const table_generic_entry_t& lt_res = lt_res_vec.back();

    la_status ret = m_db->update(lt_res.key, length, lt_res.payload);

    return ret;
}

template <class _Trait>
la_status
ra_lpm_translator<_Trait>::erase(const key_type& key, size_t length, const value_type& value)
{
    log_debug(RA,
              "ra_lpm_translator::erase(%s, %s, %zd, %s)",
              _Trait::get_table_name().c_str(),
              key.pack().to_string().c_str(),
              length,
              value.pack().to_string().c_str());

    lt_result_vec_t lt_res_vec;
    prefix_translate(key, value, lt_res_vec);

    if (lt_res_vec.empty()) {
        // Line translation gave nothing for this context/replication idx. No error should be issued.
        return LA_STATUS_SUCCESS;
    }

    const table_generic_entry_t& lt_res = lt_res_vec.back();

    la_status ret = m_db->erase(lt_res.key, length);

    return ret;
}

template <class _Trait>
void
ra_lpm_translator<_Trait>::action_translate(const npl_action_e ip_action, lpm_action_e& out_action) const
{
    switch (ip_action) {
    case npl_action_e::ADD:
        out_action = lpm_action_e::INSERT;
        break;

    case npl_action_e::DELETE:
        out_action = lpm_action_e::REMOVE;
        break;

    case npl_action_e::MODIFY:
        out_action = lpm_action_e::MODIFY;
        break;
    }
}

template <class _Trait>
la_status
ra_lpm_translator<_Trait>::bulk_updates(const npl_lpm_bulk_entries_vec<_Trait>& lpm_entries, size_t& out_count_success)
{
    lt_result_vec_t lt_res_vec;

    log_debug(RA, "ra_lpm_translator::bulk_updates(%s): size %zu", _Trait::get_table_name().c_str(), lpm_entries.size());
    m_actions.resize(lpm_entries.size());

    size_t j = 0;
    for (size_t i = 0; i < lpm_entries.size(); i++) {
        prefix_translate(lpm_entries[i].key, lpm_entries[i].value, lt_res_vec);
        if (lt_res_vec.empty()) {
            // Line translation gave nothing for this context/replication idx. No error should be issued.
            continue;
        }

        const table_generic_entry_t& lt_res = lt_res_vec.back();
        action_translate(lpm_entries[i].action, m_actions[j].action);
        m_actions[j].length = lpm_entries[i].length;
        m_actions[j].key = lt_res.key;
        m_actions[j].payload = lt_res.payload;
        m_actions[j].latency_sensitive = lpm_entries[i].latency_sensitive;
        j++;
    }

    m_actions.resize(j);
    la_status ret = m_db->bulk_updates(m_actions, out_count_success);

    if (ret != LA_STATUS_SUCCESS) {
        log_err(RA,
                "ra_lpm_translator::bulk_updates(%s) done: size %zu, out_count_success %zu, status %s",
                _Trait::get_table_name().c_str(),
                lpm_entries.size(),
                out_count_success,
                la_status2str(ret).c_str());
    } else {
        log_debug(RA,
                  "ra_lpm_translator::bulk_updates(%s) done: size %zu, out_count_success %zu",
                  _Trait::get_table_name().c_str(),
                  lpm_entries.size(),
                  out_count_success);
        dassert_crit(lpm_entries.size() == out_count_success);
    }

    return ret;
}

template <class _Trait>
size_t
ra_lpm_translator<_Trait>::max_size() const
{
    return m_db->max_size();
}

template <class _Trait>
size_t
ra_lpm_translator<_Trait>::get_physical_usage(size_t number_of_logical_entries_in_table) const
{
    return m_db->get_physical_usage(number_of_logical_entries_in_table);
}

template <class _Trait>
size_t
ra_lpm_translator<_Trait>::get_available_entries() const
{
    return m_db->get_available_entries();
}

}; // namespace silicon_one

#endif // __RA_LPM_TRANSLATOR_H__
