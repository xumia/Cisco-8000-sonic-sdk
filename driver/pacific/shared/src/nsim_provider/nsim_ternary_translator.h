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

//

#ifndef _NSIM_TERNARY_TRANSLATOR_H_
#define _NSIM_TERNARY_TRANSLATOR_H_

#include "nplapi/npl_ternary_table_translator_base.h"

#include "common/defines.h"
#include "nsim_provider/sim_command.h"
#include "nsim_translator_command.h"

#include <memory>

namespace silicon_one
{

template <class _Trait>
class nsim_ternary_translator : public npl_ternary_table_translator_base<_Trait>
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    typedef typename _Trait::key_type key_type;
    typedef typename _Trait::value_type value_type;
    typedef typename npl_ternary_table_translator_base<_Trait>::npl_translator_entry_desc npl_translator_entry_desc;

    nsim_ternary_translator(size_t index, ll_device_sptr device);
    virtual ~nsim_ternary_translator()
    {
    }
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
        ar(m_ref_model, m_index, m_is_initialized, m_ll_device);
    }

private:
    nsim_ternary_translator() = default; // For serialization purposes only.
    struct entry {
        entry() : is_valid(false)
        {
        }

        bool is_valid;
        key_type key;
        key_type mask;
        value_type value;

        template <class Archive>
        void serialize(Archive& ar)
        {
            ar(is_valid, key, mask, value);
        }
    };

    std::vector<std::unique_ptr<entry> > m_ref_model;

    size_t m_index;
    bool m_is_initialized;
    ll_device_sptr m_ll_device;
};

template <class _Trait>
nsim_ternary_translator<_Trait>::nsim_ternary_translator(size_t index, ll_device_sptr device)
    : m_index(index), m_is_initialized(false), m_ll_device(device)
{
    if (device) {
        m_is_initialized = (device->get_pacific_tree() != nullptr || device->get_gibraltar_tree() != nullptr
                            || device->get_asic4_tree() != nullptr
                            || device->get_asic3_tree() != nullptr
                            || device->get_asic5_tree() != nullptr);
    }

    m_ref_model.resize(max_size());
}

template <class _Trait>
la_status
nsim_ternary_translator<_Trait>::initialize()
{
    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
nsim_ternary_translator<_Trait>::set_entry_value(size_t line, const key_type& key, const key_type& mask, const value_type& value)
{
    dassert_crit(line < m_ref_model.size());
    dassert_crit(m_ref_model[line] && m_ref_model[line]->is_valid);

    if (!m_is_initialized) {
        return LA_STATUS_EUNKNOWN;
    }

    // Send command to nsim.
    size_t table_id = _Trait::table_id;
    nsim_translator_command cmd(m_ll_device);

    la_status status = cmd.send(sim_command::nsim_command_e::TERNARY_TABLE_UPDATE, table_id, m_index, line, key, mask, value);
    return_on_error(status);

    // Update ref model.
    m_ref_model[line]->value = value;

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
nsim_ternary_translator<_Trait>::insert(size_t line, const key_type& key, const key_type& mask, const value_type& value)
{
    log_debug(RA, "%s::insert(location=%lu)", _Trait::get_table_name().c_str(), line);

    if (!m_is_initialized) {
        return LA_STATUS_EUNKNOWN;
    }

    // Update ref model.
    if (line >= m_ref_model.size()) {
        return LA_STATUS_EUNKNOWN;
    }

    // Send command to nsim.
    size_t table_id = _Trait::table_id;
    nsim_translator_command cmd(m_ll_device);

    la_status status = cmd.send(sim_command::nsim_command_e::TERNARY_TABLE_INSERT, table_id, m_index, line, key, mask, value);
    return_on_error(status);

    // Update ref model.
    if (!m_ref_model[line]) {
        m_ref_model[line] = std::unique_ptr<entry>(new entry);
    }
    m_ref_model[line]->key = key;
    m_ref_model[line]->mask = mask;
    m_ref_model[line]->value = value;
    m_ref_model[line]->is_valid = true;

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
nsim_ternary_translator<_Trait>::insert_bulk(size_t first_line,
                                             size_t bulk_size,
                                             const vector_alloc<npl_translator_entry_desc>& entries)
{
    log_debug(RA, "%s::insert_bulk(first_line=%lu, bulk_size=%lu)", _Trait::get_table_name().c_str(), first_line, bulk_size);

    la_status status = LA_STATUS_SUCCESS;

    if (!m_is_initialized) {
        return LA_STATUS_EUNKNOWN;
    }

    // Update ref model's size.
    if (first_line + bulk_size > m_ref_model.size()) {
        return LA_STATUS_EUNKNOWN;
    }

    size_t table_id = _Trait::table_id;

    size_t line = first_line;
    for (size_t i = 0; i < bulk_size; i++) {
        // Send command to nsim.
        nsim_translator_command cmd(m_ll_device);
        status = cmd.send(sim_command::nsim_command_e::TERNARY_TABLE_INSERT,
                          table_id,
                          m_index,
                          line,
                          entries[i].key,
                          entries[i].mask,
                          entries[i].value);
        if (status != LA_STATUS_SUCCESS) {
            break;
        }

        if (!m_ref_model[line]) {
            m_ref_model[line] = std::unique_ptr<entry>(new entry);
        }

        // Now insert the new line
        m_ref_model[line]->key = entries[i].key;
        m_ref_model[line]->mask = entries[i].mask;
        m_ref_model[line]->value = entries[i].value;
        m_ref_model[line]->is_valid = true;

        line++;
    }

    if (status != LA_STATUS_SUCCESS) {
        for (; line >= first_line; line--) {
            nsim_translator_command cmd(m_ll_device);
            cmd.send(sim_command::nsim_command_e::TERNARY_TABLE_ERASE, table_id, m_index, line);
            m_ref_model[line] = nullptr;
        }
        return status;
    }

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
nsim_ternary_translator<_Trait>::push(size_t line,
                                      size_t free_slot,
                                      const key_type& key,
                                      const key_type& mask,
                                      const value_type& value)
{
    log_debug(RA, "%s::push(location=%lu)", _Trait::get_table_name().c_str(), line);
    dassert_crit(free_slot > line);

    la_status status = LA_STATUS_SUCCESS;

    if (!m_is_initialized) {
        return LA_STATUS_EUNKNOWN;
    }

    // Update ref model's size.
    if (free_slot >= m_ref_model.size()) {
        return LA_STATUS_EUNKNOWN;
    }

    size_t table_id = _Trait::table_id;

    // Go bottom up and shift the entries down.
    for (size_t curr_line = free_slot; curr_line > line; --curr_line) {
        // All entries should be valid.
        dassert_crit(m_ref_model[curr_line - 1] && m_ref_model[curr_line - 1]->is_valid);

        // Send command to nsim.
        nsim_translator_command ins_cmd(m_ll_device);
        status = ins_cmd.send(sim_command::nsim_command_e::TERNARY_TABLE_INSERT,
                              table_id,
                              m_index,
                              curr_line,
                              m_ref_model[curr_line - 1]->key,
                              m_ref_model[curr_line - 1]->mask,
                              m_ref_model[curr_line - 1]->value);
        return_on_error(status);

        nsim_translator_command rem_cmd(m_ll_device);
        status = rem_cmd.send(sim_command::nsim_command_e::TERNARY_TABLE_ERASE, table_id, m_index, curr_line - 1);
        return_on_error(status);

        // Update ref model.
        m_ref_model[curr_line] = std::move(m_ref_model[curr_line - 1]);
    }

    // Send command to nsim.
    nsim_translator_command cmd(m_ll_device);
    status = cmd.send(sim_command::nsim_command_e::TERNARY_TABLE_INSERT, table_id, m_index, line, key, mask, value);
    return_on_error(status);

    if (!m_ref_model[line]) {
        m_ref_model[line] = std::unique_ptr<entry>(new entry);
    }

    // Now insert the new line
    m_ref_model[line]->key = key;
    m_ref_model[line]->mask = mask;
    m_ref_model[line]->value = value;
    m_ref_model[line]->is_valid = true;

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
nsim_ternary_translator<_Trait>::erase(size_t line)
{
    log_debug(RA, "%s::erase(location=%lu)", _Trait::get_table_name().c_str(), line);

    dassert_crit(line < m_ref_model.size());

    if (!m_is_initialized) {
        return LA_STATUS_EUNKNOWN;
    }

    // Send command to nsim.
    size_t table_id = _Trait::table_id;
    nsim_translator_command cmd(m_ll_device);

    la_status status = cmd.send(sim_command::nsim_command_e::TERNARY_TABLE_ERASE, table_id, m_index, line);
    return_on_error(status);

    // Update ref model.
    m_ref_model[line] = nullptr;

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
nsim_ternary_translator<_Trait>::move(size_t dst_line, size_t src_line, size_t count)
{
    la_status status = LA_STATUS_SUCCESS;

    log_debug(RA, "%s::move(dst_line=%lu, src_line=%lu, count=%lu)", _Trait::get_table_name().c_str(), dst_line, src_line, count);

    dassert_crit((dst_line < m_ref_model.size()) && (src_line < m_ref_model.size()) && ((dst_line + count) < m_ref_model.size()));

    if (!m_is_initialized) {
        return LA_STATUS_EUNKNOWN;
    }

    if (!count) {
        return LA_STATUS_SUCCESS;
    }

    size_t table_id = _Trait::table_id;

    // Remove the dst_line, if occupied.
    if (m_ref_model[dst_line] && m_ref_model[dst_line]->is_valid) {

        // Send command to nsim.
        nsim_translator_command cmd(m_ll_device);
        status = cmd.send(sim_command::nsim_command_e::TERNARY_TABLE_ERASE, table_id, m_index, dst_line);
        return_on_error(status);

        // Update ref model.
        m_ref_model[dst_line] = nullptr;
    }

    // Go top down and shift the entries up.
    size_t dest_line = dst_line;
    for (size_t curr_line = src_line; curr_line < (src_line + count); ++curr_line, ++dest_line) {

        if (!m_ref_model[curr_line] || !m_ref_model[curr_line]->is_valid) {
            continue;
        }

        // Send command to nsim.
        nsim_translator_command ins_cmd(m_ll_device);
        status = ins_cmd.send(sim_command::nsim_command_e::TERNARY_TABLE_INSERT,
                              table_id,
                              m_index,
                              dest_line,
                              m_ref_model[curr_line]->key,
                              m_ref_model[curr_line]->mask,
                              m_ref_model[curr_line]->value);
        return_on_error(status);

        nsim_translator_command rem_cmd(m_ll_device);
        status = rem_cmd.send(sim_command::nsim_command_e::TERNARY_TABLE_ERASE, table_id, m_index, curr_line);
        return_on_error(status);

        // Update ref model.
        m_ref_model[dest_line] = std::move(m_ref_model[curr_line]);
    }

    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
nsim_ternary_translator<_Trait>::pop(size_t line)
{
    log_debug(RA, "%s::pop(location=%lu)", _Trait::get_table_name().c_str(), line);

    return move(line, line + 1, m_ref_model.size() - line - 1);
}

template <class _Trait>
size_t
nsim_ternary_translator<_Trait>::max_size() const
{
    return _Trait::table_size;
}

template <class _Trait>
la_status
nsim_ternary_translator<_Trait>::set_trans_info(void* trans_info)
{
    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
nsim_ternary_translator<_Trait>::get_max_available_space(size_t& out_max_scale) const
{
    size_t lines_occupied;
    la_status status = get_physical_usage(lines_occupied);
    dassert_crit(status == LA_STATUS_SUCCESS);
    out_max_scale = max_size() - lines_occupied;
    return LA_STATUS_SUCCESS;
}

template <class _Trait>
la_status
nsim_ternary_translator<_Trait>::get_physical_usage(size_t& out_physical_usage) const
{
    size_t lines_occupied = 0;
    for (size_t line = 0; line < m_ref_model.size(); line++) {
        if (m_ref_model[line] && m_ref_model[line]->is_valid) {
            lines_occupied++;
        }
    }
    out_physical_usage = lines_occupied;
    return LA_STATUS_SUCCESS;
}

}; // namespace silicon_one

#endif // _NSIM_TERNARY_TRANSLATOR_H_
