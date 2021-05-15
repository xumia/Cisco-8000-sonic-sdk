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

#ifndef _NSIM_LPM_TRANSLATOR_H_
#define _NSIM_LPM_TRANSLATOR_H_

#include "nplapi/npl_lpm_table_translator_base.h"

#include "nsim_provider/sim_command.h"
#include "nsim_translator_command.h"

namespace silicon_one
{

template <class _Trait>
class nsim_lpm_translator : public npl_lpm_table_translator_base<_Trait>
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    typedef typename _Trait::key_type key_type;
    typedef typename _Trait::value_type value_type;

    nsim_lpm_translator(size_t index, ll_device_sptr device);
    virtual ~nsim_lpm_translator()
    {
    }
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
        ar(m_index, m_is_initialized, m_ll_device);
    }

private:
    nsim_lpm_translator() = default; // For serialization purposes only
    size_t m_index;
    bool m_is_initialized;
    ll_device_sptr m_ll_device;
};

template <class _Trait>
nsim_lpm_translator<_Trait>::nsim_lpm_translator(size_t index, ll_device_sptr device)
    : m_index(index), m_is_initialized(false), m_ll_device(device)
{
    if (device) {
        m_is_initialized = (device->get_pacific_tree() != nullptr || device->get_gibraltar_tree() != nullptr
                            || device->get_asic4_tree() != nullptr
                            || device->get_asic3_tree() != nullptr
                            || device->get_asic5_tree() != nullptr);
    }
}

template <class _Trait>
la_status
nsim_lpm_translator<_Trait>::set_entry_value(const key_type& key, size_t length, const value_type& value)
{
    if (!m_is_initialized) {
        return LA_STATUS_EUNKNOWN;
    }

    sim_command::nsim_command_e command = sim_command::nsim_command_e::LPM_TABLE_UPDATE;
    size_t table_id = _Trait::table_id;
    nsim_translator_command cmd(m_ll_device);

    return cmd.send(command, table_id, m_index, key, length, value);
}

template <class _Trait>
la_status
nsim_lpm_translator<_Trait>::erase(const key_type& key, size_t length, const value_type& value)
{
    if (!m_is_initialized) {
        return LA_STATUS_EUNKNOWN;
    }

    sim_command::nsim_command_e command = sim_command::nsim_command_e::LPM_TABLE_ERASE;
    size_t table_id = _Trait::table_id;
    nsim_translator_command cmd(m_ll_device);

    return cmd.send(command, table_id, m_index, key, length, value);
}

template <class _Trait>
la_status
nsim_lpm_translator<_Trait>::insert(const key_type& key, size_t length, const value_type& value)
{
    if (!m_is_initialized) {
        return LA_STATUS_EUNKNOWN;
    }

    sim_command::nsim_command_e command = sim_command::nsim_command_e::LPM_TABLE_INSERT;
    size_t table_id = _Trait::table_id;
    nsim_translator_command cmd(m_ll_device);

    return cmd.send(command, table_id, m_index, key, length, value);
}

template <class _Trait>
la_status
nsim_lpm_translator<_Trait>::bulk_updates(const npl_lpm_bulk_entries_vec<_Trait>& lpm_entries, size_t& out_count_success)
{
    la_status status;

    out_count_success = 0;
    for (size_t i = 0; i < lpm_entries.size(); i++) {
        switch (lpm_entries[i].action) {
        case npl_action_e::ADD:
            status = insert(lpm_entries[i].key, lpm_entries[i].length, lpm_entries[i].value);
            return_on_error(status);
            break;
        case npl_action_e::DELETE:
            status = erase(lpm_entries[i].key, lpm_entries[i].length, lpm_entries[i].value);
            return_on_error(status);
            break;
        case npl_action_e::MODIFY:
            status = set_entry_value(lpm_entries[i].key, lpm_entries[i].length, lpm_entries[i].value);
            return_on_error(status);
            break;
        }
        out_count_success++;
    }
    return LA_STATUS_SUCCESS;
}

template <class _Trait>
size_t
nsim_lpm_translator<_Trait>::max_size() const
{
    // Return a large value for NSIM. max_size of tables is computed as min() of
    // all translators. Setting nsim_translator to return a large number will allow us to
    // get accurate max_size from RA translators.
    return std::numeric_limits<std::size_t>::max();
}

template <class _Trait>
size_t
nsim_lpm_translator<_Trait>::get_physical_usage(size_t number_of_logical_entries_in_table) const
{
    return number_of_logical_entries_in_table;
}

template <class _Trait>
size_t
nsim_lpm_translator<_Trait>::get_available_entries() const
{
    return std::numeric_limits<std::size_t>::max();
}

}; // namespace silicon_one

#endif // _NSIM_LPM_TRANSLATOR_H_
