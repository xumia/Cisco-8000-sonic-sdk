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

#ifndef __NSIM_TRANSLATOR_H__
#define __NSIM_TRANSLATOR_H__

#include "nplapi/npl_table_translator_base.h"

#include "nsim_provider/sim_command.h"
#include "nsim_translator_command.h"

namespace silicon_one
{

template <class _Trait>
class nsim_translator : public npl_table_translator_base<_Trait>
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    typedef typename _Trait::key_type key_type;
    typedef typename _Trait::value_type value_type;

    nsim_translator(size_t index, ll_device_sptr device);
    virtual ~nsim_translator()
    {
    }
    virtual la_status set_entry_value(const key_type& key, const value_type& value);
    virtual la_status erase(const key_type& key, const value_type& value);
    virtual la_status insert(const key_type& key, const value_type& value);
    virtual size_t max_size() const;
    virtual la_status get_physical_usage(size_t number_of_logical_entries_in_table, size_t& out_physical_usage) const;
    virtual la_status get_available_entries(size_t& out_available_entries) const;

    template <class Archive>
    void serialize(Archive& ar)
    {
        ar(m_index, m_is_initialized, m_ll_device);
    }

private:
    nsim_translator() = default; // For serialization purposes only.
    size_t m_index;
    bool m_is_initialized;
    ll_device_sptr m_ll_device;
};

template <class _Trait>
nsim_translator<_Trait>::nsim_translator(size_t index, ll_device_sptr device)
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
nsim_translator<_Trait>::set_entry_value(const key_type& key, const value_type& value)
{
    if (!m_is_initialized) {
        return LA_STATUS_EUNKNOWN;
    }

    sim_command::nsim_command_e command = sim_command::nsim_command_e::TABLE_UPDATE;
    size_t table_id = _Trait::table_id;
    nsim_translator_command cmd(m_ll_device);

    return cmd.send(command, table_id, m_index, key, value);
}

template <class _Trait>
la_status
nsim_translator<_Trait>::erase(const key_type& key, const value_type& value)
{
    if (!m_is_initialized) {
        return LA_STATUS_EUNKNOWN;
    }

    sim_command::nsim_command_e command = sim_command::nsim_command_e::TABLE_ERASE;
    size_t table_id = _Trait::table_id;
    nsim_translator_command cmd(m_ll_device);

    return cmd.send(command, table_id, m_index, key, value);
}

template <class _Trait>
la_status
nsim_translator<_Trait>::insert(const key_type& key, const value_type& value)
{
    if (!m_is_initialized) {
        return LA_STATUS_EUNKNOWN;
    }
    sim_command::nsim_command_e command = sim_command::nsim_command_e::TABLE_INSERT;
    size_t table_id = _Trait::table_id;
    nsim_translator_command cmd(m_ll_device);

    return cmd.send(command, table_id, m_index, key, value);
}

template <class _Trait>
size_t
nsim_translator<_Trait>::max_size() const
{
    // Return a large value for NSIM. max_size of tables is computed as min() of
    // all translators. Setting nsim_translator to return a large number will allow us to
    // get accurate max_size from RA translators.
    return std::numeric_limits<std::size_t>::max();
}
template <class _Trait>
la_status
nsim_translator<_Trait>::get_physical_usage(size_t number_of_logical_entries_in_table, size_t& out_physical_usage) const
{
    out_physical_usage = 0;
    return LA_STATUS_SUCCESS;
}
template <class _Trait>
la_status
nsim_translator<_Trait>::get_available_entries(size_t& out_available_entries) const
{
    out_available_entries = std::numeric_limits<std::size_t>::max();
    return LA_STATUS_SUCCESS;
}

}; // namespace silicon_one

#endif // __NSIM_TRANSLATOR_H__
