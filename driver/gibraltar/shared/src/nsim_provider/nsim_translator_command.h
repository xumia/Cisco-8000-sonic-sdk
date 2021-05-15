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

#ifndef __NSIM_TRANSLATOR_COMMAND_H__
#define __NSIM_TRANSLATOR_COMMAND_H__

#include "lld/device_tree.h"
#include "lld/ll_device.h"

#include "nsim_provider/sim_command.h"

namespace silicon_one
{
/// @brief Commands used by all available nsim table translators.
class nsim_translator_command
{
public:
    nsim_translator_command(ll_device_sptr lld) : m_ll_device(lld)
    {
        if (lld) {
            if (lld->is_pacific()) {
                m_command_mem = lld->get_pacific_tree()->sim_access->nsim_command_mem;
            } else if (lld->is_gibraltar()) {
                m_command_mem = lld->get_gibraltar_tree()->sim_access->nsim_command_mem;
            }
        }
    }

    la_status send(sim_command::nsim_command_e command, size_t table_id, size_t slice_idx, size_t line)
    {
        m_cmd.line = line;

        return send(command, table_id, slice_idx);
    }

    template <class _Key, class _Value>
    la_status send(sim_command::nsim_command_e command, size_t table_id, size_t slice_idx, const _Key& key, const _Value& value)
    {
        translate_to_byte_array(key, m_cmd.key);
        translate_to_byte_array(value, m_cmd.value);

        return send(command, table_id, slice_idx);
    }

    template <class _Key, class _Value>
    la_status send(sim_command::nsim_command_e command,
                   size_t table_id,
                   size_t slice_idx,
                   size_t line,
                   const _Key& key,
                   const _Key& mask,
                   const _Value& value)
    {
        translate_to_byte_array(mask, m_cmd.key_mask);
        m_cmd.line = line;

        return send(command, table_id, slice_idx, key, value);
    }

    template <class _Key, class _Value>
    la_status send(sim_command::nsim_command_e command,
                   size_t table_id,
                   size_t slice_idx,
                   const _Key& key,
                   size_t length,
                   const _Value& value)
    {
        m_cmd.key_len = length;

        return send(command, table_id, slice_idx, key, value);
    }

private:
    la_status send(sim_command::nsim_command_e command, size_t table_id, size_t slice_idx)
    {
        m_cmd.table_id = table_id;
        m_cmd.slice_idx = slice_idx;
        m_cmd.cmd = command;

        if (m_command_mem) {
            size_t width_total = m_command_mem->get_desc()->width_total;
            size_t entries = sizeof(m_cmd) / width_total;

            dassert_crit((entries * width_total == sizeof(m_cmd))
                         && "sizeof(sim_command::command) must be an integer multiple of nsim_command_mem width_total");

            return m_ll_device->write_memory(*m_command_mem, 0 /*first entry*/, entries, sizeof(m_cmd), &m_cmd);
        }

        return LA_STATUS_SUCCESS;
    }

    template <class V>
    void translate_to_byte_array(const V& val, sim_command::reg_data& buf)
    {

        bit_vector bv = val.pack();
        buf.long_cmd.width = bv.get_width();

        if (bv.get_width_in_bytes() > sim_command::LONG_FIELD_LEN) {
            log_err(HLD,
                    "%s: register data structure is too small, bv.get_width_in_bytes() %lu, sim_command::LONG_FIELD_LEN %d",
                    __func__,
                    bv.get_width_in_bytes(),
                    sim_command::LONG_FIELD_LEN);
        }

        memcpy(&buf.long_cmd.value, bv.byte_array(), bv.get_width_in_bytes());
    }

private:
    ll_device_sptr m_ll_device;
    lld_memory_sptr m_command_mem;
    sim_command::command m_cmd;
};

} // namespace silicon_one

#endif // __NSIM_TRANSLATOR_COMMAND_H__
