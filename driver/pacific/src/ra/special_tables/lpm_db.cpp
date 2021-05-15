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

#include "lpm_db.h"

#include "common/logger.h"
#include "hw_tables/logical_lpm.h"

#include "hw_tables/lpm_types.h"
#include "lld/ll_device.h"
#include "lld/pacific_tree.h"

namespace silicon_one
{

lpm_db::lpm_db(const ll_device_sptr& ldevice, size_t prefix_len, lpm_ip_protocol_e ip_protocol, const logical_lpm_wptr& lpm)
    : m_ll_device(ldevice), m_prefix_len(prefix_len), m_protocol(ip_protocol), m_lpm(lpm)
{
    dassert_crit(lpm);
    protocol_bit = (m_protocol == lpm_ip_protocol_e::IPV4 ? 0 : 1);
}

lpm_db::~lpm_db()
{
}

void
lpm_db::key_translate(const bit_vector& key, size_t length, lpm_key_t& out_lpm_key)
{
    // Accounting for prefix addition
    length += m_prefix_len;
    out_lpm_key = key.bits_from_msb(0, length);

    // Accounting for table type bit
    length += 1;
    out_lpm_key.resize(length);
    out_lpm_key.set_bit(length - 1, protocol_bit);
}

la_status
lpm_db::insert(const bit_vector& key, size_t length, const bit_vector& payload)
{
    lpm_key_t lpm_key;
    lpm_payload_t lpm_payload = payload.get_value();

    key_translate(key, length, lpm_key);

    log_debug(RA, "# action::lpm_insert %s %zd %u", lpm_key.to_string().c_str(), length, lpm_payload);

    la_status status = m_lpm->insert(lpm_key, lpm_payload);

    log_debug(RA, "# end action::lpm_insert %s %zd %u", lpm_key.to_string().c_str(), length, lpm_payload);

    return status;
}

la_status
lpm_db::update(const bit_vector& key, size_t length, const bit_vector& payload)
{
    lpm_key_t lpm_key;
    lpm_payload_t lpm_payload = payload.get_value();

    key_translate(key, length, lpm_key);

    log_debug(RA, "# action::lpm_update %s %zd %u", lpm_key.to_string().c_str(), length, lpm_payload);

    la_status status = m_lpm->modify(lpm_key, lpm_payload);

    log_debug(RA, "# end action::lpm_update %s %zd %u", lpm_key.to_string().c_str(), length, lpm_payload);

    return status;
}

la_status
lpm_db::erase(const bit_vector& key, size_t length)
{
    lpm_key_t lpm_key;

    key_translate(key, length, lpm_key);
    log_debug(RA, "# action::lpm_remove %s %zd", lpm_key.to_string().c_str(), length);

    la_status status = m_lpm->remove(lpm_key);

    log_debug(RA, "# end action::lpm_remove %s %zd", lpm_key.to_string().c_str(), length);

    return status;
}

la_status
lpm_db::bulk_updates(lpm_db_action_desc_vec_t& actions, size_t& out_count_success)
{
    log_debug(RA, "# action::lpm_bulk_updates: size %zu", actions.size());

    m_actions.resize(actions.size());

    for (size_t i = 0; i < actions.size(); i++) {
        m_actions[i].m_action = actions[i].action;

        if ((actions[i].action == lpm_action_e::INSERT) || (actions[i].action == lpm_action_e::MODIFY)) {
            m_actions[i].m_payload = actions[i].payload.get_value();
            m_actions[i].m_latency_sensitive = actions[i].latency_sensitive;
        }

        key_translate(actions[i].key, actions[i].length, m_actions[i].m_key);
    }

    la_status status = m_lpm->update(m_actions, out_count_success);

    if (status != LA_STATUS_SUCCESS) {
        log_err(RA,
                "# end action::lpm_bulk_updates:  size %zu, out_count_success %zu status %s",
                m_actions.size(),
                out_count_success,
                la_status2str(status).c_str());
    } else {
        log_debug(RA, "# end action::lpm_bulk_updates: size %zu out_count_success %zu", m_actions.size(), out_count_success);
        dassert_crit(m_actions.size() == out_count_success);
    }

    return status;
}

size_t
lpm_db::max_size() const
{
    return m_lpm->max_size();
}

size_t
lpm_db::get_physical_usage(size_t number_of_logical_entries_in_table) const
{
    return m_lpm->get_physical_usage(m_protocol, number_of_logical_entries_in_table);
}
size_t
lpm_db::get_available_entries() const
{
    return m_lpm->get_available_entries(m_protocol);
}

} // namespace silicon_one
