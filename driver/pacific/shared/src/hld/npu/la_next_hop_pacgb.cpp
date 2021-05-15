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

#include "la_next_hop_pacgb.h"
#include "api/npu/la_l3_port.h"
#include "nplapi/npl_constants.h"
#include "nplapi/nplapi_tables.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_l3_fec_impl.h"
#include "npu/la_next_hop_impl_common.h"
#include "npu/la_svi_port_base.h"
#include "npu/resolution_utils.h"
#include "system/la_device_impl.h"
#include "system/la_spa_port_base.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_next_hop_pacgb::la_next_hop_pacgb(const la_device_impl_wptr& device) : la_next_hop_base(device)
{
}

la_next_hop_pacgb::~la_next_hop_pacgb() = default;

la_status
la_next_hop_pacgb::configure_global_tx_tables()
{
    for (la_slice_pair_id_t slice_pair : m_device->get_used_slice_pairs()) {
        la_status status = do_configure_global_tx_tables(slice_pair);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_pacgb::do_configure_global_tx_tables(la_slice_pair_id_t slice_pair)
{
    if (m_gid < la_device_impl::EGRESS_DIRECT0_TABLE_SIZE) {
        const auto& table(m_device->m_tables.egress_nh_and_svi_direct0_table[slice_pair]);
        npl_egress_nh_and_svi_direct0_table_key_t key;
        npl_egress_nh_and_svi_direct0_table_value_t value;
        npl_egress_nh_and_svi_direct0_table_entry_wptr_t entry;

        key.egress_direct0_key.direct0_key = m_gid;
        la_status status = populate_nh_and_svi_payload(value.payloads.nh_and_svi_payload, slice_pair);
        return_on_error(status);

        status = table->insert(key, value, entry);
        return_on_error(status);

        m_nh_direct0_entry[slice_pair] = entry;
    } else {
        const auto& table(m_device->m_tables.egress_nh_and_svi_direct1_table[slice_pair]);
        npl_egress_nh_and_svi_direct1_table_key_t key;
        npl_egress_nh_and_svi_direct1_table_value_t value;
        npl_egress_nh_and_svi_direct1_table_entry_wptr_t entry;

        key.egress_direct1_key.direct1_key = m_gid;
        la_status status = populate_nh_and_svi_payload(value.payloads.nh_and_svi_payload, slice_pair);
        return_on_error(status);

        status = table->insert(key, value, entry);
        return_on_error(status);

        m_nh_direct1_entry[slice_pair] = entry;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_pacgb::update_global_tx_tables()
{
    for (la_slice_pair_id_t slice_pair : m_device->get_used_slice_pairs()) {
        la_status status = do_update_global_tx_tables(slice_pair);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_pacgb::do_update_global_tx_tables(la_slice_pair_id_t slice_pair)
{
    if (m_gid < la_device_impl::EGRESS_DIRECT0_TABLE_SIZE) {
        npl_egress_nh_and_svi_direct0_table_value_t value;

        la_status status = populate_nh_and_svi_payload(value.payloads.nh_and_svi_payload, slice_pair);
        return_on_error(status);

        status = m_nh_direct0_entry[slice_pair]->update(value);
        return_on_error(status);
    } else {
        npl_egress_nh_and_svi_direct1_table_value_t value;

        la_status status = populate_nh_and_svi_payload(value.payloads.nh_and_svi_payload, slice_pair);
        return_on_error(status);

        status = m_nh_direct1_entry[slice_pair]->update(value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_pacgb::teardown_global_tx_tables()
{
    for (la_slice_pair_id_t slice_pair : m_device->get_used_slice_pairs()) {
        do_teardown_global_tx_tables(slice_pair);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_next_hop_pacgb::do_teardown_global_tx_tables(la_slice_pair_id_t slice_pair)
{
    if (m_gid < la_device_impl::EGRESS_DIRECT0_TABLE_SIZE) {
        const auto& table(m_device->m_tables.egress_nh_and_svi_direct0_table[slice_pair]);

        la_status status = table->erase(m_nh_direct0_entry[slice_pair]->key());
        return_on_error(status);
        m_nh_direct0_entry[slice_pair] = nullptr;
    } else {
        const auto& table(m_device->m_tables.egress_nh_and_svi_direct1_table[slice_pair]);

        la_status status = table->erase(m_nh_direct1_entry[slice_pair]->key());
        return_on_error(status);
        m_nh_direct1_entry[slice_pair] = nullptr;
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
