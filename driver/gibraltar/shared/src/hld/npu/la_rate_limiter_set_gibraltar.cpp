// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "la_rate_limiter_set_gibraltar.h"
#include "api_tracer.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

la_rate_limiter_set_gibraltar::la_rate_limiter_set_gibraltar(la_device_impl_wptr device) : la_rate_limiter_set_base(device)
{
}

la_rate_limiter_set_gibraltar::~la_rate_limiter_set_gibraltar()
{
}

la_status
la_rate_limiter_set_gibraltar::get_pass_count(la_rate_limiters_packet_type_e packet_type,
                                              bool clear_on_read,
                                              size_t& out_packets,
                                              size_t& out_bytes) const
{
    la_slice_id_t slice_id = m_system_port->get_slice();
    la_ifg_id_t ifg_id = m_system_port->get_ifg();
    la_uint_t port_id = m_system_port->get_base_pif();

    la_uint_t table_index = (slice_id * NUM_IFGS_PER_SLICE) + ifg_id;
    la_uint_t table_entry_index = (port_id * (la_uint_t)la_rate_limiters_packet_type_e::LAST) + (la_uint_t)packet_type;

    gibraltar::rx_meter_port_counter_pair_table_memory entry = {{0}};

    auto m = (*m_device->m_gb_tree->rx_meter->top->port_counter_pair_table)[table_index];
    la_status status = m_device->m_ll_device->read_memory(m, table_entry_index, entry);
    return_on_error(status);

    out_packets = entry.fields.pass_pkt_count;
    out_bytes = entry.fields.pass_byte_count;

    return LA_STATUS_SUCCESS;
}

la_status
la_rate_limiter_set_gibraltar::get_drop_count(la_rate_limiters_packet_type_e packet_type,
                                              bool clear_on_read,
                                              size_t& out_packets,
                                              size_t& out_bytes) const
{
    la_slice_id_t slice_id = m_system_port->get_slice();
    la_ifg_id_t ifg_id = m_system_port->get_ifg();
    la_uint_t port_id = m_system_port->get_base_pif();

    la_uint_t table_index = (slice_id * NUM_IFGS_PER_SLICE) + ifg_id;
    la_uint_t table_entry_index = (port_id * (la_uint_t)la_rate_limiters_packet_type_e::LAST) + (la_uint_t)packet_type;

    gibraltar::rx_meter_port_counter_pair_table_memory entry = {{0}};

    auto m = (*m_device->m_gb_tree->rx_meter->top->port_counter_pair_table)[table_index];
    la_status status = m_device->m_ll_device->read_memory(m, table_entry_index, entry);
    return_on_error(status);

    out_packets = entry.fields.drop_pkt_count;
    out_bytes = entry.fields.drop_byte_count;

    return LA_STATUS_SUCCESS;
}
}
