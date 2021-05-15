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

#include "system/la_l2_mirror_command_pacgb.h"
#include "qos/la_meter_set_statistical_impl.h"

namespace silicon_one
{

la_l2_mirror_command_pacgb::la_l2_mirror_command_pacgb(const la_device_impl_wptr& device) : la_l2_mirror_command_base(device)
{
}

la_l2_mirror_command_pacgb::~la_l2_mirror_command_pacgb()
{
}

la_status
la_l2_mirror_command_pacgb::configure_rx_obm_punt_src_and_code(uint64_t punt_source, la_voq_gid_t voq_id) const
{
    la_meter_set_exact_impl_wptr counter;
    if (m_meter != nullptr) {
        if (m_meter->get_type() == la_meter_set::type_e::STATISTICAL) {
            auto stat_meter = m_meter.weak_ptr_static_cast<const la_meter_set_statistical_impl>();
            counter = stat_meter->get_exact_meter_set_as_counter();
        }
    }

    return m_device->configure_rx_obm_punt_src_and_code(m_mirror_gid, punt_source, 0, 0, m_meter, counter, voq_id);
}

void
la_l2_mirror_command_pacgb::populate_rx_obm_code_table_key(la_uint_t mirror_gid, npl_rx_obm_code_table_key_t& out_key) const
{
    out_key.tx_to_rx_rcy_data.unscheduled_recycle_data = mirror_gid;
    // egress-mirroring -> unscheduled recycle
    out_key.tx_to_rx_rcy_data.unscheduled_recycle_code.unscheduled_recycle_code_lsb = 0x1;
    out_key.tx_to_rx_rcy_data.unscheduled_recycle_code.recycle_pkt = 0x1;
}

la_status
la_l2_mirror_command_pacgb::configure_mirror_to_dsp_in_npu_soft_header_table(uint8_t value)
{
    const auto& table(m_device->m_tables.mirror_to_dsp_in_npu_soft_header_table);
    npl_mirror_to_dsp_in_npu_soft_header_table_key_t k;
    npl_mirror_to_dsp_in_npu_soft_header_table_value_t v;
    npl_mirror_to_dsp_in_npu_soft_header_table_entry_t* entry = nullptr;

    k.mirror_code = m_mirror_gid;
    v.payloads.update_dsp_in_npu_soft_header = value;

    la_status status = table->set(k, v, entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_pacgb::teardown_mirror_to_dsp_in_npu_soft_header_table()
{
    const auto& table(m_device->m_tables.mirror_to_dsp_in_npu_soft_header_table);
    npl_mirror_to_dsp_in_npu_soft_header_table_key_t key;

    key.mirror_code = m_mirror_gid;

    la_status status = table->erase(key);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
