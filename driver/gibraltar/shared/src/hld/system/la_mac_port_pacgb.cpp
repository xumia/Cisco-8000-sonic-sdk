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

#include "la_mac_port_pacgb.h"

#include "hld_utils.h"
#include "qos/la_meter_set_impl.h"
#include "system/ifg_handler.h"
#include "system/mac_pool8_port.h"
#include "tm/tm_utils.h"

#include "api_tracer.h"

namespace silicon_one
{

la_mac_port_pacgb::la_mac_port_pacgb(const la_device_impl_wptr& device) : la_mac_port_base(device)
{
}

la_mac_port_pacgb::~la_mac_port_pacgb()
{
}

la_status
la_mac_port_pacgb::configure_serdes_source_pif_table_extended_mac()
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_mac_port_pacgb::erase_serdes_source_pif_table_extended_mac()
{
    for (la_uint_t serdes_offset = 0; serdes_offset < m_serdes_count; serdes_offset++) {
        npl_source_pif_hw_table_key_t key;
        key.rxpp_npu_input_ifg = get_physical_ifg(m_slice_id, m_ifg_id);
        key.rxpp_npu_input_ifg_rx_fd_source_pif = m_serdes_base_id + serdes_offset;

        la_status status = m_device->m_tables.source_pif_hw_table[m_slice_id]->erase(key);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_pacgb::initialize_pif()
{
    m_pif_base_id = m_serdes_base_id;
    m_pif_count = m_serdes_count;
    return LA_STATUS_SUCCESS;
}
}
