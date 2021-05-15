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

#include "la_mac_port_plgr.h"

#include "hld_utils.h"
#include "qos/la_meter_set_impl.h"
#include "system/ifg_handler.h"
#include "tm/tm_utils.h"

#include "api_tracer.h"

namespace silicon_one
{

la_mac_port_plgr::la_mac_port_plgr(const la_device_impl_wptr& device) : la_mac_port_akpg(device)
{
}

la_mac_port_plgr::~la_mac_port_plgr()
{
}

la_status
la_mac_port_plgr::update_pdoq_oq_ifc_mapping()
{
    // update_pdoq table relies on a preconfiguration done by la_device_impl::configure_pdoq_oq_ifc_mapping_network
    for (la_uint_t pif_offset = 0; pif_offset < m_pif_count; pif_offset++) {
        la_uint_t oq_base = m_ifg_id * NUM_OQ_PER_IFG + (m_pif_base_id + pif_offset) * NUM_OQ_PER_PIF;
        for (la_uint_t oq_offset = 0; oq_offset < NUM_OQ_PER_PIF; oq_offset++) {
            const auto& table(m_device->m_tables.pdoq_oq_ifc_mapping[m_slice_id]);
            npl_pdoq_oq_ifc_mapping_key_t key;
            npl_pdoq_oq_ifc_mapping_value_t value;
            npl_pdoq_oq_ifc_mapping_entry_t* entry = nullptr;

            key.dest_oq = oq_base + oq_offset;
            la_status status = table->lookup(key, entry);
            return_on_error(status);
            value = entry->value();

            // For Non extended PIF the oq_pair field is always 0, meaning all 8 OQ are used
            value.payloads.pdoq_oq_ifc_mapping_result.txpp_map_data.parsed.oq_pair
                = (m_is_extended) ? oq_offset / NUM_OQ_PER_EXTENDED_PORT : 0;

            status = entry->update(value);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_mac_port_plgr::erase_serdes_source_pif_table_extended_mac()
{
    la_status status;

    for (la_uint_t pif_offset = 0; pif_offset < m_pif_count; pif_offset++) {
        for (int i = 0; i < NUM_PCH_SUB_PORT_PER_PIF; i++) {
            if (!get_physical_ifg(m_slice_id, m_ifg_id)) {
                npl_ifg0_ssp_mapping_table_key_t key;
                key.rx_pd_init_local_vars_sub_port_index = i;
                key.rxpp_npu_input_ifg_rx_fd_source_pif = m_pif_base_id + pif_offset;
                status = m_device->m_tables.ifg0_ssp_mapping_table[m_slice_id]->erase(key);
            } else {
                npl_ifg1_ssp_mapping_table_key_t key;
                key.rx_pd_init_local_vars_sub_port_index = i;
                key.rxpp_npu_input_ifg_rx_fd_source_pif = m_pif_base_id + pif_offset;
                status = m_device->m_tables.ifg1_ssp_mapping_table[m_slice_id]->erase(key);
            }
        }
    }

    return status;
}
}
