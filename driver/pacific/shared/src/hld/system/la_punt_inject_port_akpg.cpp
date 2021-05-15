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

#include "la_punt_inject_port_akpg.h"
#include "nplapi/npl_constants.h"
#include "system/la_device_impl.h"
#include "system/la_system_port_akpg.h"

#include "hld_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_punt_inject_port_akpg::la_punt_inject_port_akpg(const la_device_impl_wptr& device) : la_punt_inject_port_base(device)
{
}

la_punt_inject_port_akpg::~la_punt_inject_port_akpg()
{
}

la_status
la_punt_inject_port_akpg::set_slice_source_pif_entry(la_slice_id_t slice)
{
    // Update the system port with the NPP attributes index
    npl_ifg0_ssp_mapping_table_value_t v;

    v.action = NPL_IFG0_SSP_MAPPING_TABLE_ACTION_INIT_RX_DATA;

    // FI and NP macro are special inject macros. No tag swapping for now.
    v.payloads.init_rx_data.fi_macro_id = NPL_FI_MACRO_ID_ETH | FI_MACRO_RTC_STAGE;

    // np_macro_id is the in-engine, 6-bit ID and not the full 8-bit ID; truncate the MSB-s
    v.payloads.init_rx_data.np_macro_id = (NPL_RX_INJECT_MACRO & 0x3F);
    // v.payloads.init_rx_data.tag_swap_cmd = NPL_NO_TAG_SWAP;

    v.payloads.init_rx_data.initial_rx_data.init_fields.init_data.initial_npp_attributes_index = 0; // Not used
    v.payloads.init_rx_data.initial_rx_data.init_fields.init_data.initial_slice_id = 0;             // Not used
    v.payloads.init_rx_data.initial_rx_data.init_fields.initial_mapping_type = NPL_L2_VLAN_MAPPING;
    v.payloads.init_rx_data.initial_rx_data.init_fields.initial_mac_lp_type = NPL_LP_TYPE_LAYER_2;
    v.payloads.init_rx_data.initial_rx_data.init_fields.initial_vlan_profile = 0;
    // v.payloads.init_rx_Data.initial_rx_data.init_fields.initial_lp_type = NPL_L2_LP_TYPE_NPP;
    v.payloads.init_rx_data.initial_rx_data.init_fields.mapping_key.initial_lp_id.id = 0;
    v.payloads.init_rx_data.initial_rx_data.init_fields.mapping_key.mpls_label_placeholder = 0;
    v.payloads.init_rx_data.first_header_is_layer = 1;
    v.payloads.init_rx_data.first_header_type = NPL_PROTOCOL_TYPE_ETHERNET;

    if (m_system_port != nullptr) {
        auto system_port_akpg = m_system_port.weak_ptr_static_cast<la_system_port_akpg>();
        la_status status = system_port_akpg->set_source_pif_table(v);
        return status;
    }

    return LA_STATUS_EUNKNOWN;
}

la_status
la_punt_inject_port_akpg::handle_punt_inject_over_mac_at_init()
{
    la_system_port_base::port_type_e sys_port_type = m_system_port->get_port_type();

    if (sys_port_type == la_system_port_base::port_type_e::MAC) {
        m_system_recycle_port = m_device->allocate_punt_recycle_port(m_system_port);
        if (m_system_recycle_port == nullptr) {
            log_err(HLD, "Requires a recycle port. Recycle port was not found");
            return LA_STATUS_ENOTFOUND;
        }

        auto status = m_system_port->do_set_slice_rx_obm_code(m_system_recycle_port);
        m_device->add_object_dependency(m_system_recycle_port, this); // add obj dependency

        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_punt_inject_port_akpg::handle_punt_inject_over_mac_at_destroy()
{
    if (m_system_recycle_port != nullptr) {
        // erase from obm_code table
        auto status = m_system_port->do_erase_slice_rx_obm_code(m_system_recycle_port);
        return_on_error(status);

        m_device->release_punt_recycle_port(m_system_recycle_port);

        m_device->remove_object_dependency(m_system_recycle_port, this);
        m_system_recycle_port = nullptr;
    }

    return LA_STATUS_SUCCESS;
}

slice_ifg_vec_t
la_punt_inject_port_akpg::get_ifgs() const
{
    slice_ifg_vec_t slice_ifg_vec;

    auto actual_dsp = get_actual_dsp(m_system_port);
    la_slice_ifg sp_slice_ifg = {.slice = actual_dsp->get_slice(), .ifg = actual_dsp->get_ifg()};
    slice_ifg_vec.push_back(sp_slice_ifg);

    return slice_ifg_vec;
}

destination_id
la_punt_inject_port_akpg::get_destination_id(resolution_step_e prev_step) const
{
    if (m_system_port != nullptr) {
        return silicon_one::get_destination_id(m_system_port.get(), prev_step);
    } else {
        return DESTINATION_ID_INVALID;
    }
}

la_system_port_wcptr
la_punt_inject_port_akpg::get_actual_system_port() const
{
    return get_actual_dsp(m_system_port);
}

} // namespace silicon_one
