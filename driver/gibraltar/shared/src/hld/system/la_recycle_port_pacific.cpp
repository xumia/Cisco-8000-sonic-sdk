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

#include "lld/pacific_tree.h"

#include "system/la_device_impl.h"
#include "system/la_pci_port_base.h"
#include "system/la_recycle_port_pacific.h"
#include "tm/la_ifg_scheduler_impl.h"
#include "tm/la_interface_scheduler_impl.h"

#include "hld_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"

namespace silicon_one
{

la_recycle_port_pacific::la_recycle_port_pacific(const la_device_impl_wptr& device) : la_recycle_port_base(device)
{
}

la_recycle_port_pacific::~la_recycle_port_pacific()
{
}

static la_pci_port_base_wcptr
get_pci_port_on_slice(const la_device_impl_wptr& device, la_slice_id_t slice)
{
    auto pci_ports = device->get_objects(la_object::object_type_e::PCI_PORT);
    for (const auto& pp : pci_ports) {
        auto ppb = device->get_sptr<const la_pci_port_base>(pp);
        auto pp_slice = ppb->get_slice();
        if (pp_slice == slice) {
            return ppb;
            break;
        }
    }

    return nullptr;
}

la_status
la_recycle_port_pacific::initialize(la_object_id_t oid, la_slice_id_t slice, la_ifg_id_t ifg)
{
    m_oid = oid;

    bool pacific_B0_changes_en;
    auto status = m_device->get_bool_property(la_device_property_e::ENABLE_PACIFIC_B0_IFG_CHANGES, pacific_B0_changes_en);
    return_on_error(status);

    // don't return error to allow sdk unit-testing to run on pacific A0
    bool allow_rcy_on_all_slices;
    status
        = m_device->get_bool_property(la_device_property_e::TEST_MODE_PACIFIC_A0_ALLOW_RCY_ON_ALL_SLICES, allow_rcy_on_all_slices);
    return_on_error(status);

    if ((m_device->m_pacific_tree->get_revision() == la_device_revision_e::PACIFIC_A0 || pacific_B0_changes_en == false)
        && ((slice & 1) == 0)) {
        auto pci_port_on_slice = get_pci_port_on_slice(m_device, slice);
        if (pci_port_on_slice != nullptr) {
            // PACKET-DMA-WA
            log_err(HLD,
                    "%s: PCI port %s already exist in this slice. RCY port cannot be created on same slice as PCI port.",
                    __func__,
                    pci_port_on_slice->to_string().c_str());

            if (!allow_rcy_on_all_slices) {
                return LA_STATUS_EINVAL;
            }
        }
    }

    if (((m_device->m_revision == la_device_revision_e::PACIFIC_A0) || (m_device->m_revision == la_device_revision_e::PACIFIC_B0))
        && (ifg != 0)) {
        // PACKET-DMA-WA
        log_err(HLD, "%s: RCY port can be created on IFG 0 only.", __func__);

        return LA_STATUS_EINVAL;
    }

    m_slice = slice;
    m_ifg = ifg;

    // Configure source PIF entries
    status = set_slice_source_pif_entry();
    return_on_error(status);

    la_uint_t intf_id;
    status = get_intf_id(intf_id);
    return_on_error(status);

    la_interface_scheduler_impl_sptr scheduler;
    status = m_device->create_interface_scheduler(m_slice, m_ifg, intf_id, m_speed, false /* is_fabric */, scheduler);
    return_on_error(status);
    m_scheduler = scheduler;

    status = m_device->m_ifg_schedulers[m_slice][m_ifg]->initialize_interface(intf_id, 1 /* m_pif_count */);
    return_on_error(status);

    status = m_scheduler->set_oqs_enabled(true /* enabled */);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_recycle_port_pacific::set_slice_source_pif_entry()
{
    // Update the system port with the NPP attributes index
    npl_source_pif_hw_table_t::value_type v;
    npl_source_pif_hw_table_t::key_type k;
    npl_source_pif_hw_table_t::entry_pointer_type e = nullptr;

    k.rxpp_npu_input_ifg = get_physical_ifg(m_slice, m_ifg);
    k.rxpp_npu_input_ifg_rx_fd_source_pif = RECYCLE_PIF_ID;

    v.action = NPL_SOURCE_PIF_HW_TABLE_ACTION_INIT_RX_DATA;

    // FI and NP macro are special inject macros. No tag swapping for now.
    v.payloads.init_rx_data.fi_macro_id = NPL_FI_MACRO_ID_ETH;
    // np_macro_id is the in-engine, 6-bit ID and not the full 8-bit ID; truncate the MSB-s
    v.payloads.init_rx_data.np_macro_id = (NPL_RX_INJECT_MACRO & 0x3F);
    v.payloads.init_rx_data.tag_swap_cmd = NPL_NO_TAG_SWAP;

    v.payloads.init_rx_data.initial_rx_data.init_fields.init_data.initial_npp_attributes_index = 0; // Not used
    v.payloads.init_rx_data.initial_rx_data.init_fields.init_data.initial_slice_id = m_slice;
    v.payloads.init_rx_data.initial_rx_data.init_fields.initial_mapping_type = NPL_L2_VLAN_MAPPING;
    v.payloads.init_rx_data.initial_rx_data.init_fields.initial_mac_lp_type = NPL_LP_TYPE_LAYER_2;
    v.payloads.init_rx_data.initial_rx_data.init_fields.initial_vlan_profile = 0;
    v.payloads.init_rx_data.initial_rx_data.init_fields.initial_lp_type = NPL_L2_LP_TYPE_NPP;
    v.payloads.init_rx_data.initial_rx_data.init_fields.mapping_key.initial_lp_id.id = 0;
    v.payloads.init_rx_data.initial_rx_data.init_fields.mapping_key.mpls_label_placeholder = 0;

    la_status status = m_device->m_tables.source_pif_hw_table[m_slice]->lookup(k, e);
    if (status == LA_STATUS_SUCCESS) {
        status = e->update(v);
    } else {
        status = m_device->m_tables.source_pif_hw_table[m_slice]->insert(k, v, e);
    }

    return status;
}

la_status
la_recycle_port_pacific::erase_slice_source_pif_entry()
{
    npl_source_pif_hw_table_t::key_type key;
    key.rxpp_npu_input_ifg = get_physical_ifg(m_slice, m_ifg);
    key.rxpp_npu_input_ifg_rx_fd_source_pif = RECYCLE_PIF_ID;

    la_status status = m_device->m_tables.source_pif_hw_table[m_slice]->erase(key);

    return status;
}
}
