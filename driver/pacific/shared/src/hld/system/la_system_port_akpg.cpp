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

#include "la_system_port_akpg.h"
#include "nplapi/npl_constants.h"
#include "system/la_device_impl.h"
#include "system/la_mac_port_base.h"
#include "system/la_npu_host_port_base.h"
#include "system/la_pci_port_base.h"
#include "system/la_recycle_port_base.h"
#include "system/la_remote_port_impl.h"
#include "system/slice_id_manager_base.h"
#include "tm/la_interface_scheduler_impl.h"
#include "tm/la_unicast_tc_profile_impl.h"
#include "tm/la_voq_set_impl.h"

#include "hld_utils.h"
#include "npu/resolution_utils.h"
#include "tm/la_system_port_scheduler_impl.h"
#include "tm/tm_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_system_port_akpg::la_system_port_akpg(const la_device_impl_wptr& device) : la_system_port_base(device)
{
}

la_system_port_akpg::~la_system_port_akpg()
{
}

la_status
la_system_port_akpg::initialize_for_pci(la_object_id_t oid,
                                        const la_pci_port_wptr& pci_port,
                                        la_system_port_gid_t gid,
                                        const la_voq_set_wptr& voq_set,
                                        const la_tc_profile_wcptr& tc_profile)
{
    la_status status = pre_initialize(oid, pci_port, gid, voq_set);
    return_on_error(status);

    m_pci_port = pci_port.weak_ptr_static_cast<la_pci_port_base>();
    m_port_type = port_type_e::PCI;
    m_slice_id = m_pci_port->get_slice();
    m_ifg_id = m_pci_port->get_ifg();
    m_pif_base = PKTDMA_PIF_ID;
    m_pif_count = 1;
    m_intf_scheduler = m_device->get_sptr(m_pci_port->get_scheduler());

    // PACKET-DMA-WA
    m_punt_recycle_port = m_device->allocate_punt_recycle_port(m_device->get_sptr(this));
    if (m_punt_recycle_port == nullptr) {
        log_err(HLD, "PCI port requires a recycle port on the same slice pair. Recycle port was not found");
        return LA_STATUS_ENOTFOUND;
    }

    status = initialize_common_local(pci_port, voq_set, tc_profile);
    if (status != LA_STATUS_SUCCESS) {
        m_pci_port = nullptr;
        return status;
    }

    npl_initial_pd_nw_rx_data_t init_data;
    memset(&init_data, 0, sizeof(npl_initial_pd_nw_rx_data_t)); // Empty struct. We only need slice, ifg and pif.

    status = set_inject_up_entry(init_data);
    if (status != LA_STATUS_SUCCESS) {
        m_recycle_port = nullptr;
        return status;
    }

    m_device->add_object_dependency(m_punt_recycle_port, this);

    status = set_slice_rx_obm_code(); // PACKET-DMA-WA
    return_on_error(status);

    status = set_rx_obm_code_for_tests();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_akpg::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    la_status status = teardown_tm_tables();
    return_on_error(status);

    if (m_port_type != port_type_e::REMOTE) {
        status = destroy_common_local();
        return_on_error(status);
    }

    m_device->remove_object_dependency(m_voq_set, this);
    m_device->remove_object_dependency(m_tc_profile, this);

    if (m_mac_port != nullptr) {
        m_device->remove_object_dependency(m_mac_port, this);
        m_mac_port = nullptr;
    }

    if (m_recycle_port != nullptr) {
        m_device->remove_object_dependency(m_recycle_port, this);
        m_recycle_port = nullptr;
    }

    if (m_npu_host_port != nullptr) {
        // no object dependency in the case of npu_host_port
        m_npu_host_port = nullptr;
    }

    if (m_pci_port != nullptr) {
        status = erase_slice_rx_obm_code();
        return_on_error(status);

        status = erase_rx_obm_code_for_tests();
        return_on_error(status);

        m_device->remove_object_dependency(m_pci_port, this);
        m_device->remove_object_dependency(m_punt_recycle_port, this); // PACKET-DMA-WA
        m_pci_port = nullptr;

        m_device->release_punt_recycle_port(m_punt_recycle_port);
        m_punt_recycle_port = nullptr;
    }

    if (m_remote_port != nullptr) {
        m_device->remove_object_dependency(m_remote_port, this);
        m_remote_port = nullptr;
    }

    if (m_scheduler != nullptr) {
        m_device->do_destroy(m_scheduler);
        m_scheduler = nullptr;
    }

    if (m_pif_base == RECYCLE_SERDES_ID) { // PACKET-DMA-WA
        size_t ifg_idx = m_device->get_slice_id_manager()->slice_ifg_2_global_ifg(m_slice_id, m_ifg_id);
        m_device->m_per_ifg_recycle_sp[ifg_idx] = nullptr;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_akpg::set_inject_up_entry(npl_initial_pd_nw_rx_data_t initial_pd_nw_rx_data)
{
    npl_inject_up_ssp_init_data_table_key_t k1;
    npl_inject_up_ssp_init_data_table_t::entry_pointer_type e1 = nullptr;
    npl_inject_up_pif_ifg_init_data_table_key_t k2;
    npl_inject_up_pif_ifg_init_data_table_t::entry_pointer_type e2 = nullptr;

    k1.up_ssp = m_gid;
    npl_inject_up_ssp_init_data_table_value_t v1;
    v1.action = NPL_INJECT_UP_SSP_INIT_DATA_TABLE_ACTION_WRITE;
    v1.payloads.write_init_data_for_ssp.init_data = initial_pd_nw_rx_data;
    v1.payloads.write_init_data_for_ssp.init_data.init_data.initial_npp_attributes_index = m_npp_attributes_index;

    size_t table_instance = get_inject_up_table_instance_index();

    la_status status = m_device->m_tables.inject_up_ssp_init_data_table[table_instance]->set(k1, v1, e1);
    return_on_error(status);

    k2.initial_slice_id = m_slice_id;
    k2.source_if.ifg = get_physical_ifg(m_slice_id, m_ifg_id);
    k2.source_if.pif = m_pif_base;

    npl_inject_up_pif_ifg_init_data_table_value_t v2;
    v2.action = NPL_INJECT_UP_PIF_IFG_INIT_DATA_TABLE_ACTION_WRITE;
    v2.payloads.write_init_data_for_pif_ifg.init_data = initial_pd_nw_rx_data;
    v2.payloads.write_init_data_for_pif_ifg.slice_and_source_if.slice_id_on_npu = m_slice_id;
    v2.payloads.write_init_data_for_pif_ifg.slice_and_source_if.source_if_on_npu.ifg = get_physical_ifg(m_slice_id, m_ifg_id);
    v2.payloads.write_init_data_for_pif_ifg.slice_and_source_if.source_if_on_npu.pif = m_pif_base;
    v2.payloads.write_init_data_for_pif_ifg.init_data.init_data.initial_npp_attributes_index = m_npp_attributes_index;
    status = m_device->m_tables.inject_up_pif_ifg_init_data_table[table_instance]->set(k2, v2, e2);

    return status;
}

la_status
la_system_port_akpg::erase_inject_up_entry()
{
    npl_inject_up_ssp_init_data_table_key_t k1;
    k1.up_ssp = m_gid;

    size_t table_instance = get_inject_up_table_instance_index();

    la_status status = m_device->m_tables.inject_up_ssp_init_data_table[table_instance]->erase(k1);
    return_on_error(status);

    npl_inject_up_pif_ifg_init_data_table_key_t k2;
    k2.initial_slice_id = m_slice_id;
    k2.source_if.ifg = get_physical_ifg(m_slice_id, m_ifg_id);
    k2.source_if.pif = m_pif_base;

    status = m_device->m_tables.inject_up_pif_ifg_init_data_table[table_instance]->erase(k2);

    return status;
}

la_status
la_system_port_akpg::set_recycled_inject_up_entry()
{
    npl_recycled_inject_up_info_table_key_t k1;
    npl_recycled_inject_up_info_table_t::entry_pointer_type e1 = nullptr;

    k1.tx_to_rx_rcy_data = NPL_TX2RX_SCHED_RCY_DATA_RCY_PORT_TO_INJECT_UP & 0x3f;

    npl_recycled_inject_up_info_table_value_t v1;
    v1.action = NPL_RECYCLED_INJECT_UP_INFO_TABLE_ACTION_UPDATE_DATA;
    v1.payloads.update_data.init_data_selector = NPL_INIT_DATA_FROM_PIF_IFG;
    v1.payloads.update_data.ssp = 0;
    v1.payloads.update_data.phb.tc = 0;
    v1.payloads.update_data.phb.dp = 0;

    la_status status = m_device->m_tables.recycled_inject_up_info_table[m_slice_id]->set(k1, v1, e1);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_akpg::set_mtu(la_mtu_t mtu)
{
    bool instantiate_remotes = false;
    la_status status = m_device->get_bool_property(la_device_property_e::INSTANTIATE_REMOTE_SYSTEM_PORTS, instantiate_remotes);
    return_on_error(status);

    // Port can be remote in that case there is no mtu to apply locally.
    if (m_port_type == port_type_e::REMOTE && !instantiate_remotes) {
        return LA_STATUS_SUCCESS;
    }

    m_mtu = mtu;
    return set_slice_tx_dsp_attributes();
}

la_status
la_system_port_akpg::read_egress_congestion_watermark(la_traffic_class_t tc,
                                                      bool clear_on_read,
                                                      egress_max_congestion_watermark& out_cong_wm)
{
    start_api_getter_call("tc=", tc, "clear_on_read=", clear_on_read);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_system_port_akpg::read_egress_delay_watermark(la_traffic_class_t tc,
                                                 bool clear_on_read,
                                                 egress_max_delay_watermark& out_delay_wm)
{
    start_api_getter_call("tc=", tc, "clear_on_read=", clear_on_read);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_system_port_akpg::update_mtu_macro_trigger_threshold(la_mtu_t old_mtu, la_mtu_t mtu)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_system_port_akpg::set_source_pif_table(npl_ifg0_ssp_mapping_table_value_t value)
{
    npl_source_if_t source_if;
    source_if.ifg = get_physical_ifg(m_slice_id, m_ifg_id);
    source_if.pif = m_pif_base;

    value.payloads.init_rx_data.slice_source_system_port.value = source_if.pack().get_value();

    if (m_port_type == port_type_e::PCI) {
        value.payloads.init_rx_data.initial_rx_data.init_fields.init_data.initial_slice_id = m_slice_id;
        value.payloads.init_rx_data.initial_rx_data.init_fields.init_data.initial_npp_attributes_index = 0;
    } else {
        value.payloads.init_rx_data.initial_rx_data.init_fields.init_data.initial_slice_id = 0;
        value.payloads.init_rx_data.initial_rx_data.init_fields.init_data.initial_npp_attributes_index = m_npp_attributes_index;
    }

    la_uint_t num_of_entries = (m_port_extender_vid == NON_EXTENDED_PORT) ? m_pif_count : 1;
    for (la_uint_t pif_offset = 0; pif_offset < num_of_entries; pif_offset++) {
        la_status status = (m_port_extender_vid == NON_EXTENDED_PORT)
                               ? configure_pif_source_pif_table(value, m_pif_base + pif_offset)
                               : configure_port_extender_map_rx_data_table(value);

        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_akpg::configure_port_extender_map_rx_data_table(npl_ifg0_ssp_mapping_table_value_t value)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_system_port_akpg::erase_port_extender_map_rx_data_table()
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_system_port_akpg::populate_common_dsp_attributes(npl_dsp_attr_common_t& common_attributes)
{
    common_attributes = {0};
    common_attributes.dsp = get_gid();
    common_attributes.mask_egress_vlan_edit = m_mask_eve ? 1 : 0;
    common_attributes.dsp_map_info.dsp_is_scheduled_rcy = (m_port_type == port_type_e::RECYCLE) ? 1 : 0;
    // common_attributes.is_extnd_port = (m_port_extender_vid != NON_EXTENDED_PORT) ? 1 : 0;

    // If TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST is true, packets should be recycled and transmitted through the PCI port.
    bool test_mode_punt_to_egress = false;
    la_status status = is_test_mode_punt_to_egress(test_mode_punt_to_egress);
    return_on_error(status);

    common_attributes.dsp_map_info.dsp_punt_rcy
        = (m_port_type == port_type_e::RECYCLE || (test_mode_punt_to_egress && (m_port_type == port_type_e::MAC))) ? 1 : 0;
    common_attributes.dsp_is_dma = (m_port_type == port_type_e::PCI) ? 1 : 0;

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_akpg::fill_in_dsp_attr_key(npl_pif_ifg_base_t& omd_txpp, la_uint_t pif_offset)
{
    // matching pdoq_oq_ifc_mapping_result.txpp_map_data.parsed (only PIF/IFG are included).
    // as programmed in configure_pdoq_oq_ifc_mapping_network
    omd_txpp.pif = (m_pif_base + pif_offset);
    omd_txpp.ifg = m_ifg_id;
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_akpg::calculate_network_txpp(npl_dsp_l2_attributes_table_t::key_type& key, la_uint_t pif_offset)
{
    return fill_in_dsp_attr_key(key.omd_txpp, pif_offset);
}

la_status
la_system_port_akpg::calculate_network_txpp(npl_dsp_l3_attributes_table_t::key_type& key, la_uint_t pif_offset)
{
    return fill_in_dsp_attr_key(key.omd_txpp, pif_offset);
}

la_status
la_system_port_akpg::update_npp_sgt_attributes(la_sgt_t security_group_tag)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_akpg::update_dsp_sgt_attributes(bool security_group_policy_enforcement)
{
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
