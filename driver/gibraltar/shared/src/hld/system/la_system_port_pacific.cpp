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

#include "la_system_port_pacific.h"
#include "nplapi/npl_constants.h"
#include "system/la_device_impl.h"
#include "system/la_mac_port_pacific.h"
#include "system/la_npu_host_port_base.h"
#include "system/la_pci_port_base.h"
#include "system/la_recycle_port_base.h"
#include "system/la_remote_port_impl.h"
#include "system/slice_id_manager_base.h"
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
#include "lld/pacific_tree.h"

#include <sstream>

namespace silicon_one
{

la_system_port_pacific::la_system_port_pacific(const la_device_impl_wptr& device) : la_system_port_pacgb(device)
{
}

la_system_port_pacific::~la_system_port_pacific()
{
}

la_status
la_system_port_pacific::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    update_mtu_macro_trigger_threshold(m_mtu, LA_MTU_MAX);
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
        // PACKET-DMA-WA
        status = erase_slice_rx_obm_code();
        return_on_error(status);

        status = erase_rx_obm_code_for_tests();
        return_on_error(status);

        m_device->remove_object_dependency(m_pci_port, this);
        m_device->remove_object_dependency(m_punt_recycle_port, this); // PACKET-DMA-WA

        m_device->release_punt_recycle_port(m_punt_recycle_port);
        m_pci_port = nullptr;
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
la_system_port_pacific::set_inject_up_entry(npl_initial_pd_nw_rx_data_t initial_pd_nw_rx_data)
{
    npl_inject_up_ssp_init_data_table_key_t k1;
    npl_inject_up_ssp_init_data_table_t::entry_pointer_type e1 = nullptr;
    npl_inject_up_pif_ifg_init_data_table_key_t k2;
    npl_inject_up_pif_ifg_init_data_table_t::entry_pointer_type e2 = nullptr;

    k1.up_ssp = m_gid;
    npl_inject_up_ssp_init_data_table_value_t v1;
    v1.action = NPL_INJECT_UP_SSP_INIT_DATA_TABLE_ACTION_WRITE_INIT_DATA_FOR_SSP;
    v1.payloads.write_init_data_for_ssp.init_data = initial_pd_nw_rx_data;
    v1.payloads.write_init_data_for_ssp.init_data.init_data.initial_npp_attributes_index = m_npp_attributes_index;

    la_status status = m_device->m_tables.inject_up_ssp_init_data_table[m_slice_id]->set(k1, v1, e1);
    return_on_error(status);

    k2.initial_slice_id = m_slice_id;
    k2.source_if.ifg = get_physical_ifg(m_slice_id, m_ifg_id);
    k2.source_if.pif = m_pif_base;

    npl_inject_up_pif_ifg_init_data_table_value_t v2;
    v2.action = NPL_INJECT_UP_PIF_IFG_INIT_DATA_TABLE_ACTION_WRITE_INIT_DATA_FOR_PIF_IFG;
    v2.payloads.write_init_data_for_pif_ifg.init_data = initial_pd_nw_rx_data;
    v2.payloads.write_init_data_for_pif_ifg.slice_and_source_if.slice_id_on_npu = m_slice_id;
    v2.payloads.write_init_data_for_pif_ifg.slice_and_source_if.source_if_on_npu.ifg = get_physical_ifg(m_slice_id, m_ifg_id);
    v2.payloads.write_init_data_for_pif_ifg.slice_and_source_if.source_if_on_npu.pif = m_pif_base;
    v2.payloads.write_init_data_for_pif_ifg.init_data.init_data.initial_npp_attributes_index = m_npp_attributes_index;
    status = m_device->m_tables.inject_up_pif_ifg_init_data_table[m_slice_id]->set(k2, v2, e2);

    return status;
}

la_status
la_system_port_pacific::erase_inject_up_entry()
{
    npl_inject_up_ssp_init_data_table_key_t k1;
    k1.up_ssp = m_gid;

    la_status status = m_device->m_tables.inject_up_ssp_init_data_table[m_slice_id]->erase(k1);
    return_on_error(status);

    npl_inject_up_pif_ifg_init_data_table_key_t k2;
    k2.initial_slice_id = m_slice_id;
    k2.source_if.ifg = get_physical_ifg(m_slice_id, m_ifg_id);
    k2.source_if.pif = m_pif_base;

    status = m_device->m_tables.inject_up_pif_ifg_init_data_table[m_slice_id]->erase(k2);

    return status;
}

la_status
la_system_port_pacific::set_recycled_inject_up_entry()
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
la_system_port_pacific::set_mtu(la_mtu_t mtu)
{
    bool instantiate_remotes = false;
    la_status status = m_device->get_bool_property(la_device_property_e::INSTANTIATE_REMOTE_SYSTEM_PORTS, instantiate_remotes);
    return_on_error(status);

    bool svl_mode = false;
    status = m_device->get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);
    return_on_error(status);

    instantiate_remotes |= svl_mode;

    // Port can be remote in that case there is no mtu to apply locally.
    if (m_port_type == port_type_e::REMOTE && !instantiate_remotes) {
        return LA_STATUS_SUCCESS;
    }
    la_mtu_t old_mtu = m_mtu;
    m_mtu = mtu;
    status = set_slice_tx_dsp_attributes();
    return_on_error(status);
    return update_mtu_macro_trigger_threshold(old_mtu, mtu);
}

la_status
la_system_port_pacific::read_egress_congestion_watermark(la_traffic_class_t tc,
                                                         bool clear_on_read,
                                                         egress_max_congestion_watermark& out_cong_wm)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_system_port_pacific::read_egress_delay_watermark(la_traffic_class_t tc,
                                                    bool clear_on_read,
                                                    egress_max_delay_watermark& out_delay_wm)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_system_port_pacific::update_mtu_macro_trigger_threshold(la_mtu_t old_mtu, la_mtu_t mtu)
{
    // If old and new mtu are in the same range, we don't update tables.
    if ((mtu < (512 + 64)) && (old_mtu < (512 + 64))) {
        return LA_STATUS_SUCCESS;
    }

    if ((mtu >= (512 + 64)) && (mtu < (768 + 64)) && (old_mtu >= (512 + 64)) && (old_mtu < (768 + 64))) {
        return LA_STATUS_SUCCESS;
    }

    if ((mtu >= (768 + 64)) && (mtu < (1024 + 64)) && (old_mtu >= (768 + 64)) && (old_mtu < (1024 + 64))) {
        return LA_STATUS_SUCCESS;
    }

    if ((mtu >= (1024 + 64)) && (mtu < (1280 + 64)) && (old_mtu >= (1024 + 64)) && (old_mtu < (1280 + 64))) {
        return LA_STATUS_SUCCESS;
    }

    if ((mtu >= (1280 + 64)) && (old_mtu >= (1280 + 64))) {
        return LA_STATUS_SUCCESS;
    }

    la_mtu_t reference_mtu = mtu;
    la_mtu_t sibling_mtu = LA_MTU_MAX;
    const la_system_port* sibling_port = nullptr;
    la_status status = m_device->get_lowest_mtu_sibling_port_of_this_slice(static_cast<const la_system_port*>(this), sibling_port);
    return_on_error(status);
    if (sibling_port != nullptr) {
        sibling_mtu = (static_cast<const la_system_port_base*>(sibling_port))->get_mtu();
    }
    if (mtu < old_mtu) {
        if (sibling_mtu <= mtu) {
            return LA_STATUS_SUCCESS;
        } else {
            reference_mtu = mtu;
        }
    } else {
        if (sibling_mtu <= old_mtu) {
            return LA_STATUS_SUCCESS;
        } else {
            reference_mtu = std::min(sibling_mtu, mtu);
        }
    }

    npl_pad_mtu_inj_check_static_table_t::entry_pointer_type entry = nullptr;
    npl_pad_mtu_inj_check_static_table_t::key_type pad_mtu_inj_512_key;
    npl_pad_mtu_inj_check_static_table_t::key_type pad_mtu_inj_512_mask;
    npl_pad_mtu_inj_check_static_table_t::value_type pad_mtu_inj_512_value;
    pad_mtu_inj_512_key.tx_npu_header_is_inject_up.val = NPL_FALSE_VALUE;
    pad_mtu_inj_512_mask.tx_npu_header_is_inject_up.val = NPL_FALSE_VALUE;
    pad_mtu_inj_512_key.l3_tx_local_vars_fwd_pkt_size = 0;
    pad_mtu_inj_512_mask.l3_tx_local_vars_fwd_pkt_size = 0x3E00; /*match upto 511*/
    pad_mtu_inj_512_value.payloads.pad_mtu_inj_next_macro_action.pl_inc = NPL_PL_INC_NONE;
    pad_mtu_inj_512_value.payloads.pad_mtu_inj_next_macro_action.macro_id = NPL_NETWORK_TX_PAD_OR_MTU_MACRO;

    npl_pad_mtu_inj_check_static_table_t::key_type pad_mtu_inj_768_key;
    npl_pad_mtu_inj_check_static_table_t::key_type pad_mtu_inj_768_mask;
    npl_pad_mtu_inj_check_static_table_t::value_type pad_mtu_inj_768_value;
    pad_mtu_inj_768_key.tx_npu_header_is_inject_up.val = NPL_FALSE_VALUE;
    pad_mtu_inj_768_mask.tx_npu_header_is_inject_up.val = NPL_FALSE_VALUE;
    pad_mtu_inj_768_key.l3_tx_local_vars_fwd_pkt_size = 0;
    pad_mtu_inj_768_mask.l3_tx_local_vars_fwd_pkt_size = 0x3D00; /*match upto 767*/
    pad_mtu_inj_768_value.payloads.pad_mtu_inj_next_macro_action.pl_inc = NPL_PL_INC_NONE;
    pad_mtu_inj_768_value.payloads.pad_mtu_inj_next_macro_action.macro_id = NPL_NETWORK_TX_PAD_OR_MTU_MACRO;

    npl_pad_mtu_inj_check_static_table_t::key_type pad_mtu_inj_1024_key;
    npl_pad_mtu_inj_check_static_table_t::key_type pad_mtu_inj_1024_mask;
    npl_pad_mtu_inj_check_static_table_t::value_type pad_mtu_inj_1024_value;
    pad_mtu_inj_1024_key.tx_npu_header_is_inject_up.val = NPL_FALSE_VALUE;
    pad_mtu_inj_1024_mask.tx_npu_header_is_inject_up.val = NPL_FALSE_VALUE;
    pad_mtu_inj_1024_key.l3_tx_local_vars_fwd_pkt_size = 0;
    pad_mtu_inj_1024_mask.l3_tx_local_vars_fwd_pkt_size = 0x3C00; /*match upto 1023*/
    pad_mtu_inj_1024_value.payloads.pad_mtu_inj_next_macro_action.pl_inc = NPL_PL_INC_NONE;
    pad_mtu_inj_1024_value.payloads.pad_mtu_inj_next_macro_action.macro_id = NPL_NETWORK_TX_PAD_OR_MTU_MACRO;

    npl_pad_mtu_inj_check_static_table_t::key_type pad_mtu_inj_1280_key;
    npl_pad_mtu_inj_check_static_table_t::key_type pad_mtu_inj_1280_mask;
    npl_pad_mtu_inj_check_static_table_t::value_type pad_mtu_inj_1280_value;
    pad_mtu_inj_1280_key.tx_npu_header_is_inject_up.val = NPL_FALSE_VALUE;
    pad_mtu_inj_1280_mask.tx_npu_header_is_inject_up.val = NPL_FALSE_VALUE;
    pad_mtu_inj_1280_key.l3_tx_local_vars_fwd_pkt_size = 0;
    pad_mtu_inj_1280_mask.l3_tx_local_vars_fwd_pkt_size = 0x3B00; /*match upto 1279*/
    pad_mtu_inj_1280_value.payloads.pad_mtu_inj_next_macro_action.pl_inc = NPL_PL_INC_NONE;
    pad_mtu_inj_1280_value.payloads.pad_mtu_inj_next_macro_action.macro_id = NPL_NETWORK_TX_PAD_OR_MTU_MACRO;

    pad_mtu_inj_512_value.action = reference_mtu < (512 + 64)
                                       ? NPL_PAD_MTU_INJ_CHECK_STATIC_TABLE_ACTION_PAD_MTU_INJ_NEXT_MACRO_ACTION
                                       : NPL_PAD_MTU_INJ_CHECK_STATIC_TABLE_ACTION_DEFAULT_PAD_MTU_INJ_ACTION;
    pad_mtu_inj_768_value.action = reference_mtu < (768 + 64)
                                       ? NPL_PAD_MTU_INJ_CHECK_STATIC_TABLE_ACTION_PAD_MTU_INJ_NEXT_MACRO_ACTION
                                       : NPL_PAD_MTU_INJ_CHECK_STATIC_TABLE_ACTION_DEFAULT_PAD_MTU_INJ_ACTION;
    pad_mtu_inj_1024_value.action = reference_mtu < (1024 + 64)
                                        ? NPL_PAD_MTU_INJ_CHECK_STATIC_TABLE_ACTION_PAD_MTU_INJ_NEXT_MACRO_ACTION
                                        : NPL_PAD_MTU_INJ_CHECK_STATIC_TABLE_ACTION_DEFAULT_PAD_MTU_INJ_ACTION;
    pad_mtu_inj_1280_value.action = reference_mtu < (1280 + 64)
                                        ? NPL_PAD_MTU_INJ_CHECK_STATIC_TABLE_ACTION_PAD_MTU_INJ_NEXT_MACRO_ACTION
                                        : NPL_PAD_MTU_INJ_CHECK_STATIC_TABLE_ACTION_DEFAULT_PAD_MTU_INJ_ACTION;

    status = m_device->m_tables.pad_mtu_inj_check_static_table[m_slice_id]->set(
        2, pad_mtu_inj_512_key, pad_mtu_inj_512_mask, pad_mtu_inj_512_value, entry);
    return_on_error(status);

    status = m_device->m_tables.pad_mtu_inj_check_static_table[m_slice_id]->set(
        3, pad_mtu_inj_768_key, pad_mtu_inj_768_mask, pad_mtu_inj_768_value, entry);
    return_on_error(status);

    status = m_device->m_tables.pad_mtu_inj_check_static_table[m_slice_id]->set(
        4, pad_mtu_inj_1024_key, pad_mtu_inj_1024_mask, pad_mtu_inj_1024_value, entry);
    return_on_error(status);

    status = m_device->m_tables.pad_mtu_inj_check_static_table[m_slice_id]->set(
        5, pad_mtu_inj_1280_key, pad_mtu_inj_1280_mask, pad_mtu_inj_1280_value, entry);

    return status;
}

la_status
la_system_port_pacific::set_pfc(bool enable)
{
    npl_source_pif_hw_table_t::key_type key;
    npl_source_pif_hw_table_t::value_type value;
    npl_source_pif_hw_table_t::entry_pointer_type entry_ptr = nullptr;

    // Create the key
    key.rxpp_npu_input_ifg = get_physical_ifg(m_slice_id, m_ifg_id);
    key.rxpp_npu_input_ifg_rx_fd_source_pif = m_pif_base;

    la_status status = m_device->m_tables.source_pif_hw_table[m_slice_id]->lookup(key, entry_ptr);
    return_on_error(status);

    m_pfc_enabled = enable;
    value = entry_ptr->value();

    status = set_source_pif_table(value);
    return status;
}

la_status
la_system_port_pacific::set_tc_profile_core_ect(const la_tc_profile_wcptr& tc_profile)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_pacific::teardown_tm_tables_ect()
{
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_pacific::get_output_queue_size(la_oq_id_t oq_offset, size_t& out_size) const
{
    start_api_getter_call();

    if (oq_offset >= tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint_t oq_id = get_base_oq() + oq_offset;
    la_slice_id_t slice_id = get_slice();

    pdoq_enq_qsize_memory enq_qsize;
    la_status status
        = m_device->m_ll_device->read_memory(m_device->m_pacific_tree->slice[slice_id]->pdoq->top->enq_qsize, oq_id, enq_qsize);
    return_on_error(status);

    out_size = enq_qsize.fields.enq_qsize_data;

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_pacific::get_output_queue_fcn_enabled(la_oq_id_t oq_offset, bool& out_fcn_enabled) const
{
    start_api_getter_call();

    if (oq_offset >= tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint_t oq_id = get_base_oq() + oq_offset;
    la_slice_id_t slice_id = get_slice();

    pdoq_fcn_memory fcn{{0}};
    size_t line_num = oq_id / 16;
    la_status status = m_device->m_ll_device->read_memory(m_device->m_pacific_tree->slice[slice_id]->pdoq->top->fcn, line_num, fcn);
    return_on_error(status);

    size_t position = oq_id % 16;
    la_uint16_t fcn_data = fcn.fields.fcn_data;
    out_fcn_enabled = (fcn_data & (0x1 << position)) ? true : false;

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_pacific::populate_common_dsp_attributes(npl_dsp_attr_common_t& common_attributes)
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

la_uint8_t
la_system_port_pacific::fill_in_dsp_attr_key(la_uint_t pif_offset)
{
    // matching pdoq_oq_ifc_mapping_result.txpp_map_data.parsed (only PIF/IFG are included).
    // as programmed in configure_pdoq_oq_ifc_mapping_network
    return ((m_pif_base + pif_offset) << 1) | m_ifg_id;
}

la_status
la_system_port_pacific::calculate_network_txpp(npl_dsp_l2_attributes_table_t::key_type& key, la_uint_t pif_offset)
{
    key.omd_txpp = fill_in_dsp_attr_key(pif_offset);
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_pacific::calculate_network_txpp(npl_dsp_l3_attributes_table_t::key_type& key, la_uint_t pif_offset)
{
    key.omd_txpp = fill_in_dsp_attr_key(pif_offset);
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_pacific::update_npp_sgt_attributes(la_sgt_t security_group_tag)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_pacific::update_dsp_sgt_attributes(bool security_group_policy_enforcement)
{
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
