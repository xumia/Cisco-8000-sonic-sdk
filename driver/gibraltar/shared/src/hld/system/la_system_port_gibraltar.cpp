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

#include "la_system_port_gibraltar.h"
#include "lld/gibraltar_tree.h"
#include "nplapi/npl_constants.h"
#include "system/la_device_impl.h"
#include "system/la_mac_port_gibraltar.h"
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

#include <sstream>

namespace silicon_one
{

la_system_port_gibraltar::la_system_port_gibraltar(const la_device_impl_wptr& device) : la_system_port_pacgb(device)
{
}

la_system_port_gibraltar::~la_system_port_gibraltar()
{
}

la_status
la_system_port_gibraltar::destroy()
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
    if (m_ect_voq_set != nullptr) {
        m_device->remove_object_dependency(m_ect_voq_set, this);
        m_ect_voq_set = nullptr;
    }
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
la_system_port_gibraltar::set_inject_up_entry(npl_initial_pd_nw_rx_data_t initial_pd_nw_rx_data)
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

    la_status status = m_device->m_tables.inject_up_ssp_init_data_table[m_slice_id / 2]->set(k1, v1, e1);
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
    status = m_device->m_tables.inject_up_pif_ifg_init_data_table[m_slice_id / 2]->set(k2, v2, e2);

    return status;
}

la_status
la_system_port_gibraltar::erase_inject_up_entry()
{
    npl_inject_up_ssp_init_data_table_key_t k1;
    k1.up_ssp = m_gid;

    la_status status = m_device->m_tables.inject_up_ssp_init_data_table[m_slice_id / 2]->erase(k1);
    return_on_error(status);

    npl_inject_up_pif_ifg_init_data_table_key_t k2;
    k2.initial_slice_id = m_slice_id;
    k2.source_if.ifg = get_physical_ifg(m_slice_id, m_ifg_id);
    k2.source_if.pif = m_pif_base;

    status = m_device->m_tables.inject_up_pif_ifg_init_data_table[m_slice_id / 2]->erase(k2);

    return status;
}

la_status
la_system_port_gibraltar::set_recycled_inject_up_entry()
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
la_system_port_gibraltar::set_tc_profile_core_ect(const la_tc_profile_wcptr& tc_profile)
{
    if (tc_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    bool ecn_queuing_enabled = false;
    la_status status = m_device->get_bool_property(la_device_property_e::ENABLE_ECN_QUEUING, ecn_queuing_enabled);
    return_on_error(status);

    // Map the DSP to VOQ
    const auto& table(m_device->m_tables.rxpdr_dsp_lookup_table);
    const auto& tc_profile_impl = tc_profile.weak_ptr_static_cast<const la_tc_profile_impl>();
    npl_rxpdr_dsp_lookup_table_key_t ect_key;
    npl_rxpdr_dsp_lookup_table_value_t ect_value;
    npl_rxpdr_dsp_lookup_table_entry_t* ect_entry = nullptr;

    ect_key.fwd_destination_lsb = ECN_EXTENDED_SYSTEM_PORT_RANGE | m_gid;
    ect_value.payloads.rxpdr_dsp_lookup_table_result.tc_map_profile = tc_profile_impl->get_id();
    ect_value.payloads.rxpdr_dsp_lookup_table_result.dest_device = 0; // This has meaning only for FLB - currenly unused.

    if (ecn_queuing_enabled && (m_ect_voq_set != nullptr)) {
        ect_value.payloads.rxpdr_dsp_lookup_table_result.base_voq_num = m_ect_voq_set->get_base_voq_id();
    } else if (ecn_queuing_enabled) {
        // m_ect_voq_set is not configured and the ECN extended system port
        // range needs to be configured for the regular VoQ
        ect_value.payloads.rxpdr_dsp_lookup_table_result.base_voq_num = m_voq_set->get_base_voq_id();
    }

    status = table->set(ect_key, ect_value, ect_entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_gibraltar::teardown_tm_tables_ect()
{
    bool ecn_queuing_enabled = false;
    la_status status = m_device->get_bool_property(la_device_property_e::ENABLE_ECN_QUEUING, ecn_queuing_enabled);
    return_on_error(status);

    if (!ecn_queuing_enabled) {
        return LA_STATUS_SUCCESS;
    }

    const auto& rxpdr_dsp_lookup_table(m_device->m_tables.rxpdr_dsp_lookup_table);
    npl_rxpdr_dsp_lookup_table_key_t ect_key;
    ect_key.fwd_destination_lsb = ECN_EXTENDED_SYSTEM_PORT_RANGE | m_gid;

    status = rxpdr_dsp_lookup_table->erase(ect_key);
    return_on_error(status);

    if (m_ect_voq_set != nullptr) {
        // Clean VOQ->device/slice/OQ table
        for (la_slice_id_t slice_id : m_device->get_used_slices()) {
            if (!m_device->is_network_slice(slice_id)) {
                continue;
            }

            const auto& filb_voq_mapping_table(m_device->m_tables.filb_voq_mapping[slice_id]);
            npl_filb_voq_mapping_t::key_type key;

            for (size_t voq_offset = 0; voq_offset < m_ect_voq_set->get_set_size(); voq_offset++) {
                key.rxpdr_output_voq_nr = m_ect_voq_set->get_base_voq_id() + voq_offset;

                status = filb_voq_mapping_table->erase(key);
                return_on_error(status);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_gibraltar::set_mtu(la_mtu_t mtu)
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
la_system_port_gibraltar::update_mtu_macro_trigger_threshold(la_mtu_t old_mtu, la_mtu_t mtu)
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
la_system_port_gibraltar::get_output_queue_size(la_oq_id_t oq_offset, size_t& out_size) const
{
    start_api_getter_call();

    if (oq_offset >= tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint_t oq_id = get_base_oq() + oq_offset;
    la_slice_id_t slice_id = get_slice();

    gibraltar::pdoq_enq_qsize_memory enq_qsize;
    la_status status
        = m_device->m_ll_device->read_memory(m_device->m_gb_tree->slice[slice_id]->pdoq->top->enq_qsize, oq_id, enq_qsize);
    return_on_error(status);

    out_size = enq_qsize.fields.enq_qsize_data;

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_gibraltar::get_output_queue_fcn_enabled(la_oq_id_t oq_offset, bool& out_fcn_enabled) const
{
    start_api_getter_call();

    if (oq_offset >= tm_utils::NUM_OQS_PER_SYSTEM_PORT_SCH) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_uint_t oq_id = get_base_oq() + oq_offset;
    la_slice_id_t slice_id = get_slice();

    gibraltar::pdoq_fcn_memory fcn = {{0}};
    size_t line_num = oq_id / 16;
    la_status status = m_device->m_ll_device->read_memory(m_device->m_gb_tree->slice[slice_id]->pdoq->top->fcn, line_num, fcn);
    return_on_error(status);

    size_t position = oq_id % 16;
    la_uint16_t fcn_data = fcn.fields.fcn_data;
    out_fcn_enabled = (fcn_data & (0x1 << position)) ? true : false;

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_gibraltar::populate_common_dsp_attributes(npl_dsp_attr_common_t& common_attributes)
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

    common_attributes.svl_vpc_prune_port = m_stack_prune;
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_gibraltar::get_delay_measurement_mapped_tc(la_traffic_class_t tc, la_traffic_class_t& out_mapped_tc)
{
    gibraltar::txpp_delay_measurement_cmd_memory mem;
    la_ifg_id_t ifg = get_physical_ifg(m_slice_id, m_ifg_id);

    uint64_t line = ifg * NUM_OQ_PER_IFG + m_pif_base * NUM_OQ_PER_PIF + tc;

    la_status status = m_device->m_ll_device->read_memory(
        m_device->m_gb_tree->slice[m_slice_id]->npu->txpp->top->delay_measurement_cmd, line, mem);
    return_on_error(status);

    out_mapped_tc = mem.fields.mapped_traffic_class;

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_gibraltar::do_read_egress_delay_and_cong_memory(la_traffic_class_t tc,
                                                               gibraltar::txpp_tod_port_max_delay_and_cong_memory& out_mem)
{
    la_ifg_id_t ifg = get_physical_ifg(m_slice_id, m_ifg_id);
    uint64_t pif = m_pif_base;
    la_uint8_t mapped_tc;
    la_status status = get_delay_measurement_mapped_tc(tc, mapped_tc);
    return_on_error(status);

    uint64_t line = ifg * NUM_OQ_PER_IFG + pif * NUM_OQ_PER_PIF + mapped_tc;

    status = m_device->m_ll_device->read_memory(
        m_device->m_gb_tree->slice[m_slice_id]->npu->txpp->top->tod_port_max_delay_and_cong, line, out_mem);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_gibraltar::do_write_egress_delay_and_cong_memory(la_traffic_class_t tc,
                                                                gibraltar::txpp_tod_port_max_delay_and_cong_memory& mem)
{
    la_ifg_id_t ifg = get_physical_ifg(m_slice_id, m_ifg_id);
    uint64_t pif = m_pif_base;
    la_uint8_t mapped_tc;
    la_status status = get_delay_measurement_mapped_tc(tc, mapped_tc);
    return_on_error(status);

    uint64_t line = ifg * NUM_OQ_PER_IFG + pif * NUM_OQ_PER_PIF + mapped_tc;

    status = m_device->m_ll_device->write_memory(
        m_device->m_gb_tree->slice[m_slice_id]->npu->txpp->top->tod_port_max_delay_and_cong, line, mem);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_gibraltar::read_egress_congestion_watermark(la_traffic_class_t tc,
                                                           bool clear_on_read,
                                                           egress_max_congestion_watermark& out_cong_wm)
{
    start_api_getter_call("tc=", tc, "clear_on_read=", clear_on_read);

    // Validate tc.
    if (tc >= NUM_TC_CLASSES) {
        return LA_STATUS_EINVAL;
    }

    gibraltar::txpp_tod_port_max_delay_and_cong_memory mem;

    la_status status = do_read_egress_delay_and_cong_memory(tc, mem);
    return_on_error(status);

    out_cong_wm.max_congestion_level = mem.fields.max_cong_congestion_level;

    // Delay in memory is 9 bits and is stored as {5b offset, value}.
    // Actual delay value in nano seconds is {1b1, value[3:0]} << offset[4:0] - 4.
    out_cong_wm.delay = 0;
    if (mem.fields.max_cong_quantized_delay) {
        size_t offset = mem.fields.max_cong_quantized_delay >> 4;
        size_t value = mem.fields.max_cong_quantized_delay & 0xf;
        out_cong_wm.delay = (0x10 | value) << (offset - 4);
    }

    if (clear_on_read) {
        // Clear max_cong watermark fields.
        mem.fields.max_cong_congestion_level = 0;
        mem.fields.max_cong_ssp = 0;
        mem.fields.max_cong_quantized_delay = 0;
        status = do_write_egress_delay_and_cong_memory(tc, mem);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_gibraltar::read_egress_delay_watermark(la_traffic_class_t tc,
                                                      bool clear_on_read,
                                                      egress_max_delay_watermark& out_delay_wm)
{
    start_api_getter_call("tc=", tc, "clear_on_read=", clear_on_read);

    // Validate tc.
    if (tc >= NUM_TC_CLASSES) {
        return LA_STATUS_EINVAL;
    }

    gibraltar::txpp_tod_port_max_delay_and_cong_memory mem;

    la_status status = do_read_egress_delay_and_cong_memory(tc, mem);
    return_on_error(status);

    // Delay in memory is 9 bits and is stored as {5b offset, value}.
    // Actual delay value in nano seconds is {1b1, value[3:0]} << offset[4:0] - 4.
    out_delay_wm.max_delay = 0;
    if (mem.fields.max_delay_quantized_delay) {
        size_t offset = mem.fields.max_delay_quantized_delay >> 4;
        size_t value = mem.fields.max_delay_quantized_delay & 0xf;
        out_delay_wm.max_delay = (0x10 | value) << (offset - 4);
    }
    out_delay_wm.congestion_level = mem.fields.max_delay_congestion_level;

    if (clear_on_read) {
        // Clear max_delay watermark fields.
        mem.fields.max_delay_congestion_level = 0;
        mem.fields.max_delay_ssp = 0;
        mem.fields.max_delay_quantized_delay = 0;
        status = do_write_egress_delay_and_cong_memory(tc, mem);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_gibraltar::fill_in_dsp_attr_key(npl_pif_ifg_base_t& omd_txpp, la_uint_t pif_offset)
{
    // matching pdoq_oq_ifc_mapping_result.txpp_map_data.parsed (only PIF/IFG are included).
    // as programmed in configure_pdoq_oq_ifc_mapping_network
    omd_txpp.pif = (m_pif_base + pif_offset);
    omd_txpp.ifg = m_ifg_id;
    return LA_STATUS_SUCCESS;
}

la_status
la_system_port_gibraltar::calculate_network_txpp(npl_dsp_l2_attributes_table_t::key_type& key, la_uint_t pif_offset)
{
    return fill_in_dsp_attr_key(key.omd_txpp, pif_offset);
}

la_status
la_system_port_gibraltar::calculate_network_txpp(npl_dsp_l3_attributes_table_t::key_type& key, la_uint_t pif_offset)
{
    return fill_in_dsp_attr_key(key.omd_txpp, pif_offset);
}

la_status
la_system_port_gibraltar::update_npp_sgt_attributes(la_sgt_t security_group_tag)
{
    la_status status = LA_STATUS_SUCCESS;

    npl_npp_sgt_attributes_table_t::key_type key;
    npl_npp_sgt_attributes_table_t::value_type value;
    npl_npp_sgt_attributes_table_t::entry_pointer_type entry = nullptr;

    value.action = NPL_NPP_SGT_ATTRIBUTES_TABLE_ACTION_WRITE;
    value.payloads.npp_sgt_attributes.security_group = security_group_tag;

    la_system_port_base::port_type_e sys_port_type = get_port_type();
    if (sys_port_type != la_system_port_base::port_type_e::REMOTE) {
        // Create the key
        key.npp_attributes_index = get_npp_attributes_index();

        // Update NPP SGT attributes table
        auto slice_id = get_slice();
        status = m_device->m_tables.npp_sgt_attributes_table[slice_id]->set(key, value, entry);
        return_on_error(status);
    }

    return status;
}

la_status
la_system_port_gibraltar::update_dsp_sgt_attributes(bool security_group_policy_enforcement)
{
    la_status status = LA_STATUS_SUCCESS;

    npl_dsp_group_policy_table_t::key_type key;
    npl_dsp_group_policy_table_t::value_type value;
    npl_dsp_group_policy_table_t::entry_pointer_type entry = nullptr;

    value.action = NPL_DSP_GROUP_POLICY_TABLE_ACTION_WRITE;
    value.payloads.dsp_group_policy.enable = security_group_policy_enforcement;

    la_system_port_base::port_type_e sys_port_type = get_port_type();
    if (sys_port_type != la_system_port_base::port_type_e::REMOTE) {
        // Create the key
        key.dsp_index = get_gid();

        // Update Security Group Policy Enforcement table
        status = m_device->m_tables.dsp_group_policy_table->set(key, value, entry);
        return_on_error(status);
    }

    return status;
}

} // namespace silicon_one
