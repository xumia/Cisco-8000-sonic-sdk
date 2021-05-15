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

#include "system/la_l2_mirror_command_gibraltar.h"
#include "api_tracer.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "lld/device_reg_structs.h"
#include "lld/device_tree.h"
#include "lld/ll_device.h"
#include "npu/mc_copy_id_manager.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

la_l2_mirror_command_gibraltar::la_l2_mirror_command_gibraltar(const la_device_impl_wptr& device)
    : la_l2_mirror_command_pacgb(device)
{
}

la_l2_mirror_command_gibraltar::~la_l2_mirror_command_gibraltar()
{
}

la_status
la_l2_mirror_command_gibraltar::configure_redirect_code(uint64_t redirect_code,
                                                        npl_punt_nw_encap_type_e redirect_type,
                                                        la_uint_t encap_ptr)
{
    la_status status;

    {
        npl_tx_redirect_code_table_t::key_type tk;
        npl_tx_redirect_code_table_t::value_type tv;
        npl_tx_redirect_code_table_t::entry_pointer_type te = nullptr;

        tk.tx_redirect_code = NPL_REDIRECT_CODE_PFC_MEASUREMENT;
        tv.action = NPL_TX_REDIRECT_CODE_TABLE_ACTION_TX_REDIRECT_ACTION;
        tv.payloads.tx_redirect_action.cntr_stamp_cmd.offset = 0;
        tv.payloads.tx_redirect_action.tx_punt_nw_encap_ptr.punt_nw_encap_type = redirect_type;
        tv.payloads.tx_redirect_action.tx_punt_nw_encap_ptr.punt_nw_encap_ptr.ptr = encap_ptr;
        tv.payloads.tx_redirect_action.stamp_into_packet_header = NPL_STAMP_ON_PACKET_HEADER;
        tv.payloads.tx_redirect_action.ts_cmd.op = NPL_TS_CMD_STAMP_DEV_TIME;
        /*
         * We need to stamp a place in the original packet in a known place to calculate the latency.
         * Stamp the src mac which will be 40B (NPU header) + 6B DA MAC
         */
        tv.payloads.tx_redirect_action.ts_cmd.offset = la_device_impl::NPU_HEADER_SIZE + 6;

        status = m_device->m_tables.tx_redirect_code_table->lookup(tk, te);
        if (status == LA_STATUS_SUCCESS) {
            te->update(tv);
        } else {
            status = m_device->m_tables.tx_redirect_code_table->insert(tk, tv, te);
            return_on_error(status);
        }
    }

    {
        npl_punt_rcy_inject_header_ene_encap_table_t::key_type k{};
        npl_punt_rcy_inject_header_ene_encap_table_t::value_type v{};
        npl_punt_rcy_inject_header_ene_encap_table_t::entry_pointer_type e = nullptr;

        k.punt_nw_encap_ptr.ptr = encap_ptr;

        v.action = NPL_PUNT_RCY_INJECT_HEADER_ENE_ENCAP_TABLE_ACTION_FOUND;
        v.payloads.found.ene_inject_down_payload.ene_inject_destination.val = 0;
        v.payloads.found.ene_inject_down_payload.ene_inject_phb.tc = 0;
        v.payloads.found.ene_inject_down_payload.ene_inject_down_encap_type = NPL_INJECT_DOWN_ENCAP_TYPE_NONE;

        la_status status = m_device->m_tables.punt_rcy_inject_header_ene_encap_table->set(k, v, e);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_gibraltar::populate_punt_encap_data(la_uint_t mirror_gid,
                                                         npl_punt_encap_data_t& punt_encap_data,
                                                         la_uint_t encap_ptr) const
{
    auto& msb = punt_encap_data.punt_msb_encap.punt_encap_msb;

    if (m_stack_port != nullptr) {
        msb.npu_mirror_or_redirect_encapsulation_type = NPL_NPU_ENCAP_REMOTE_MIRROR;
    } else {
        msb.npu_mirror_or_redirect_encapsulation_type = NPL_NPU_ENCAP_MIRROR_OR_REDIRECT;
    }
    msb.lpts_tcam_first_result_encap_data_msb.ingress_punt_src = NPL_PUNT_SRC_INBOUND_MIRROR;
    msb.lpts_tcam_first_result_encap_data_msb.punt_sub_code.sub_code.lpts_flow_type.lpts_flow = 0;

    auto& lsb = punt_encap_data.punt_lsb_encap.punt_shared_lsb_encap;
    lsb.punt_encap_data_lsb.punt_controls.mirror_local_encap_format = 1;
    lsb.punt_encap_data_lsb.punt_nw_encap_ptr.ptr = encap_ptr;
    lsb.punt_encap_data_lsb.punt_nw_encap_type = m_encap_type;

    if (!m_is_mc_lpts) {
        msb.lpts_tcam_first_result_encap_data_msb.encap_punt_code.mirror_or_redirect_code = mirror_gid;
        lsb.punt_cud_type = NPL_PUNT_CUD_TYPE_IBM;
    } else {
        msb.lpts_tcam_first_result_encap_data_msb.encap_punt_code.mirror_or_redirect_code = NPL_REDIRECT_CODE_LPM_MC_LPTS;
        lsb.punt_cud_type = NPL_PUNT_CUD_TYPE_MC_LPTS;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_gibraltar::set_truncate(bool truncate)
{
    start_api_call("truncate=", truncate);

    pdoq_fdoq_partial_mirror_configuration_register reg{{0}};
    la_status status;

    auto& lld = m_device->m_ll_device;

    for (la_slice_id_t slice : m_device->get_used_slices()) {
        status = lld->read_register(m_device->m_gb_tree->slice[slice]->pdoq->fdoq->partial_mirror_configuration, reg);
        return_on_error(status);
        if (truncate) {
            reg.fields.partial_mirror = bit_utils::set_bit(reg.fields.partial_mirror, m_mirror_gid, true);
        } else {
            reg.fields.partial_mirror = bit_utils::set_bit(reg.fields.partial_mirror, m_mirror_gid, false);
        }

        status = lld->write_register(m_device->m_gb_tree->slice[slice]->pdoq->fdoq->partial_mirror_configuration, reg);
        return_on_error(status);
    }

    m_truncate = truncate;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_mirror_command_gibraltar::configure_cud_entry(la_uint_t mirror_hw_id, la_uint_t mirror_gid, la_uint_t encap_ptr)
{
    return configure_mc_cud_table_entry(mirror_hw_id, mirror_gid, encap_ptr);
}

la_status
la_l2_mirror_command_gibraltar::teardown_cud_entry(la_uint_t mirror_hw_id)
{
    return teardown_mc_cud_table_entry(mirror_hw_id);
}

la_status
la_l2_mirror_command_gibraltar::configure_mc_cud_table_entry(la_uint_t mirror_hw_id, la_uint_t mirror_gid, la_uint_t encap_ptr)
{
    npl_mc_cud_table_key_t k;
    npl_mc_cud_table_value_t v;

    k.cud_mapping_local_vars_exp_mc_copy_id_14_1_ = mc_copy_id_manager::get_mc_cud_table_key(mirror_hw_id);

    v.action = NPL_MC_CUD_TABLE_ACTION_UPDATE;
    v.payloads.update.mapped_cud_is_narrow = 0;
    npl_punt_encap_data_t& punt_encap_data = v.payloads.update.mapped_cud.mirror.mirror_cud_encap.punt_encap_data;
    la_status status = populate_punt_encap_data(mirror_gid, punt_encap_data, encap_ptr);
    return_on_error(status);

    const auto& tables(m_device->m_tables.mc_cud_table);
    status = per_slice_tables_insert(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);

    return status;
}

la_status
la_l2_mirror_command_gibraltar::teardown_mc_cud_table_entry(la_uint_t mirror_hw_id)
{
    npl_mc_cud_table_key_t k;
    k.cud_mapping_local_vars_exp_mc_copy_id_14_1_ = mc_copy_id_manager::get_mc_cud_table_key(mirror_hw_id);

    const auto& tables(m_device->m_tables.mc_cud_table);
    la_status status = per_slice_tables_erase(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k);

    return status;
}

la_status
la_l2_mirror_command_gibraltar::configure_recycle_override_entry(la_uint_t mirror_hw_id)
{
    return m_device->configure_recycle_override_network_slices_entry(1 /* key_recycle_code */,
                                                                     mirror_hw_id /* key_recycle_data */,
                                                                     0 /* key_sched_rcy */,
                                                                     true /* override_src */,
                                                                     NPL_OUTBOUND_MIRROR_RX_MACRO /* np_macro */,
                                                                     NPL_FI_MACRO_ID_ETH /* fi_macro */);
}

la_status
la_l2_mirror_command_gibraltar::remove_recycle_override_entry(la_uint_t mirror_hw_id)
{
    return m_device->remove_network_slices_entry_from_recycle_override_table(1, mirror_hw_id, 0);
}

la_status
la_l2_mirror_command_gibraltar::configure_stack_remote_mirror_destination_map(la_uint_t mirror_gid, npl_destination_t destination)
{
    npl_svl_mirror_cmd_remote_dsp_table_key_t k;
    npl_svl_mirror_cmd_remote_dsp_table_value_t v;

    k.ibm_cmd = mirror_gid;

    v.action = NPL_SVL_MIRROR_CMD_REMOTE_DSP_TABLE_ACTION_WRITE;
    v.payloads.svl_mirror_dsp.dsp = destination.val;

    const auto& tables(m_device->m_tables.svl_mirror_cmd_remote_dsp_table);
    la_status status
        = per_slice_tables_insert(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k, v);

    return status;
}

la_status
la_l2_mirror_command_gibraltar::teardown_stack_remote_mirror_destination_map(la_uint_t mirror_gid)
{
    npl_svl_mirror_cmd_remote_dsp_table_key_t k;
    npl_svl_mirror_cmd_remote_dsp_table_t::entry_pointer_type e;

    k.ibm_cmd = mirror_gid;

    const auto& tables(m_device->m_tables.svl_mirror_cmd_remote_dsp_table);
    auto sid = m_device->first_active_slice_id();
    la_status status = tables[sid]->lookup(k, e);
    if (status == LA_STATUS_ENOTFOUND) {
        return LA_STATUS_SUCCESS;
    }

    status = per_slice_tables_erase(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC}, k);

    return status;
}

} // namespace silicon_one
