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

#include "system/la_erspan_mirror_command_pacific.h"
#include "api_tracer.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "lld/device_reg_structs.h"
#include "lld/device_tree.h"
#include "lld/ll_device.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

la_erspan_mirror_command_pacific::la_erspan_mirror_command_pacific(const la_device_impl_wptr& device)
    : la_erspan_mirror_command_base(device)
{
}

la_erspan_mirror_command_pacific::~la_erspan_mirror_command_pacific()
{
}

la_status
la_erspan_mirror_command_pacific::populate_punt_encap_data(la_uint_t mirror_code,
                                                           npl_punt_encap_data_t& punt_encap_data,
                                                           la_uint_t encap_ptr) const
{
    punt_encap_data.punt_msb_encap.punt_encap_msb.npu_mirror_or_redirect_encapsulation_type = NPL_NPU_ENCAP_MIRROR_OR_REDIRECT;
    punt_encap_data.punt_msb_encap.punt_encap_msb.lpts_tcam_first_result_encap_data_msb.ingress_punt_src
        = NPL_PUNT_SRC_INBOUND_MIRROR;
    punt_encap_data.punt_msb_encap.punt_encap_msb.lpts_tcam_first_result_encap_data_msb.encap_punt_code.mirror_or_redirect_code
        = mirror_code;
    punt_encap_data.punt_msb_encap.punt_encap_msb.lpts_tcam_first_result_encap_data_msb.punt_sub_code.sub_code.lpts_flow_type
        .lpts_flow
        = 0;

    bool is_tagged;
    if (is_vlan_tag_eq(m_vlan_tag, LA_VLAN_TAG_UNTAGGED)) {
        is_tagged = false;
    } else {
        is_tagged = true;
    }

    punt_encap_data.punt_lsb_encap.punt_shared_lsb_encap.punt_encap_data_lsb.punt_nw_encap_ptr.ptr = encap_ptr;
    punt_encap_data.punt_lsb_encap.punt_shared_lsb_encap.punt_encap_data_lsb.punt_controls.mirror_local_encap_format = 1;
    punt_encap_data.punt_lsb_encap.punt_shared_lsb_encap.punt_cud_type = NPL_PUNT_CUD_TYPE_IBM;
    if (la_erspan_mirror_command_base::m_type == la_erspan_mirror_command::type_e::SFLOW_TUNNEL) {
        if (is_tagged) {
            if (m_ip_version == la_ip_version_e::IPV4) {
                punt_encap_data.punt_lsb_encap.punt_shared_lsb_encap.punt_encap_data_lsb.punt_nw_encap_type
                    = NPL_PUNT_NW_IP_UDP_ENCAP_TYPE;
            } else {
                punt_encap_data.punt_lsb_encap.punt_shared_lsb_encap.punt_encap_data_lsb.punt_nw_encap_type
                    = NPL_PUNT_NW_IPV6_UDP_ENCAP_TYPE;
            }
        } else {
            if (m_ip_version == la_ip_version_e::IPV4) {
                punt_encap_data.punt_lsb_encap.punt_shared_lsb_encap.punt_encap_data_lsb.punt_nw_encap_type
                    = NPL_PUNT_NW_IP_UDP_NO_VLAN_ENCAP_TYPE;
            } else {
                punt_encap_data.punt_lsb_encap.punt_shared_lsb_encap.punt_encap_data_lsb.punt_nw_encap_type
                    = NPL_PUNT_NW_IPV6_UDP_NO_VLAN_ENCAP_TYPE;
            }
        }
        punt_encap_data.punt_lsb_encap.punt_shared_lsb_encap.punt_encap_data_lsb.punt_controls.punt_format
            = NPL_PUNT_HEADER_FORMAT_TYPE_UDP;
    } else {
        if (is_tagged) {
            if (m_ip_version == la_ip_version_e::IPV4) {
                punt_encap_data.punt_lsb_encap.punt_shared_lsb_encap.punt_encap_data_lsb.punt_nw_encap_type
                    = NPL_PUNT_NW_IP_TUNNEL_ENCAP_TYPE;
            } else {
                punt_encap_data.punt_lsb_encap.punt_shared_lsb_encap.punt_encap_data_lsb.punt_nw_encap_type
                    = NPL_PUNT_NW_IPV6_TUNNEL_ENCAP_TYPE;
            }
        } else {
            if (m_ip_version == la_ip_version_e::IPV4) {
                punt_encap_data.punt_lsb_encap.punt_shared_lsb_encap.punt_encap_data_lsb.punt_nw_encap_type
                    = NPL_PUNT_NW_IP_TUNNEL_NO_VLAN_ENCAP_TYPE;
            } else {
                punt_encap_data.punt_lsb_encap.punt_shared_lsb_encap.punt_encap_data_lsb.punt_nw_encap_type
                    = NPL_PUNT_NW_IPV6_TUNNEL_NO_VLAN_ENCAP_TYPE;
            }
        }
        punt_encap_data.punt_lsb_encap.punt_shared_lsb_encap.punt_encap_data_lsb.punt_controls.punt_format
            = NPL_PUNT_HEADER_FORMAT_TYPE_ERSPAN_II;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_pacific::set_truncate(bool truncate)
{
    start_api_call("truncate=", truncate);

    pdoq_fdoq_partial_mirror_configuration_register reg{{0}};
    la_status status;

    auto& lld = m_device->m_ll_device;

    for (la_slice_id_t slice : m_device->get_used_slices()) {
        status = lld->read_register(*m_device->m_pacific_tree->slice[slice]->pdoq->fdoq->partial_mirror_configuration, reg);
        return_on_error(status);
        if (truncate) {
            reg.fields.partial_mirror = bit_utils::set_bit(reg.fields.partial_mirror, m_mirror_gid, true);
        } else {
            reg.fields.partial_mirror = bit_utils::set_bit(reg.fields.partial_mirror, m_mirror_gid, false);
        }

        status = lld->write_register(*m_device->m_pacific_tree->slice[slice]->pdoq->fdoq->partial_mirror_configuration, reg);
        return_on_error(status);
    }

    m_truncate = truncate;

    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_pacific::configure_cud_entry(la_uint_t mirror_hw_id, la_uint_t mirror_gid, la_uint_t encap_ptr)
{
    return configure_cud_wide_hw_entry(mirror_hw_id, mirror_gid, encap_ptr);
}

la_status
la_erspan_mirror_command_pacific::teardown_cud_entry(la_uint_t mirror_hw_id)
{
    return teardown_cud_wide_hw_entry(mirror_hw_id);
}

la_status
la_erspan_mirror_command_pacific::configure_cud_wide_hw_entry(la_uint_t mirror_hw_id, la_uint_t mirror_gid, la_uint_t encap_ptr)
{
    npl_cud_wide_hw_table_t::key_type k;
    npl_cud_wide_hw_table_t::value_type v;

    k.cud_mapping_local_vars_mc_copy_id_12_1_ = mirror_hw_id;
    v.action = NPL_CUD_WIDE_HW_TABLE_ACTION_WRITE;

    npl_punt_encap_data_t& punt_encap_data(v.payloads.cud_mapping_local_vars_wide_mc_cud.mirror.mirror_cud_encap.punt_encap_data);
    la_status status = populate_punt_encap_data(mirror_gid, punt_encap_data, encap_ptr);
    return_on_error(status);

    const auto& tables(m_device->m_tables.cud_wide_hw_table);
    status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK}, k, v);

    return status;
}

la_status
la_erspan_mirror_command_pacific::teardown_cud_wide_hw_entry(la_uint_t mirror_gid)
{
    npl_cud_wide_hw_table_t::key_type k;
    k.cud_mapping_local_vars_mc_copy_id_12_1_ = mirror_gid;

    const auto& tables(m_device->m_tables.cud_wide_hw_table);
    la_status status = per_slice_tables_erase(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK}, k);

    return status;
}

la_status
la_erspan_mirror_command_pacific::configure_ibm_command_table(la_uint_t sampling_rate)
{
    auto sp_impl = m_dsp.weak_ptr_static_cast<const la_system_port_base>();

    const auto& table(m_device->m_tables.ibm_cmd_table);
    npl_ibm_cmd_table_key_t key;
    npl_ibm_cmd_table_value_t value;
    npl_ibm_cmd_table_entry_t* entry = nullptr;

    key.rxpp_to_txpp_local_vars_mirror_command = m_mirror_gid;
    value.payloads.ibm_cmd_table_result.sampling_probability = sampling_rate;
    value.payloads.ibm_cmd_table_result.is_mc = 0;
    value.payloads.ibm_cmd_table_result.tc_map_profile = la_device_impl::IBM_TC_PROFILE;

    la_voq_set* voq_set = sp_impl->get_voq_set();

    // For ERSPAN rate-limiting support, add the TC to the base voq to get the
    // final voq. The TC profile mapping values should always be 0.
    value.payloads.ibm_cmd_table_result.voq_or_bitmap.base_voq = voq_set->get_base_voq_id() + m_voq_offset;

    la_status status = table->set(key, value, entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_pacific::configure_mirror_to_dsp_in_npu_soft_header_table(uint8_t value)
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
la_erspan_mirror_command_pacific::teardown_mirror_to_dsp_in_npu_soft_header_table()
{
    const auto& table(m_device->m_tables.mirror_to_dsp_in_npu_soft_header_table);
    npl_mirror_to_dsp_in_npu_soft_header_table_key_t key;

    key.mirror_code = m_mirror_gid;

    la_status status = table->erase(key);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
