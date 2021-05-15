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

#include "system/la_erspan_mirror_command_akpg.h"
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

la_erspan_mirror_command_akpg::la_erspan_mirror_command_akpg(const la_device_impl_wptr& device)
    : la_erspan_mirror_command_base(device)
{
}

la_erspan_mirror_command_akpg::~la_erspan_mirror_command_akpg()
{
}

la_status
la_erspan_mirror_command_akpg::populate_punt_encap_data(la_uint_t mirror_code,
                                                        npl_punt_encap_data_t& punt_encap_data,
                                                        la_uint_t encap_ptr) const
{
    auto& msb = punt_encap_data.punt_msb_encap.punt_encap_msb;
    msb.npu_mirror_or_redirect_encapsulation_type = NPL_NPU_ENCAP_MIRROR_OR_REDIRECT;
    msb.lpts_tcam_first_result_encap_data_msb.ingress_punt_src = NPL_PUNT_SRC_INBOUND_MIRROR;
    msb.lpts_tcam_first_result_encap_data_msb.encap_punt_code.mirror_or_redirect_code = mirror_code;
    msb.lpts_tcam_first_result_encap_data_msb.punt_sub_code.sub_code.lpts_flow_type.lpts_flow = 0;

    auto& lsb = punt_encap_data.punt_lsb_encap.punt_shared_lsb_encap;
    lsb.punt_encap_data_lsb.punt_controls.mirror_local_encap_format = 1;

    bool is_tagged;
    if (is_vlan_tag_eq(m_vlan_tag, LA_VLAN_TAG_UNTAGGED)) {
        is_tagged = false;
    } else {
        is_tagged = true;
    }

    lsb.punt_encap_data_lsb.punt_nw_encap_ptr.ptr = encap_ptr;
    lsb.punt_cud_type = NPL_PUNT_CUD_TYPE_IBM;
    if (la_erspan_mirror_command_base::m_type == la_erspan_mirror_command::type_e::SFLOW_TUNNEL) {
        if (is_tagged) {
            if (m_ip_version == la_ip_version_e::IPV4) {
                lsb.punt_encap_data_lsb.punt_nw_encap_type = NPL_PUNT_NW_IP_UDP_ENCAP_TYPE;
            } else {
                lsb.punt_encap_data_lsb.punt_nw_encap_type = NPL_PUNT_NW_IPV6_UDP_ENCAP_TYPE;
            }
        } else {
            if (m_ip_version == la_ip_version_e::IPV4) {
                lsb.punt_encap_data_lsb.punt_nw_encap_type = NPL_PUNT_NW_IP_UDP_NO_VLAN_ENCAP_TYPE;
            } else {
                lsb.punt_encap_data_lsb.punt_nw_encap_type = NPL_PUNT_NW_IPV6_UDP_NO_VLAN_ENCAP_TYPE;
            }
        }
        lsb.punt_encap_data_lsb.punt_controls.punt_format = NPL_PUNT_HEADER_FORMAT_TYPE_UDP;
    } else {
        if (is_tagged) {
            if (m_ip_version == la_ip_version_e::IPV4) {
                lsb.punt_encap_data_lsb.punt_nw_encap_type = NPL_PUNT_NW_IP_TUNNEL_ENCAP_TYPE;
            } else {
                lsb.punt_encap_data_lsb.punt_nw_encap_type = NPL_PUNT_NW_IPV6_TUNNEL_ENCAP_TYPE;
            }
        } else {
            if (m_ip_version == la_ip_version_e::IPV4) {
                lsb.punt_encap_data_lsb.punt_nw_encap_type = NPL_PUNT_NW_IP_TUNNEL_NO_VLAN_ENCAP_TYPE;
            } else {
                lsb.punt_encap_data_lsb.punt_nw_encap_type = NPL_PUNT_NW_IPV6_TUNNEL_NO_VLAN_ENCAP_TYPE;
            }
        }
        lsb.punt_encap_data_lsb.punt_controls.punt_format = NPL_PUNT_HEADER_FORMAT_TYPE_ERSPAN_II;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_akpg::configure_cud_entry(la_uint_t mirror_hw_id, la_uint_t mirror_gid, la_uint_t encap_ptr)
{
    return configure_mc_cud_table_entry(mirror_hw_id, mirror_gid, encap_ptr);
}

la_status
la_erspan_mirror_command_akpg::teardown_cud_entry(la_uint_t mirror_hw_id)
{
    return teardown_mc_cud_table_entry(mirror_hw_id);
}

la_status
la_erspan_mirror_command_akpg::configure_mc_cud_table_entry(la_uint_t mirror_hw_id, la_uint_t mirror_gid, la_uint_t encap_ptr)
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
    status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK}, k, v);

    return status;
}

la_status
la_erspan_mirror_command_akpg::teardown_mc_cud_table_entry(la_uint_t mirror_hw_id)
{
    npl_mc_cud_table_key_t k;
    k.cud_mapping_local_vars_exp_mc_copy_id_14_1_ = mc_copy_id_manager::get_mc_cud_table_key(mirror_hw_id);

    const auto& tables(m_device->m_tables.mc_cud_table);
    la_status status = per_slice_tables_erase(m_device->m_slice_mode, tables, {la_slice_mode_e::NETWORK}, k);

    return status;
}

la_status
la_erspan_mirror_command_akpg::configure_mirror_to_dsp_in_npu_soft_header_table(uint8_t value)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_akpg::teardown_mirror_to_dsp_in_npu_soft_header_table()
{
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
