// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "la_meter_markdown_profile_impl.h"
#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/math_utils.h"
#include "hld_types.h"
#include "hld_utils.h"
#include "ifg_use_count.h"
#include "la_strings.h"
#include "nplapi/nplapi_tables.h"
#include "system/la_device_impl.h"

#include <sstream>

namespace silicon_one
{

la_meter_markdown_profile_impl::la_meter_markdown_profile_impl(const la_device_impl_wptr& device) : m_device(device), m_gid(0)
{
}

la_meter_markdown_profile_impl::~la_meter_markdown_profile_impl()
{
}

la_status
la_meter_markdown_profile_impl::initialize(la_object_id_t oid, la_meter_markdown_gid_t gid)
{
    m_oid = oid;
    la_status status = LA_STATUS_SUCCESS;
    m_gid = gid;

    status = set_meter_markdown_default_mappings();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_markdown_profile_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_meter_markdown_profile_impl::type() const
{
    return object_type_e::METER_MARKDOWN_PROFILE;
}

const la_device*
la_meter_markdown_profile_impl::get_device() const
{
    return m_device.get();
}

uint64_t
la_meter_markdown_profile_impl::oid() const
{
    return m_oid;
}

std::string
la_meter_markdown_profile_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_meter_markdown_profile_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_meter_markdown_gid_t
la_meter_markdown_profile_impl::get_gid() const
{
    return m_gid;
}

la_status
la_meter_markdown_profile_impl::set_meter_markdown_mapping_pcpdei(la_qos_color_e color,
                                                                  la_vlan_pcpdei from_pcp,
                                                                  la_vlan_pcpdei markdown_pcp)
{
    start_api_call("color=", color, "from_pcp=", from_pcp, "markdown_pcp=", markdown_pcp);

    npl_txpp_fwd_qos_mapping_table_t::key_type k;
    npl_txpp_fwd_qos_mapping_table_t::value_type v;
    npl_txpp_fwd_qos_mapping_table_t::entry_pointer_type entry_ptr = nullptr;

    k.pd_tx_out_color = (uint64_t)color;
    k.packet_protocol_layer_none__tx_npu_header_slp_qos_id = m_gid;
    k.packet_protocol_layer_none__tx_npu_header_fwd_qos_tag = get_prefixed_qos_field(from_pcp);
    v.payloads.txpp_npu_header_fwd_qos_tag = get_prefixed_qos_field(markdown_pcp);
    v.action = NPL_TXPP_FWD_QOS_MAPPING_TABLE_ACTION_WRITE;

    la_status status = m_device->m_tables.txpp_fwd_qos_mapping_table->set(k, v, entry_ptr);
    return_on_error(status);

    return status;
}

la_status
la_meter_markdown_profile_impl::set_meter_markdown_mapping_dscp(la_qos_color_e color,
                                                                la_ip_dscp from_dscp,
                                                                la_ip_dscp markdown_dscp)
{
    start_api_call("color=", color, "from_dscp=", from_dscp, "markdown_dscp=", markdown_dscp);

    npl_txpp_fwd_qos_mapping_table_t::key_type k;
    npl_txpp_fwd_qos_mapping_table_t::value_type v;
    npl_txpp_fwd_qos_mapping_table_t::entry_pointer_type entry_ptr = nullptr;

    k.pd_tx_out_color = (uint64_t)color;
    k.packet_protocol_layer_none__tx_npu_header_slp_qos_id = m_gid;
    k.packet_protocol_layer_none__tx_npu_header_fwd_qos_tag = get_prefixed_qos_field(from_dscp);
    v.payloads.txpp_npu_header_fwd_qos_tag = get_prefixed_qos_field(markdown_dscp);
    v.action = NPL_TXPP_FWD_QOS_MAPPING_TABLE_ACTION_WRITE;

    la_status status = m_device->m_tables.txpp_fwd_qos_mapping_table->set(k, v, entry_ptr);
    return_on_error(status);

    return status;
}

la_status
la_meter_markdown_profile_impl::set_meter_markdown_mapping_mpls_tc(la_qos_color_e color,
                                                                   la_mpls_tc from_mpls_tc,
                                                                   la_mpls_tc markdown_mpls_tc)
{
    start_api_call("color=", color, "from_mpls_tc=", from_mpls_tc, "markdown_mpls_tc=", markdown_mpls_tc);

    npl_txpp_fwd_qos_mapping_table_t::key_type k;
    npl_txpp_fwd_qos_mapping_table_t::value_type v;
    npl_txpp_fwd_qos_mapping_table_t::entry_pointer_type entry_ptr = nullptr;

    k.pd_tx_out_color = (uint64_t)color;
    k.packet_protocol_layer_none__tx_npu_header_slp_qos_id = m_gid;
    k.packet_protocol_layer_none__tx_npu_header_fwd_qos_tag = get_prefixed_qos_field(from_mpls_tc);
    v.payloads.txpp_npu_header_fwd_qos_tag = get_prefixed_qos_field(markdown_mpls_tc);
    v.action = NPL_TXPP_FWD_QOS_MAPPING_TABLE_ACTION_WRITE;

    la_status status = m_device->m_tables.txpp_fwd_qos_mapping_table->set(k, v, entry_ptr);
    return_on_error(status);

    return status;
}

la_status
la_meter_markdown_profile_impl::get_meter_markdown_mapping_pcpdei(la_qos_color_e color,
                                                                  la_vlan_pcpdei from_pcp,
                                                                  la_vlan_pcpdei& out_markdown_pcp) const
{
    start_api_getter_call("color=", color, "from_pcp=", from_pcp);

    npl_txpp_fwd_qos_mapping_table_t::key_type k;
    npl_txpp_fwd_qos_mapping_table_t::entry_pointer_type entry_ptr = nullptr;

    k.pd_tx_out_color = (uint64_t)color;
    k.packet_protocol_layer_none__tx_npu_header_slp_qos_id = m_gid;
    k.packet_protocol_layer_none__tx_npu_header_fwd_qos_tag = get_prefixed_qos_field(from_pcp);

    la_status status = m_device->m_tables.txpp_fwd_qos_mapping_table->lookup(k, entry_ptr);
    return_on_error(status);

    npl_txpp_fwd_qos_mapping_table_t::value_type v = entry_ptr->value();
    out_markdown_pcp = la_vlan_pcpdei(v.payloads.txpp_npu_header_fwd_qos_tag);

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_markdown_profile_impl::get_meter_markdown_mapping_dscp(la_qos_color_e color,
                                                                la_ip_dscp from_dscp,
                                                                la_ip_dscp& out_markdown_dscp) const
{
    start_api_getter_call("color=", color, "from_dscp=", from_dscp);

    npl_txpp_fwd_qos_mapping_table_t::key_type k;
    npl_txpp_fwd_qos_mapping_table_t::entry_pointer_type entry_ptr = nullptr;

    k.pd_tx_out_color = (uint64_t)color;
    k.packet_protocol_layer_none__tx_npu_header_slp_qos_id = m_gid;
    k.packet_protocol_layer_none__tx_npu_header_fwd_qos_tag = get_prefixed_qos_field(from_dscp);

    la_status status = m_device->m_tables.txpp_fwd_qos_mapping_table->lookup(k, entry_ptr);
    return_on_error(status);

    npl_txpp_fwd_qos_mapping_table_t::value_type v = entry_ptr->value();
    out_markdown_dscp.value = v.payloads.txpp_npu_header_fwd_qos_tag;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_markdown_profile_impl::get_meter_markdown_mapping_mpls_tc(la_qos_color_e color,
                                                                   la_mpls_tc from_mpls_tc,
                                                                   la_mpls_tc& out_markdown_mpls_tc) const
{
    start_api_getter_call("color=", color, "from_mpls_tc=", from_mpls_tc);

    npl_txpp_fwd_qos_mapping_table_t::key_type k;
    npl_txpp_fwd_qos_mapping_table_t::entry_pointer_type entry_ptr = nullptr;

    k.pd_tx_out_color = (uint64_t)color;
    k.packet_protocol_layer_none__tx_npu_header_slp_qos_id = m_gid;
    k.packet_protocol_layer_none__tx_npu_header_fwd_qos_tag = get_prefixed_qos_field(from_mpls_tc);

    la_status status = m_device->m_tables.txpp_fwd_qos_mapping_table->lookup(k, entry_ptr);
    return_on_error(status);

    npl_txpp_fwd_qos_mapping_table_t::value_type v = entry_ptr->value();
    out_markdown_mpls_tc.value = v.payloads.txpp_npu_header_fwd_qos_tag;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_markdown_profile_impl::set_meter_markdown_mapping_mpls_tc_encap(la_qos_color_e color,
                                                                         la_mpls_tc from_encap_mpls_tc,
                                                                         la_mpls_tc markdown_mpls_tc)
{
    start_api_call("color=", color, "from_encap_mpls_tc=", from_encap_mpls_tc, "markdown_mpls_tc=", markdown_mpls_tc);

    npl_txpp_encap_qos_mapping_table_t::key_type k;
    npl_txpp_encap_qos_mapping_table_t::value_type v;
    npl_txpp_encap_qos_mapping_table_t::entry_pointer_type entry_ptr = nullptr;

    k.pd_tx_out_color = (uint64_t)color;
    k.packet_protocol_layer_none__tx_npu_header_slp_qos_id = m_gid;
    k.packet_protocol_layer_none__tx_npu_header_encap_qos_tag = get_prefixed_mpls_exp_field(from_encap_mpls_tc);
    v.payloads.txpp_npu_header_encap_qos_tag = get_prefixed_mpls_exp_field(markdown_mpls_tc);
    v.action = NPL_TXPP_ENCAP_QOS_MAPPING_TABLE_ACTION_WRITE;

    la_status status = m_device->m_tables.txpp_encap_qos_mapping_table->set(k, v, entry_ptr);
    return_on_error(status);

    return status;
}

la_status
la_meter_markdown_profile_impl::get_meter_markdown_mapping_mpls_tc_encap(la_qos_color_e color,
                                                                         la_mpls_tc from_encap_mpls_tc,
                                                                         la_mpls_tc& out_markdown_mpls_tc) const
{
    start_api_getter_call("color=", color, "from_encap_mpls_tc=", from_encap_mpls_tc);

    npl_txpp_encap_qos_mapping_table_t::key_type k;
    npl_txpp_encap_qos_mapping_table_t::entry_pointer_type entry_ptr = nullptr;

    k.pd_tx_out_color = (uint64_t)color;
    k.packet_protocol_layer_none__tx_npu_header_slp_qos_id = m_gid;
    k.packet_protocol_layer_none__tx_npu_header_encap_qos_tag = get_prefixed_mpls_exp_field(from_encap_mpls_tc);

    la_status status = m_device->m_tables.txpp_encap_qos_mapping_table->lookup(k, entry_ptr);
    return_on_error(status);

    npl_txpp_encap_qos_mapping_table_t::value_type v = entry_ptr->value();
    out_markdown_mpls_tc.value = v.payloads.txpp_npu_header_encap_qos_tag;

    return LA_STATUS_SUCCESS;
}

la_status
la_meter_markdown_profile_impl::set_meter_markdown_default_mappings()
{
    la_status status = LA_STATUS_SUCCESS;
    const la_qos_color_e meter_markdown_colors[] = {la_qos_color_e::GREEN, la_qos_color_e::YELLOW, la_qos_color_e::RED};

    for (auto color : meter_markdown_colors) {
        for (uint8_t dscp = 0; dscp < MAX_IP_DSCP_VALUE; dscp++) {
            la_ip_dscp ip_dscp = {.value = dscp};
            status = set_meter_markdown_mapping_dscp(color, ip_dscp, ip_dscp);
            return_on_error(status);
        }

        for (uint8_t pcpdei = 0; pcpdei < MAX_VLAN_PCPDEI_VALUE; ++pcpdei) {
            la_vlan_pcpdei vlan_pcpdei(pcpdei);
            status = set_meter_markdown_mapping_pcpdei(color, vlan_pcpdei, vlan_pcpdei);
            return_on_error(status);
        }

        for (uint8_t tc = 0; tc < MAX_MPLS_TC_VALUE; ++tc) {
            la_mpls_tc mpls_tc = {.value = tc};
            status = set_meter_markdown_mapping_mpls_tc(color, mpls_tc, mpls_tc);
            return_on_error(status);
            status = set_meter_markdown_mapping_mpls_tc_encap(color, mpls_tc, mpls_tc);
            return_on_error(status);
        }
    }

    return status;
}

} // namespace silicon_one
