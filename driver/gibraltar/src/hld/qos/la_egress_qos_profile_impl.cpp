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

#include "qos/la_egress_qos_profile_impl.h"
#include "hld_utils.h"
#include "npu/la_acl_delegate.h"
#include "system/la_device_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "la_strings.h"

#include <sstream>

using namespace std;
namespace silicon_one
{

la_egress_qos_profile_impl::la_egress_qos_profile_impl(const la_device_impl_wptr& device) : m_device(device)
{
}

la_egress_qos_profile_impl::~la_egress_qos_profile_impl()
{
}

la_status
la_egress_qos_profile_impl::initialize(la_object_id_t oid, la_egress_qos_marking_source_e marking_source)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    m_oid = oid;
    set_marking_source(marking_source);

    return LA_STATUS_SUCCESS;
}

la_status
la_egress_qos_profile_impl::destroy()
{
    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_egress_qos_profile_impl::type() const
{
    return object_type_e::EGRESS_QOS_PROFILE;
}

la_object_id_t
la_egress_qos_profile_impl::oid() const
{
    return m_oid;
}

const la_device*
la_egress_qos_profile_impl::get_device() const
{
    return m_device.get();
}

uint64_t
la_egress_qos_profile_impl::get_id(la_slice_pair_id_t slice_pair) const
{
    return m_slice_pair_data[slice_pair].qos_id;
}

std::string
la_egress_qos_profile_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_egress_qos_profile_impl(oid=" << m_oid << ")";
    return log_message.str();
}

// Marking source
la_status
la_egress_qos_profile_impl::set_marking_source(la_egress_qos_marking_source_e marking_source)
{
    m_marking_source = marking_source;

    return LA_STATUS_SUCCESS;
}

la_status
la_egress_qos_profile_impl::get_marking_source(la_egress_qos_marking_source_e& out_marking_source) const
{
    start_api_getter_call("");

    out_marking_source = m_marking_source;

    return LA_STATUS_SUCCESS;
}

// Ethernet forwarding QoS re/marking mapping
la_status
la_egress_qos_profile_impl::set_qos_tag_mapping_pcpdei(la_vlan_pcpdei egress_pcpdei_tag,
                                                       la_vlan_pcpdei remark_pcpdei,
                                                       encapsulating_headers_qos_values encap_qos_values)
{
    start_api_call("egress_pcpdei_tag=", egress_pcpdei_tag, "remark_pcpdei=", remark_pcpdei, "encap_qos_values=", encap_qos_values);

    la_status status
        = set_mac_fwd_qos_mapping_table_entry(get_prefixed_qos_field(egress_pcpdei_tag), remark_pcpdei, encap_qos_values);

    return status;
}

la_status
la_egress_qos_profile_impl::get_qos_tag_mapping_pcpdei(la_vlan_pcpdei egress_pcpdei_tag,
                                                       la_vlan_pcpdei& out_remark_pcpdei,
                                                       encapsulating_headers_qos_values& out_encap_qos_values) const
{
    start_api_getter_call("egress_pcpdei_tag=", egress_pcpdei_tag);

    la_status status
        = get_mac_fwd_qos_mapping_table_entry(get_prefixed_qos_field(egress_pcpdei_tag), out_remark_pcpdei, out_encap_qos_values);

    return status;
}

la_status
la_egress_qos_profile_impl::set_qos_group_mapping_pcpdei(la_qos_group_t qos_group,
                                                         la_vlan_pcpdei pcpdei,
                                                         encapsulating_headers_qos_values encap_qos_values)
{
    start_api_call("qos_group=", qos_group, "pcpdei=", pcpdei, "encap_qos_values=", encap_qos_values);

    la_status status = set_mac_fwd_qos_mapping_table_entry(qos_group, pcpdei, encap_qos_values);

    return status;
}

la_status
la_egress_qos_profile_impl::get_qos_group_mapping_pcpdei(la_qos_group_t qos_group,
                                                         la_vlan_pcpdei& out_pcpdei,
                                                         encapsulating_headers_qos_values& out_encap_qos_values) const
{
    start_api_getter_call("qos_group=", qos_group);

    la_status status = get_mac_fwd_qos_mapping_table_entry(qos_group, out_pcpdei, out_encap_qos_values);

    return status;
}

// IP forwarding QoS re/marking mapping

la_status
la_egress_qos_profile_impl::set_qos_tag_mapping_dscp(la_ip_dscp egress_dscp_tag,
                                                     la_ip_dscp remark_dscp,
                                                     encapsulating_headers_qos_values encap_qos_values)
{
    start_api_call("egress_dscp_tag=", egress_dscp_tag, "remark_dscp=", remark_dscp, "encap_qos_values=", encap_qos_values);

    la_status status = set_ip_fwd_qos_mapping_table_entry(get_prefixed_qos_field(egress_dscp_tag), remark_dscp, encap_qos_values);

    return status;
}

la_status
la_egress_qos_profile_impl::get_qos_tag_mapping_dscp(la_ip_dscp egress_dscp_tag,
                                                     la_ip_dscp& out_remark_dscp,
                                                     encapsulating_headers_qos_values& out_encap_qos_values) const
{
    start_api_getter_call("egress_dscp_tag=", egress_dscp_tag);

    la_status status
        = get_ip_fwd_qos_mapping_table_entry(get_prefixed_qos_field(egress_dscp_tag), out_remark_dscp, out_encap_qos_values);

    return status;
}

la_status
la_egress_qos_profile_impl::set_qos_group_mapping_dscp(la_qos_group_t qos_group,
                                                       la_ip_dscp dscp,
                                                       encapsulating_headers_qos_values encap_qos_values)
{
    start_api_call("qos_group=", qos_group, "dscp=", dscp, "encap_qos_values=", encap_qos_values);

    la_status status = set_ip_fwd_qos_mapping_table_entry(qos_group, dscp, encap_qos_values);

    return status;
}

la_status
la_egress_qos_profile_impl::get_qos_group_mapping_dscp(la_qos_group_t qos_group,
                                                       la_ip_dscp& out_dscp,
                                                       encapsulating_headers_qos_values& out_encap_qos_values) const
{
    start_api_getter_call("qos_group=", qos_group);

    la_status status = get_ip_fwd_qos_mapping_table_entry(qos_group, out_dscp, out_encap_qos_values);

    return status;
}

// MPLS forwarding QoS re/marking mapping

la_status
la_egress_qos_profile_impl::set_qos_tag_mapping_mpls_tc(la_mpls_tc egress_mpls_tc_tag,
                                                        la_mpls_tc remark_mpls_tc,
                                                        encapsulating_headers_qos_values encap_qos_values)
{
    start_api_call(
        "egress_mpls_tc_tag=", egress_mpls_tc_tag, "remark_mpls_tc=", remark_mpls_tc, "encap_qos_values=", encap_qos_values);

    la_status status = set_mpls_fwd_qos_mapping_table_entry(get_prefixed_qos_field(egress_mpls_tc_tag), encap_qos_values);

    return status;
}

la_status
la_egress_qos_profile_impl::get_qos_tag_mapping_mpls_tc(la_mpls_tc egress_mpls_tc_tag,
                                                        la_mpls_tc& out_remark_mpls_tc,
                                                        encapsulating_headers_qos_values& out_encap_qos_values) const
{
    start_api_getter_call("egress_mpls_tc_tag=", egress_mpls_tc_tag);

    la_status status = get_mpls_fwd_qos_mapping_table_entry(get_prefixed_qos_field(egress_mpls_tc_tag), out_encap_qos_values);

    return status;
}

la_status
la_egress_qos_profile_impl::set_qos_group_mapping_mpls_tc(la_qos_group_t qos_group,
                                                          la_mpls_tc mpls_tc,
                                                          encapsulating_headers_qos_values encap_qos_values)
{
    start_api_call("qos_group=", qos_group, "mpls_tc=", mpls_tc, "encap_qos_values=", encap_qos_values);

    la_status status = set_mpls_fwd_qos_mapping_table_entry(qos_group, encap_qos_values);

    return status;
}

la_status
la_egress_qos_profile_impl::get_qos_group_mapping_mpls_tc(la_qos_group_t qos_group,
                                                          la_mpls_tc& out_mpls_tc,
                                                          encapsulating_headers_qos_values& out_encap_qos_values) const
{
    start_api_getter_call("qos_group=", qos_group);

    la_status status = get_mpls_fwd_qos_mapping_table_entry(qos_group, out_encap_qos_values);

    return status;
}

// Counter offset mapping

la_status
la_egress_qos_profile_impl::set_counter_offset_mapping(la_vlan_pcpdei pcpdei, la_uint8_t offset)
{
    start_api_call("pcpdei=", pcpdei, "offset=", offset);

    // Read table
    auto v = npl_egress_qos_result_t();
    la_status status = read_mac_qos_mapping_table_entry(get_prefixed_qos_field(pcpdei), v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.q_offset.cntr_offset.offset.base_cntr_offset = offset;

    // Write table
    status = write_mac_qos_mapping_table_entry(get_prefixed_qos_field(pcpdei), v);
    return status;
}

la_status
la_egress_qos_profile_impl::get_counter_offset_mapping(la_vlan_pcpdei pcpdei, la_uint8_t& out_offset) const
{
    start_api_getter_call("pcpdei=", pcpdei);

    // Read table
    auto v = npl_egress_qos_result_t();
    la_status status = read_mac_qos_mapping_table_entry(get_prefixed_qos_field(pcpdei), v);
    return_on_error(status);

    // Modify output
    out_offset = v.q_offset.cntr_offset.offset.base_cntr_offset;
    return LA_STATUS_SUCCESS;
}

la_status
la_egress_qos_profile_impl::set_counter_offset_mapping(la_ip_dscp dscp, la_uint8_t offset)
{
    start_api_call("dscp=", dscp, "offset=", offset);

    // Read table
    auto v = npl_egress_qos_result_t();
    la_status status = read_ip_qos_mapping_table_entry(get_prefixed_qos_field(dscp), v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.q_offset.cntr_offset.offset.base_cntr_offset = offset;

    // Write table
    status = write_ip_qos_mapping_table_entry(get_prefixed_qos_field(dscp), v);
    return status;
}

la_status
la_egress_qos_profile_impl::get_counter_offset_mapping(la_ip_dscp dscp, la_uint8_t& out_offset) const
{
    start_api_getter_call();

    // Read table
    auto v = npl_egress_qos_result_t();
    la_status status = read_ip_qos_mapping_table_entry(get_prefixed_qos_field(dscp), v);
    return_on_error(status);

    // Modify output
    out_offset = v.q_offset.cntr_offset.offset.base_cntr_offset;
    return LA_STATUS_SUCCESS;
}

la_status
la_egress_qos_profile_impl::set_counter_offset_mapping(la_mpls_tc mpls_tc, la_uint8_t offset)
{
    start_api_call("mpls_tc=", mpls_tc, "offset=", offset);

    la_uint8_t prefixed_egress_mpls_tc_tag = get_prefixed_qos_field(mpls_tc);

    // Read table
    auto v = npl_egress_qos_result_t();
    la_status status = read_mpls_qos_mapping_table_entry(prefixed_egress_mpls_tc_tag, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.q_offset.cntr_offset.offset.base_cntr_offset = offset;

    // Write table
    status = write_mpls_qos_mapping_table_entry(prefixed_egress_mpls_tc_tag, v);
    return status;
}

la_status
la_egress_qos_profile_impl::get_counter_offset_mapping(la_mpls_tc mpls_tc, la_uint8_t& out_offset) const
{
    start_api_getter_call();

    la_uint8_t prefixed_egress_mpls_tc_tag = get_prefixed_qos_field(mpls_tc);

    // Read table
    auto v = npl_egress_qos_result_t();
    la_status status = read_mpls_qos_mapping_table_entry(prefixed_egress_mpls_tc_tag, v);
    return_on_error(status);

    // Modify output
    out_offset = v.q_offset.cntr_offset.offset.base_cntr_offset;
    return LA_STATUS_SUCCESS;
}

la_status
la_egress_qos_profile_impl::set_counter_offset_mapping(la_qos_group_t qos_group, la_uint8_t offset)
{
    start_api_call("qos_group=", qos_group, "offset=", offset);

    // Read any mapping table. It is same value in all mappings
    auto v = npl_egress_qos_result_t();
    la_status status = read_mpls_qos_mapping_table_entry(qos_group, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.q_offset.cntr_offset.offset.base_cntr_offset = offset;

    // Write table
    status = write_mpls_qos_mapping_table_entry(qos_group, v);
    return_on_error(status);

    status = read_mac_qos_mapping_table_entry(qos_group, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.q_offset.cntr_offset.offset.base_cntr_offset = offset;
    status = write_mac_qos_mapping_table_entry(qos_group, v);
    return_on_error(status);

    status = read_ip_qos_mapping_table_entry(qos_group, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.q_offset.cntr_offset.offset.base_cntr_offset = offset;
    status = write_ip_qos_mapping_table_entry(qos_group, v);
    return_on_error(status);

    return status;
}

la_status
la_egress_qos_profile_impl::get_counter_offset_mapping(la_qos_group_t qos_group, la_uint8_t& out_offset) const
{
    start_api_getter_call();

    // Read table
    auto v = npl_egress_qos_result_t();
    la_status status = read_mpls_qos_mapping_table_entry(qos_group, v);
    return_on_error(status);

    // Modify output
    out_offset = v.q_offset.cntr_offset.offset.base_cntr_offset;
    return LA_STATUS_SUCCESS;
}

// Helper functions for writing to QoS mapping tables

la_status
la_egress_qos_profile_impl::read_mac_qos_mapping_table_entry(la_uint8_t pcpdei_or_qos_group,
                                                             npl_egress_qos_result_t& out_value) const
{
    out_value = m_qos_map[pcpdei_or_qos_group];
    return LA_STATUS_SUCCESS;
}

la_status
la_egress_qos_profile_impl::write_mac_qos_mapping_table_entry(la_uint8_t pcpdei_or_qos_group, const npl_egress_qos_result_t& result)
{
    la_status status = LA_STATUS_SUCCESS;
    auto slice_pairs = m_ifg_use_count->get_slice_pairs();
    m_qos_map[pcpdei_or_qos_group] = result;

    for (la_slice_pair_id_t slice_pair : slice_pairs) {
        status = set_combined_qos_mapping(slice_pair, m_slice_pair_data[slice_pair].qos_id, pcpdei_or_qos_group);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_egress_qos_profile_impl::read_ip_qos_mapping_table_entry(la_uint8_t dscp_or_qos_group, npl_egress_qos_result_t& out_value) const
{
    out_value = m_qos_map[dscp_or_qos_group];
    return LA_STATUS_SUCCESS;
}

la_status
la_egress_qos_profile_impl::write_ip_qos_mapping_table_entry(la_uint8_t dscp_or_qos_group, const npl_egress_qos_result_t& result)
{
    la_status status = LA_STATUS_SUCCESS;
    auto slice_pairs = m_ifg_use_count->get_slice_pairs();
    m_qos_map[dscp_or_qos_group] = result;

    for (la_slice_pair_id_t slice_pair : slice_pairs) {
        status = set_combined_qos_mapping(slice_pair, m_slice_pair_data[slice_pair].qos_id, dscp_or_qos_group);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_egress_qos_profile_impl::read_mpls_qos_mapping_table_entry(la_uint8_t mpls_tc_or_qos_group,
                                                              npl_egress_qos_result_t& out_value) const
{
    if (mpls_tc_or_qos_group >= LA_MAX_QOS_GROUP) {
        return LA_STATUS_EINVAL;
    }

    out_value = m_qos_map[mpls_tc_or_qos_group];
    return LA_STATUS_SUCCESS;
}

la_status
la_egress_qos_profile_impl::write_mpls_qos_mapping_table_entry(la_uint8_t mpls_tc_or_qos_group,
                                                               const npl_egress_qos_result_t& result)
{
    if (mpls_tc_or_qos_group >= LA_MAX_QOS_GROUP) {
        return LA_STATUS_EINVAL;
    }

    la_status status = LA_STATUS_SUCCESS;
    auto slice_pairs = m_ifg_use_count->get_slice_pairs();
    m_qos_map[mpls_tc_or_qos_group] = result;

    for (la_slice_pair_id_t pair_idx : slice_pairs) {
        status = set_combined_qos_mapping(pair_idx, m_slice_pair_data[pair_idx].qos_id, mpls_tc_or_qos_group);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_egress_qos_profile_impl::set_mac_fwd_qos_mapping_table_entry(la_uint8_t pcpdei_or_qos_group,
                                                                la_vlan_pcpdei remark_pcpdei,
                                                                encapsulating_headers_qos_values encap_qos_values)
{
    // Read table
    auto v = npl_egress_qos_result_t();
    la_status status = read_mac_qos_mapping_table_entry(pcpdei_or_qos_group, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.remark_l2 = 1;
    v.encap.exp_no_bos.exp = encap_qos_values.tc.value;
    v.encap.pcp_dei = remark_pcpdei.flat;
    v.encap.tos = encap_qos_values.tos.flat;

    // Write table
    status = write_mac_qos_mapping_table_entry(pcpdei_or_qos_group, v);
    return status;
}

la_status
la_egress_qos_profile_impl::get_mac_fwd_qos_mapping_table_entry(la_uint8_t pcpdei_or_qos_group,
                                                                la_vlan_pcpdei& out_remark_pcpdei,
                                                                encapsulating_headers_qos_values& out_encap_qos_values) const
{
    // Read table
    auto v = npl_egress_qos_result_t();
    la_status status = read_mac_qos_mapping_table_entry(pcpdei_or_qos_group, v);
    return_on_error(status);

    // Modify output
    out_remark_pcpdei.flat = v.encap.pcp_dei;
    out_encap_qos_values.pcpdei.flat = v.encap.pcp_dei;
    out_encap_qos_values.tc.value = v.encap.exp_no_bos.exp;
    out_encap_qos_values.tos.flat = v.encap.tos;

    return LA_STATUS_SUCCESS;
}

la_status
la_egress_qos_profile_impl::set_ip_fwd_qos_mapping_table_entry(la_uint8_t dscp_or_qos_group,
                                                               la_ip_dscp remark_dscp,
                                                               encapsulating_headers_qos_values encap_qos_values)
{
    auto v = npl_egress_qos_result_t();
    la_status status = read_ip_qos_mapping_table_entry(dscp_or_qos_group, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.remark_l2 = 1;
    v.remark_l3.enable_egress_remark = 1;
    v.remark_l3.use_in_mpls_exp = !encap_qos_values.use_for_inner_labels;
    v.fwd_remark_dscp = remark_dscp.value;
    v.encap.pcp_dei = encap_qos_values.pcpdei.flat;
    v.encap.exp_no_bos.exp = encap_qos_values.tc.value;
    v.encap.tos = encap_qos_values.tos.flat;

    // Write table
    status = write_ip_qos_mapping_table_entry(dscp_or_qos_group, v);
    return status;
}

la_status
la_egress_qos_profile_impl::get_ip_fwd_qos_mapping_table_entry(la_uint8_t dscp_or_qos_group,
                                                               la_ip_dscp& out_remark_dscp,
                                                               encapsulating_headers_qos_values& out_encap_qos_values) const
{
    auto v = npl_egress_qos_result_t();
    la_status status = read_ip_qos_mapping_table_entry(dscp_or_qos_group, v);
    return_on_error(status);

    out_remark_dscp.value = v.fwd_remark_dscp;
    out_encap_qos_values.use_for_inner_labels = !v.remark_l3.use_in_mpls_exp;
    out_encap_qos_values.pcpdei.flat = v.encap.pcp_dei;
    out_encap_qos_values.tc.value = v.encap.exp_no_bos.exp;
    out_encap_qos_values.tos.flat = v.encap.tos;

    return LA_STATUS_SUCCESS;
}

la_status
la_egress_qos_profile_impl::set_mpls_fwd_qos_mapping_table_entry(la_uint8_t mpls_tc_or_qos_group,
                                                                 encapsulating_headers_qos_values encap_qos_values)
{
    auto v = npl_egress_qos_result_t();
    la_status status = read_mpls_qos_mapping_table_entry(mpls_tc_or_qos_group, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.remark_l3.use_in_mpls_exp = !encap_qos_values.use_for_inner_labels;
    v.encap.exp_no_bos.exp = encap_qos_values.tc.value;
    v.encap.pcp_dei = encap_qos_values.pcpdei.flat;
    v.encap.tos = encap_qos_values.tos.flat;

    // Write table
    status = write_mpls_qos_mapping_table_entry(mpls_tc_or_qos_group, v);
    return status;
}

la_status
la_egress_qos_profile_impl::get_mpls_fwd_qos_mapping_table_entry(la_uint8_t mpls_tc_or_qos_group,
                                                                 encapsulating_headers_qos_values& out_encap_qos_values) const
{
    auto v = npl_egress_qos_result_t();
    la_status status = read_mpls_qos_mapping_table_entry(mpls_tc_or_qos_group, v);
    return_on_error(status);

    out_encap_qos_values.use_for_inner_labels = !v.remark_l3.use_in_mpls_exp;
    out_encap_qos_values.pcpdei.flat = v.encap.pcp_dei;
    out_encap_qos_values.tc.value = v.encap.exp_no_bos.exp;
    out_encap_qos_values.tos.flat = v.encap.tos;

    return LA_STATUS_SUCCESS;
}

la_status
la_egress_qos_profile_impl::set_combined_qos_mapping(la_slice_pair_id_t slice_pair, la_acl_id_t qos_id, uint qos_tag)
{
    // program IP/MAC qos mapping
    const auto& table(m_device->m_tables.txpp_mapping_qos_tag_table[slice_pair]);
    npl_txpp_mapping_qos_tag_table_t::key_type k;
    npl_txpp_mapping_qos_tag_table_t::value_type v;

    // Set key value
    k.qos_id = qos_id;
    k.qos_tag = qos_tag;
    v.payloads.egress_qos_result = m_qos_map[qos_tag];

    // Write
    npl_txpp_mapping_qos_tag_table_t::entry_pointer_type entry_ptr = nullptr;
    return (table->set(k, v, entry_ptr));
}

la_status
la_egress_qos_profile_impl::set_qos_mapping(la_slice_pair_id_t slice_pair, la_acl_id_t qos_id)
{
    la_status status = LA_STATUS_SUCCESS;

    // Program IP/MAC Mapping table
    if (m_marking_source == la_egress_qos_marking_source_e::QOS_GROUP) {
        for (uint qos_group = 0; qos_group < LA_MAX_QOS_GROUP_OR_EXP_PCPDEI; qos_group++) {
            status = set_combined_qos_mapping(slice_pair, qos_id, qos_group);
            return_on_error(status);
        }
    } else {
        for (la_uint_t dscp = 0; dscp < LA_MAX_DSCP; dscp++) {
            la_ip_dscp dscp_struct = {};
            dscp_struct.value = dscp;
            status = set_combined_qos_mapping(slice_pair, qos_id, get_prefixed_qos_field(dscp_struct));
            return_on_error(status);
        }

        for (la_uint_t pcpdei = 0; pcpdei < LA_MAX_PCPDEI; pcpdei++) {
            la_vlan_pcpdei pcpdei_struct(pcpdei);
            status = set_combined_qos_mapping(slice_pair, qos_id, get_prefixed_qos_field(pcpdei_struct));
            return_on_error(status);
        }

        // program MPLS Mapping table
        for (uint8_t mpls_tc = 0; mpls_tc < LA_MAX_QOS_GROUP; mpls_tc++) {
            la_mpls_tc mpls_tc_struct = {};
            mpls_tc_struct.value = mpls_tc;
            status = set_combined_qos_mapping(slice_pair, qos_id, get_prefixed_qos_field(mpls_tc_struct));
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_egress_qos_profile_impl::add_ifg(la_slice_ifg ifg)
{
    transaction txn;
    bool ifg_added, slice_added, slice_pair_added;
    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);
    txn.on_fail([=]() {
        bool ifg_removed, slice_removed, slice_pair_removed;
        m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);
    });

    if (!ifg_added) {
        return LA_STATUS_SUCCESS;
    }

    if (slice_pair_added) {
        // try allocate a new profile on this slice pair
        la_slice_pair_id_t slice_pair = (ifg.slice / 2);
        la_acl_id_t qos_id = la_device_impl::NUM_EGRESS_QOS_PROFILES_PER_SLICE_PAIR;
        bool allocated = m_device->m_index_generators.slice_pair[slice_pair].egress_qos_profiles.allocate(qos_id);
        if (!allocated) {
            log_err(HLD, "Failed to allocate egress qos profile in slice_pair: %d", slice_pair);
            txn.status = LA_STATUS_ERESOURCE;
            return txn.status;
        }

        txn.on_fail([=]() {
            la_slice_pair_id_t slice_pair = (ifg.slice / 2);
            m_device->m_index_generators.slice_pair[slice_pair].egress_qos_profiles.release(m_slice_pair_data[slice_pair].qos_id);
            m_slice_pair_data[slice_pair].qos_id = la_device_impl::NUM_EGRESS_QOS_PROFILES_PER_SLICE_PAIR;
        });

        m_slice_pair_data[slice_pair].qos_id = qos_id;

        // program new slice with the new qos_id allocated
        txn.status = set_qos_mapping(slice_pair, qos_id);
        if (txn.status != LA_STATUS_SUCCESS) {
            return txn.status;
        }
    }

    // Notify users
    txn.status = m_device->notify_ifg_added(this, ifg);
    if (txn.status != LA_STATUS_SUCCESS) {
        return txn.status;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_egress_qos_profile_impl::remove_ifg(la_slice_ifg ifg)
{
    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);

    if (!ifg_removed) {
        return LA_STATUS_SUCCESS;
    }

    if (slice_pair_removed) {
        la_slice_pair_id_t slice_pair = (ifg.slice / 2);
        m_device->m_index_generators.slice_pair[slice_pair].egress_qos_profiles.release(m_slice_pair_data[slice_pair].qos_id);
        m_slice_pair_data[slice_pair].qos_id = la_device_impl::NUM_EGRESS_QOS_PROFILES_PER_SLICE_PAIR;
    }

    // Notify users
    la_status status = m_device->notify_ifg_removed(this, ifg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_egress_qos_profile_impl::notify_change(dependency_management_op op)
{
    switch (op.type_e) {

    case dependency_management_op::management_type_e::IFG_MANAGEMENT:
        if (op.action.ifg_management.ifg_op == ifg_management_op::IFG_ADD) {
            return add_ifg(op.action.ifg_management.ifg);
        } else {
            return remove_ifg(op.action.ifg_management.ifg);
        }

    default:
        log_err(HLD,
                "la_egress_qos_profile_impl::notify_change received unsupported notification (%s)",
                silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

slice_ifg_vec_t
la_egress_qos_profile_impl::get_ifgs() const
{
    return m_ifg_use_count->get_ifgs();
}

} // namespace silicon_one
