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

#include "qos/la_ingress_qos_profile_impl.h"
#include "hld_utils.h"
#include "npu/la_acl_delegate.h"
#include "system/la_device_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "la_strings.h"
#include "nplapi/npl_enums.h"
#include <sstream>

using namespace std;
namespace silicon_one
{

la_ingress_qos_profile_impl::la_ingress_qos_profile_impl(const la_device_impl_wptr& device)
    : m_device(device), m_enable_ingress_remark(false), m_meter_markdown_profile(nullptr)
{
}

la_ingress_qos_profile_impl::~la_ingress_qos_profile_impl()
{
}

la_status
la_ingress_qos_profile_impl::initialize(la_object_id_t oid)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    m_oid = oid;

    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::destroy()
{
    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_ingress_qos_profile_impl::type() const
{
    return object_type_e::INGRESS_QOS_PROFILE;
}

la_object_id_t
la_ingress_qos_profile_impl::oid() const
{
    return m_oid;
}

const la_device*
la_ingress_qos_profile_impl::get_device() const
{
    return m_device.get();
}

uint64_t
la_ingress_qos_profile_impl::get_id(la_slice_pair_id_t slice_pair) const
{
    return m_slice_pair_data[slice_pair].qos_id;
}

std::string
la_ingress_qos_profile_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_ingress_qos_profile_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_status
la_ingress_qos_profile_impl::set_qos_tag_mapping_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    la_status status;
    m_enable_ingress_remark = enabled;

    // Refresh all IP qos tag mapping entries
    for (la_uint8_t dscp = 0; dscp < LA_MAX_DSCP; dscp++) {
        la_ip_dscp in_dscp = {.value = dscp};
        npl_ingress_ip_qos_mapping_table_t::value_type v;

        status = read_ip_qos_mapping_table_entry(la_ip_version_e::IPV4, in_dscp, v);
        return_on_error(status);

        v.payloads.ip_qos_mapping_result.enable_ingress_remark = enabled;

        status = write_ip_qos_mapping_table_entry(la_ip_version_e::IPV4, in_dscp, v);

        // Here we setup IPv6
        status = read_ip_qos_mapping_table_entry(la_ip_version_e::IPV6, in_dscp, v);
        return_on_error(status);

        v.payloads.ip_qos_mapping_result.enable_ingress_remark = enabled;
        status = write_ip_qos_mapping_table_entry(la_ip_version_e::IPV6, in_dscp, v);
        return_on_error(status);
    }

    // Refresh all MPLS qos tag mapping entries
    for (la_uint8_t mpls_tc = 0; mpls_tc < LA_MAX_EXP; mpls_tc++) {
        la_mpls_tc in_mpls_tc = {.value = mpls_tc};
        npl_mpls_qos_mapping_table_t::value_type v;

        status = read_mpls_qos_mapping_table_entry(in_mpls_tc, v);
        return_on_error(status);

        v.payloads.mpls_qos_mapping_result.enable_ingress_remark = enabled;

        status = write_mpls_qos_mapping_table_entry(in_mpls_tc, v);
        return_on_error(status);
    }

    // TODO - also refresh PCP/DEI when NPL supports enable_ingress_remark for ethernet flows

    return status;
}

la_status
la_ingress_qos_profile_impl::get_qos_tag_mapping_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    out_enabled = m_enable_ingress_remark;
    return LA_STATUS_SUCCESS;
}

// Traffic class mapping
la_status
la_ingress_qos_profile_impl::set_traffic_class_mapping(la_vlan_pcpdei pcpdei, la_traffic_class_t tc)
{
    start_api_call("pcpdei=", pcpdei, "tc=", tc);

    // Insert to the table
    la_status status = set_mac_traffic_class_mapping(pcpdei, tc);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_traffic_class_mapping(la_vlan_pcpdei pcpdei, la_traffic_class_t& out_tc) const
{
    start_api_getter_call();

    la_status status = get_mac_traffic_class_mapping(pcpdei, out_tc);
    return status;
}

la_status
la_ingress_qos_profile_impl::set_traffic_class_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_traffic_class_t tc)
{
    start_api_call("ip_version=", ip_version, "dscp=", dscp, "tc=", tc);

    la_status status = set_ip_traffic_class_mapping(ip_version, dscp, tc);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_traffic_class_mapping(la_ip_version_e ip_version,
                                                       la_ip_dscp dscp,
                                                       la_traffic_class_t& out_tc) const
{
    start_api_getter_call();

    // Read from the table
    la_status status = get_ip_traffic_class_mapping(ip_version, dscp, out_tc);
    return status;
}

la_status
la_ingress_qos_profile_impl::set_traffic_class_mapping(la_mpls_tc mpls_tc, la_traffic_class_t tc)
{
    start_api_call("mpls_tc=", mpls_tc, "tc=", tc);

    // Insert to the table
    la_status status = set_mpls_traffic_class_mapping(mpls_tc, tc);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_traffic_class_mapping(la_mpls_tc mpls_tc, la_traffic_class_t& out_tc) const
{
    start_api_getter_call();

    // Read from the table
    la_status status = get_mpls_traffic_class_mapping(mpls_tc, out_tc);
    return status;
}

// Color mapping

la_status
la_ingress_qos_profile_impl::set_color_mapping(la_vlan_pcpdei pcpdei, la_qos_color_e color)
{
    start_api_call("pcpdei=", pcpdei, "color=", color);

    // Insert to the table
    la_status status = set_mac_color_mapping(pcpdei, color);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_color_mapping(la_vlan_pcpdei pcpdei, la_qos_color_e& out_color) const
{
    start_api_getter_call();

    // Read from the table
    la_status status = get_mac_color_mapping(pcpdei, out_color);
    return status;
}

la_status
la_ingress_qos_profile_impl::set_color_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_color_e color)
{
    start_api_call("ip_version=", ip_version, "dscp=", dscp, "color=", color);

    // Insert to the table
    la_status status = set_ip_color_mapping(ip_version, dscp, color);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_color_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_color_e& out_color) const
{
    start_api_getter_call();
    // Read from the IPv4 or IPv6 table
    la_status status = get_ip_color_mapping(ip_version, dscp, out_color);
    return status;
}

la_status
la_ingress_qos_profile_impl::set_color_mapping(la_mpls_tc mpls_tc, la_qos_color_e color)
{
    start_api_call("mpls_tc=", mpls_tc, "color=", color);

    // Insert to the table
    la_status status = set_mpls_color_mapping(mpls_tc, color);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_color_mapping(la_mpls_tc mpls_tc, la_qos_color_e& out_color) const
{
    start_api_getter_call();

    // Read from the table
    la_status status = get_mpls_color_mapping(mpls_tc, out_color);
    return status;
}

// Meter/Counter offset mapping

la_status
la_ingress_qos_profile_impl::set_meter_or_counter_offset_mapping(la_vlan_pcpdei pcpdei, la_uint8_t offset)
{
    start_api_call("pcpdei=", pcpdei, "offset=", offset);

    // Read table
    npl_mac_qos_mapping_table_t::value_type v;
    la_status status = read_mac_qos_mapping_table_entry(pcpdei, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.payloads.ingress_mac_qos_mapping_result.ctr_offest_union.q_m_offset.cntr_offset.offset.base_cntr_offset = offset;

    // Write table
    status = write_mac_qos_mapping_table_entry(pcpdei, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_meter_or_counter_offset_mapping(la_vlan_pcpdei pcpdei, la_uint8_t& out_offset) const
{
    start_api_getter_call();

    // Read table
    npl_mac_qos_mapping_table_t::value_type v;
    la_status status = read_mac_qos_mapping_table_entry(pcpdei, v);
    return_on_error(status);

    // Modify output
    out_offset = v.payloads.ingress_mac_qos_mapping_result.ctr_offest_union.q_m_offset.cntr_offset.offset.base_cntr_offset;
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_meter_or_counter_offset_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_uint8_t offset)
{
    start_api_call("ip_version=", ip_version, "dscp=", dscp, "offset=", offset);

    // Read table
    npl_ingress_ip_qos_mapping_table_t::value_type v;
    la_status status = read_ip_qos_mapping_table_entry(ip_version, dscp, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.payloads.ip_qos_mapping_result.ctr_offest_union.q_m_offset_5bits.offset = offset;

    // Write table
    status = write_ip_qos_mapping_table_entry(ip_version, dscp, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_meter_or_counter_offset_mapping(la_ip_version_e ip_version,
                                                                 la_ip_dscp dscp,
                                                                 la_uint8_t& out_offset) const
{
    start_api_getter_call();

    // Read table
    npl_ingress_ip_qos_mapping_table_t::value_type v;
    la_status status = read_ip_qos_mapping_table_entry(ip_version, dscp, v);
    return_on_error(status);

    // Modify output
    out_offset = v.payloads.ip_qos_mapping_result.ctr_offest_union.q_m_offset_5bits.offset;
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_meter_or_counter_offset_mapping(la_mpls_tc mpls_tc, la_uint8_t offset)
{
    start_api_call("mpls_tc=", mpls_tc, "offset=", offset);

    // Read table
    npl_mpls_qos_mapping_table_t::value_type v;
    la_status status = read_mpls_qos_mapping_table_entry(mpls_tc, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.payloads.mpls_qos_mapping_result.ctr_offest_union.q_m_offset_5bits.offset = offset;

    // Write table
    status = write_mpls_qos_mapping_table_entry(mpls_tc, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_meter_or_counter_offset_mapping(la_mpls_tc mpls_tc, la_uint8_t& out_offset) const
{
    start_api_getter_call();

    // Read table
    npl_mpls_qos_mapping_table_t::value_type v;
    la_status status = read_mpls_qos_mapping_table_entry(mpls_tc, v);
    return_on_error(status);

    // Modify output
    out_offset = v.payloads.mpls_qos_mapping_result.ctr_offest_union.q_m_offset_5bits.offset;
    return LA_STATUS_SUCCESS;
}

// Meter or Counter selection mapping

la_status
la_ingress_qos_profile_impl::set_metering_enabled_mapping(la_vlan_pcpdei pcpdei, bool enabled)
{
    start_api_call("pcpdei=", pcpdei, "enabled=", enabled);

    // Insert to the table
    la_status status = set_mac_metering_enabled_mapping(pcpdei, enabled);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_metering_enabled_mapping(la_vlan_pcpdei pcpdei, bool& out_enabled) const
{
    start_api_getter_call();

    // Read from the table
    la_status status = get_mac_metering_enabled_mapping(pcpdei, out_enabled);
    return status;
}

la_status
la_ingress_qos_profile_impl::set_metering_enabled_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, bool enabled)
{
    start_api_call("ip_version=", ip_version, "dscp=", dscp, "enabled=", enabled);

    // Insert to the table
    la_status status = set_ip_metering_enabled_mapping(ip_version, dscp, enabled);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_metering_enabled_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, bool& out_enabled) const
{
    start_api_getter_call();

    // Read from the table
    la_status status = get_ip_metering_enabled_mapping(ip_version, dscp, out_enabled);
    return status;
}

la_status
la_ingress_qos_profile_impl::set_metering_enabled_mapping(la_mpls_tc mpls_tc, bool enabled)
{
    start_api_call("mpls_tc=", mpls_tc, "enabled=", enabled);

    // Insert to the table
    la_status status = set_mpls_metering_enabled_mapping(mpls_tc, enabled);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_metering_enabled_mapping(la_mpls_tc mpls_tc, bool& out_enabled) const
{
    start_api_getter_call();

    // Read from the table
    la_status status = get_mpls_metering_enabled_mapping(mpls_tc, out_enabled);
    return status;
}

// Ingress QoS tag mapping

la_status
la_ingress_qos_profile_impl::set_qos_tag_mapping_pcpdei(la_vlan_pcpdei ingress_pcpdei, la_vlan_pcpdei mapped_pcpdei_tag)
{
    start_api_call("ingress_pcpdei=", ingress_pcpdei, "mapped_pcpdei_tag=", mapped_pcpdei_tag);

    la_status status = set_mac_qos_mapping_table_entry(ingress_pcpdei, mapped_pcpdei_tag);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_qos_tag_mapping_pcpdei(la_vlan_pcpdei ingress_pcpdei, la_vlan_pcpdei& out_mapped_pcpdei_tag) const
{
    start_api_getter_call();

    la_status status = get_mac_qos_mapping_table_entry(ingress_pcpdei, out_mapped_pcpdei_tag);
    return status;
}

la_status
la_ingress_qos_profile_impl::set_qos_tag_mapping_dscp(la_ip_dscp ingress_dscp, la_ip_dscp mapped_dscp_tag)
{
    start_api_call("ingress_dscp=", ingress_dscp, "mapped_dscp_tag=", mapped_dscp_tag);

    la_status status = set_ip_qos_mapping_table_entry(la_ip_version_e::IPV4, ingress_dscp, mapped_dscp_tag);
    return_on_error(status);
    status = set_ip_qos_mapping_table_entry(la_ip_version_e::IPV6, ingress_dscp, mapped_dscp_tag);
    return status;
}

la_status
la_ingress_qos_profile_impl::set_qos_tag_mapping_dscp(la_ip_version_e ip_version,
                                                      la_ip_dscp ingress_dscp,
                                                      la_ip_dscp mapped_dscp_tag)
{
    start_api_call("ip_version=", ip_version, "ingress_dscp=", ingress_dscp, "mapped_dscp_tag=", mapped_dscp_tag);

    la_status status = set_ip_qos_mapping_table_entry(ip_version, ingress_dscp, mapped_dscp_tag);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_qos_tag_mapping_dscp(la_ip_version_e ip_version,
                                                      la_ip_dscp ingress_dscp,
                                                      la_ip_dscp& out_mapped_dscp_tag) const
{
    start_api_getter_call();

    la_status status = get_ip_qos_mapping_table_entry(ip_version, ingress_dscp, out_mapped_dscp_tag);
    return status;
}

la_status
la_ingress_qos_profile_impl::set_qos_tag_mapping_mpls_tc(la_mpls_tc ingress_mpls_tc, la_mpls_tc mapped_mpls_tc_tag)
{
    start_api_call("ingress_mpls_tc=", ingress_mpls_tc, "mapped_mpls_tc_tag=", mapped_mpls_tc_tag);

    la_status status = set_mpls_qos_mapping_table_entry(ingress_mpls_tc, mapped_mpls_tc_tag);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_qos_tag_mapping_mpls_tc(la_mpls_tc ingress_mpls_tc, la_mpls_tc& out_mapped_mpls_tc_tag) const
{
    start_api_getter_call();

    la_status status = get_mpls_qos_mapping_table_entry(ingress_mpls_tc, out_mapped_mpls_tc_tag);
    return status;
}

// MPLS traffic-class encap mapping

la_status
la_ingress_qos_profile_impl::set_encap_qos_tag_mapping(la_vlan_pcpdei pcpdei, la_mpls_tc encap_mpls_tc)
{
    start_api_call("pcpdei=", pcpdei, "encap_mpls_tc=", encap_mpls_tc);

    // Insert to the table
    la_status status = set_mac_encap_qos_tag_mapping(pcpdei, encap_mpls_tc);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_encap_qos_tag_mapping(la_vlan_pcpdei pcpdei, la_mpls_tc& out_encap_mpls_tc) const
{
    start_api_getter_call();

    // Read from the table
    la_status status = get_mac_encap_qos_tag_mapping(pcpdei, out_encap_mpls_tc);
    return status;
}

la_status
la_ingress_qos_profile_impl::set_encap_qos_tag_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_mpls_tc encap_mpls_tc)
{
    start_api_call("ip_version=", ip_version, "dscp=", dscp, "encap_mpls_tc=", encap_mpls_tc);

    // Insert to the table
    la_status status = set_ip_encap_qos_tag_mapping(ip_version, dscp, encap_mpls_tc);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_encap_qos_tag_mapping(la_ip_version_e ip_version,
                                                       la_ip_dscp dscp,
                                                       la_mpls_tc& out_encap_mpls_tc) const
{
    start_api_getter_call();

    // Read from the table
    la_status status = get_ip_encap_qos_tag_mapping(ip_version, dscp, out_encap_mpls_tc);
    return status;
}

la_status
la_ingress_qos_profile_impl::set_encap_qos_tag_mapping(la_mpls_tc mpls_tc, la_mpls_tc encap_mpls_tc)
{
    start_api_call("mpls_tc=", mpls_tc, "encap_mpls_tc=", encap_mpls_tc);

    // Insert to the table
    la_status status = set_mpls_encap_qos_tag_mapping(mpls_tc, encap_mpls_tc);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_encap_qos_tag_mapping(la_mpls_tc mpls_tc, la_mpls_tc& out_encap_mpls_tc) const
{
    start_api_getter_call();

    // Read from the table
    la_status status = get_mpls_encap_qos_tag_mapping(mpls_tc, out_encap_mpls_tc);
    return status;
}

// QoS Group mapping

la_status
la_ingress_qos_profile_impl::set_qos_group_mapping(la_vlan_pcpdei pcpdei, la_qos_group_t qos_group)
{
    start_api_call("pcpdei=", pcpdei, "qos_group=", qos_group);

    // Insert to the table
    la_status status = set_mac_qos_group_mapping(pcpdei, qos_group);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_qos_group_mapping(la_vlan_pcpdei pcpdei, la_qos_group_t& out_qos_group) const
{
    start_api_getter_call();

    // Insert to the table
    la_status status = get_mac_qos_group_mapping(pcpdei, out_qos_group);
    return status;
}

la_status
la_ingress_qos_profile_impl::set_qos_group_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_group_t qos_group)
{
    start_api_call("ip_version=", ip_version, "dscp=", dscp, "qos_group=", qos_group);

    // Insert to the table
    la_status status = set_ip_qos_group_mapping(ip_version, dscp, qos_group);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_qos_group_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_group_t& out_qos_group) const
{
    start_api_getter_call();

    la_status status = get_ip_qos_group_mapping(ip_version, dscp, out_qos_group);
    return status;
}

la_status
la_ingress_qos_profile_impl::set_qos_group_mapping(la_mpls_tc mpls_tc, la_qos_group_t qos_group)
{
    start_api_call("mpls_tc=", mpls_tc, "qos_group=", qos_group);

    // Insert to the table
    la_status status = set_mpls_qos_group_mapping(mpls_tc, qos_group);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_qos_group_mapping(la_mpls_tc mpls_tc, la_qos_group_t& out_qos_group) const
{
    start_api_getter_call();

    // Insert to the table
    la_status status = get_mpls_qos_group_mapping(mpls_tc, out_qos_group);
    return status;
}

// Helper functions for writing to QoS mapping tables

la_status
la_ingress_qos_profile_impl::read_mac_qos_mapping_table_entry(la_vlan_pcpdei pcpdei,
                                                              npl_mac_qos_mapping_table_t::value_type& out_value) const
{
    out_value = m_mac_qos_map[pcpdei.flat];
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::write_mac_qos_mapping_table_entry(la_vlan_pcpdei pcpdei, npl_mac_qos_mapping_table_t::value_type& v)
{
    la_status status = LA_STATUS_SUCCESS;
    auto slice_pairs = m_ifg_use_count->get_slice_pairs();
    m_mac_qos_map[pcpdei.flat] = v;

    for (la_slice_pair_id_t slice_pair : slice_pairs) {
        status = set_mac_qos_mapping_table(slice_pair, m_slice_pair_data[slice_pair].qos_id, pcpdei.flat);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::read_ip_qos_mapping_table_entry(la_ip_version_e ip_version,
                                                             la_ip_dscp dscp,
                                                             npl_ingress_ip_qos_mapping_table_t::value_type& out_value) const
{
    if (ip_version == la_ip_version_e::IPV6) {
        out_value = m_ipv6_qos_map[dscp.value];
    } else {
        out_value = m_ip_qos_map[dscp.value];
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::write_ip_qos_mapping_table_entry(la_ip_version_e ip_version,
                                                              la_ip_dscp dscp,
                                                              npl_ingress_ip_qos_mapping_table_t::value_type& v)
{
    la_status status = LA_STATUS_SUCCESS;
    auto slice_pairs = m_ifg_use_count->get_slice_pairs();
    if (ip_version == la_ip_version_e::IPV6) {
        m_ipv6_qos_map[dscp.value] = v;
    } else {
        m_ip_qos_map[dscp.value] = v;
    }

    for (la_slice_pair_id_t pair_idx : slice_pairs) {
        status = set_ip_qos_mapping_table(ip_version, pair_idx, m_slice_pair_data[pair_idx].qos_id, dscp.value);
        return_on_error(status);
        ;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::read_mpls_qos_mapping_table_entry(la_mpls_tc mpls_tc,
                                                               npl_mpls_qos_mapping_table_t::value_type& out_value) const
{
    out_value = m_mpls_qos_map[mpls_tc.value];
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::write_mpls_qos_mapping_table_entry(la_mpls_tc mpls_tc, npl_mpls_qos_mapping_table_t::value_type& v)
{
    la_status status = LA_STATUS_SUCCESS;

    auto slice_pairs = m_ifg_use_count->get_slice_pairs();
    m_mpls_qos_map[mpls_tc.value] = v;

    for (la_slice_pair_id_t pair_idx : slice_pairs) {
        status = set_mpls_qos_mapping_table(pair_idx, m_slice_pair_data[pair_idx].qos_id, mpls_tc.value);
        return_on_error(status);
        ;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_mac_qos_mapping_table_entry(la_vlan_pcpdei pcpdei, la_vlan_pcpdei mapped_pcpdei_tag)
{
    // Read table
    npl_mac_qos_mapping_table_t::value_type v;
    la_status status = read_mac_qos_mapping_table_entry(pcpdei, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.payloads.ingress_mac_qos_mapping_result.ingress_qos_remark.fwd_qos_tag = get_prefixed_qos_field(mapped_pcpdei_tag);

    // Write table
    status = write_mac_qos_mapping_table_entry(pcpdei, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_mac_qos_mapping_table_entry(la_vlan_pcpdei pcpdei, la_vlan_pcpdei& out_mapped_pcpdei_tag) const
{
    // Read table
    npl_mac_qos_mapping_table_t::value_type v;
    la_status status = read_mac_qos_mapping_table_entry(pcpdei, v);
    return_on_error(status);

    // Modify output
    out_mapped_pcpdei_tag.flat = v.payloads.ingress_mac_qos_mapping_result.ingress_qos_remark.fwd_qos_tag;
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_ip_qos_mapping_table_entry(la_ip_version_e ip_version, la_ip_dscp dscp, la_ip_dscp mapped_dscp_tag)
{
    // Read table
    npl_ingress_ip_qos_mapping_table_t::value_type v;
    la_status status = read_ip_qos_mapping_table_entry(ip_version, dscp, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.payloads.ip_qos_mapping_result.fwd_qos_tag = get_prefixed_qos_field(mapped_dscp_tag);

    // Write table
    status = write_ip_qos_mapping_table_entry(ip_version, dscp, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_ip_qos_mapping_table_entry(la_ip_version_e ip_version,
                                                            la_ip_dscp dscp,
                                                            la_ip_dscp& out_mapped_dscp_tag) const
{
    // Read table
    npl_ingress_ip_qos_mapping_table_t::value_type v;
    la_status status = read_ip_qos_mapping_table_entry(ip_version, dscp, v);
    return_on_error(status);

    // Modify output
    out_mapped_dscp_tag.value = v.payloads.ip_qos_mapping_result.fwd_qos_tag;
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_mpls_qos_mapping_table_entry(la_mpls_tc mpls_tc, la_mpls_tc mapped_mpls_tc_tag)
{
    // Read table
    npl_mpls_qos_mapping_table_t::value_type v;
    npl_encap_mpls_exp_t encap;
    la_status status = read_mpls_qos_mapping_table_entry(mpls_tc, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.payloads.mpls_qos_mapping_result.fwd_qos_tag = get_prefixed_qos_field(mapped_mpls_tc_tag);
    encap.exp = mapped_mpls_tc_tag.value;
    encap.valid = true;
    v.payloads.mpls_qos_mapping_result.encap_mpls_exp = encap;
    v.payloads.mpls_qos_mapping_result.fwd_class_qos_group_u.fwd_class_qos_group.fwd_class = encap.exp;

    // Write table
    status = write_mpls_qos_mapping_table_entry(mpls_tc, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_mpls_qos_mapping_table_entry(la_mpls_tc mpls_tc, la_mpls_tc& out_mapped_mpls_tc_tag) const
{
    // Read table
    npl_mpls_qos_mapping_table_t::value_type v;
    la_status status = read_mpls_qos_mapping_table_entry(mpls_tc, v);
    return_on_error(status);

    // Modify output
    out_mapped_mpls_tc_tag.value = v.payloads.mpls_qos_mapping_result.fwd_qos_tag;
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_mac_traffic_class_mapping(la_vlan_pcpdei pcpdei, la_traffic_class_t tc)
{
    // Read table
    npl_mac_qos_mapping_table_t::value_type v;
    la_status status = read_mac_qos_mapping_table_entry(pcpdei, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.payloads.ingress_mac_qos_mapping_result.phb.tc = tc;

    // Write table
    status = write_mac_qos_mapping_table_entry(pcpdei, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_mac_traffic_class_mapping(la_vlan_pcpdei pcpdei, la_traffic_class_t& out_tc) const
{
    // Read table
    npl_mac_qos_mapping_table_t::value_type v;
    la_status status = read_mac_qos_mapping_table_entry(pcpdei, v);
    return_on_error(status);

    // Modify output
    out_tc = v.payloads.ingress_mac_qos_mapping_result.phb.tc;
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_ip_traffic_class_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_traffic_class_t tc)
{
    // Read table
    npl_ingress_ip_qos_mapping_table_t::value_type v;
    la_status status = read_ip_qos_mapping_table_entry(ip_version, dscp, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.payloads.ip_qos_mapping_result.phb.tc = tc;

    // Write table
    status = write_ip_qos_mapping_table_entry(ip_version, dscp, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_ip_traffic_class_mapping(la_ip_version_e ip_version,
                                                          la_ip_dscp dscp,
                                                          la_traffic_class_t& out_tc) const
{
    // Read table
    npl_ingress_ip_qos_mapping_table_t::value_type v;
    la_status status = read_ip_qos_mapping_table_entry(ip_version, dscp, v);
    return_on_error(status);

    // Modify output
    out_tc = v.payloads.ip_qos_mapping_result.phb.tc;
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_mpls_traffic_class_mapping(la_mpls_tc mpls_tc, la_traffic_class_t tc)
{
    // Read table
    npl_mpls_qos_mapping_table_t::value_type v;
    la_status status = read_mpls_qos_mapping_table_entry(mpls_tc, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.payloads.mpls_qos_mapping_result.phb.tc = tc;

    // Write table
    status = write_mpls_qos_mapping_table_entry(mpls_tc, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_mpls_traffic_class_mapping(la_mpls_tc mpls_tc, la_traffic_class_t& out_tc) const
{
    // Read table
    npl_mpls_qos_mapping_table_t::value_type v;
    la_status status = read_mpls_qos_mapping_table_entry(mpls_tc, v);
    return_on_error(status);

    // Modify output
    out_tc = v.payloads.mpls_qos_mapping_result.phb.tc;
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_mac_metering_enabled_mapping(la_vlan_pcpdei pcpdei, bool enabled)
{
    // Read table
    npl_mac_qos_mapping_table_t::value_type v;
    la_status status = read_mac_qos_mapping_table_entry(pcpdei, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    if (enabled) {
        v.payloads.ingress_mac_qos_mapping_result.meter = NPL_METER_CNTR;
    } else {
        v.payloads.ingress_mac_qos_mapping_result.meter = NPL_Q_CNTR;
    }

    // Write table
    status = write_mac_qos_mapping_table_entry(pcpdei, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_mac_metering_enabled_mapping(la_vlan_pcpdei pcpdei, bool& out_enabled) const
{
    // Read table
    npl_mac_qos_mapping_table_t::value_type v;
    la_status status = read_mac_qos_mapping_table_entry(pcpdei, v);
    return_on_error(status);

    // Modify output
    out_enabled = v.payloads.ingress_mac_qos_mapping_result.meter;
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_ip_metering_enabled_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, bool enabled)
{
    // Read table
    npl_ingress_ip_qos_mapping_table_t::value_type v;
    la_status status = read_ip_qos_mapping_table_entry(ip_version, dscp, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.payloads.ip_qos_mapping_result.meter = enabled;

    // Write table
    status = write_ip_qos_mapping_table_entry(ip_version, dscp, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_ip_metering_enabled_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, bool& out_enabled) const
{
    // Read table
    npl_ingress_ip_qos_mapping_table_t::value_type v;
    la_status status = read_ip_qos_mapping_table_entry(ip_version, dscp, v);
    return_on_error(status);

    // Modify output
    out_enabled = v.payloads.ip_qos_mapping_result.meter;
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_mpls_metering_enabled_mapping(la_mpls_tc mpls_tc, bool enabled)
{
    // Read table
    npl_mpls_qos_mapping_table_t::value_type v;
    la_status status = read_mpls_qos_mapping_table_entry(mpls_tc, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.payloads.mpls_qos_mapping_result.meter = enabled;

    // Write table
    status = write_mpls_qos_mapping_table_entry(mpls_tc, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_mpls_metering_enabled_mapping(la_mpls_tc mpls_tc, bool& out_enabled) const
{
    // Read table
    npl_mpls_qos_mapping_table_t::value_type v;
    la_status status = read_mpls_qos_mapping_table_entry(mpls_tc, v);
    return_on_error(status);

    // Modify output
    out_enabled = v.payloads.mpls_qos_mapping_result.meter;
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_mac_color_mapping(la_vlan_pcpdei pcpdei, la_qos_color_e color)
{
    // Read table
    npl_mac_qos_mapping_table_t::value_type v;
    la_status status = read_mac_qos_mapping_table_entry(pcpdei, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.payloads.ingress_mac_qos_mapping_result.phb.dp = la_2_pbh_dp(color);

    // Write table
    status = write_mac_qos_mapping_table_entry(pcpdei, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_mac_color_mapping(la_vlan_pcpdei pcpdei, la_qos_color_e& out_color) const
{
    // Read table
    npl_mac_qos_mapping_table_t::value_type v;
    la_status status = read_mac_qos_mapping_table_entry(pcpdei, v);
    return_on_error(status);

    // Modify output
    out_color = npl_2_la_qos_color(v.payloads.ingress_mac_qos_mapping_result.phb.dp);
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_ip_color_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_color_e color)
{
    // Read table
    npl_ingress_ip_qos_mapping_table_t::value_type v;
    la_status status = read_ip_qos_mapping_table_entry(ip_version, dscp, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.payloads.ip_qos_mapping_result.phb.dp = la_2_pbh_dp(color);

    // Write table
    status = write_ip_qos_mapping_table_entry(ip_version, dscp, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_ip_color_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_color_e& out_color) const
{
    // Read table
    npl_ingress_ip_qos_mapping_table_t::value_type v;
    la_status status = read_ip_qos_mapping_table_entry(ip_version, dscp, v);
    return_on_error(status);

    // Modify output
    out_color = npl_2_la_qos_color(v.payloads.ip_qos_mapping_result.phb.dp);
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_mpls_color_mapping(la_mpls_tc mpls_tc, la_qos_color_e color)
{
    // Read table
    npl_mpls_qos_mapping_table_t::value_type v;
    la_status status = read_mpls_qos_mapping_table_entry(mpls_tc, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.payloads.mpls_qos_mapping_result.phb.dp = la_2_pbh_dp(color);

    // Write table
    status = write_mpls_qos_mapping_table_entry(mpls_tc, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_mpls_color_mapping(la_mpls_tc mpls_tc, la_qos_color_e& out_color) const
{
    // Read table
    npl_mpls_qos_mapping_table_t::value_type v;
    la_status status = read_mpls_qos_mapping_table_entry(mpls_tc, v);
    return_on_error(status);

    // Modify output
    out_color = npl_2_la_qos_color(v.payloads.mpls_qos_mapping_result.phb.dp);
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_mac_encap_qos_tag_mapping(la_vlan_pcpdei pcpdei, la_mpls_tc encap_mpls_tc)
{
    // Read table
    npl_mac_qos_mapping_table_t::value_type v;
    la_status status = read_mac_qos_mapping_table_entry(pcpdei, v);

    // Modify
    v.payloads.ingress_mac_qos_mapping_result.ingress_qos_remark.encap_mpls_exp.valid = 1;
    v.payloads.ingress_mac_qos_mapping_result.ingress_qos_remark.encap_mpls_exp.exp = encap_mpls_tc.value;

    // Write table
    status = write_mac_qos_mapping_table_entry(pcpdei, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_mac_encap_qos_tag_mapping(la_vlan_pcpdei pcpdei, la_mpls_tc& out_encap_mpls_tc) const
{
    // Read table
    npl_mac_qos_mapping_table_t::value_type v;
    la_status status = read_mac_qos_mapping_table_entry(pcpdei, v);
    return_on_error(status);

    // Modify output
    out_encap_mpls_tc.value = v.payloads.ingress_mac_qos_mapping_result.ingress_qos_remark.encap_mpls_exp.exp;
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_ip_encap_qos_tag_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_mpls_tc encap_mpls_tc)
{
    // Read table
    npl_ingress_ip_qos_mapping_table_t::value_type v;
    la_status status = read_ip_qos_mapping_table_entry(ip_version, dscp, v);

    // Modify
    v.payloads.ip_qos_mapping_result.encap_mpls_exp.valid = 1;
    v.payloads.ip_qos_mapping_result.encap_mpls_exp.exp = encap_mpls_tc.value;

    v.payloads.ip_qos_mapping_result.fwd_class_qos_group_u.fwd_class_qos_group.fwd_class = encap_mpls_tc.value;

    // Write table
    status = write_ip_qos_mapping_table_entry(ip_version, dscp, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_ip_encap_qos_tag_mapping(la_ip_version_e ip_version,
                                                          la_ip_dscp dscp,
                                                          la_mpls_tc& out_encap_mpls_tc) const
{
    // Read table
    npl_ingress_ip_qos_mapping_table_t::value_type v;
    la_status status = read_ip_qos_mapping_table_entry(ip_version, dscp, v);
    return_on_error(status);

    // Modify output
    out_encap_mpls_tc.value = v.payloads.ip_qos_mapping_result.encap_mpls_exp.exp;
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_mpls_encap_qos_tag_mapping(la_mpls_tc mpls_tc, la_mpls_tc encap_mpls_tc)
{
    // Read table
    npl_mpls_qos_mapping_table_t::value_type v;
    la_status status = read_mpls_qos_mapping_table_entry(mpls_tc, v);
    return_on_error(status);

    // Modify
    v.payloads.mpls_qos_mapping_result.encap_mpls_exp.valid = 1;
    v.payloads.mpls_qos_mapping_result.encap_mpls_exp.exp = encap_mpls_tc.value;
    v.payloads.mpls_qos_mapping_result.fwd_class_qos_group_u.fwd_class_qos_group.fwd_class = encap_mpls_tc.value;

    status = write_mpls_qos_mapping_table_entry(mpls_tc, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_mpls_encap_qos_tag_mapping(la_mpls_tc mpls_tc, la_mpls_tc& out_encap_mpls_tc) const
{
    // Read table
    npl_mpls_qos_mapping_table_t::value_type v;
    la_status status = read_mpls_qos_mapping_table_entry(mpls_tc, v);
    return_on_error(status);

    // Modify output
    out_encap_mpls_tc.value = v.payloads.mpls_qos_mapping_result.encap_mpls_exp.exp;
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_mac_qos_group_mapping(la_vlan_pcpdei pcpdei, la_qos_group_t ingress_qos_group)
{
    // Read table
    npl_mac_qos_mapping_table_t::value_type v;
    la_status status = read_mac_qos_mapping_table_entry(pcpdei, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.payloads.ingress_mac_qos_mapping_result.ingress_qos_remark.qos_group = ingress_qos_group;

    // Write table
    status = write_mac_qos_mapping_table_entry(pcpdei, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_mac_qos_group_mapping(la_vlan_pcpdei pcpdei, la_qos_group_t& out_ingress_qos_group) const
{
    // Read table
    npl_mac_qos_mapping_table_t::value_type v;
    la_status status = read_mac_qos_mapping_table_entry(pcpdei, v);
    return_on_error(status);

    // Modify output
    out_ingress_qos_group = v.payloads.ingress_mac_qos_mapping_result.ingress_qos_remark.qos_group;
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_ip_qos_group_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_group_t ingress_qos_group)
{
    // Read table
    npl_ingress_ip_qos_mapping_table_t::value_type v;
    la_status status = read_ip_qos_mapping_table_entry(ip_version, dscp, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.payloads.ip_qos_mapping_result.fwd_class_qos_group_u.fwd_class_qos_group.qos_group = ingress_qos_group;

    // Write table
    status = write_ip_qos_mapping_table_entry(ip_version, dscp, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_ip_qos_group_mapping(la_ip_version_e ip_version,
                                                      la_ip_dscp dscp,
                                                      la_qos_group_t& out_ingress_qos_group) const
{
    // Read table
    npl_ingress_ip_qos_mapping_table_t::value_type v;
    la_status status = read_ip_qos_mapping_table_entry(ip_version, dscp, v);
    return_on_error(status);

    // Modify output
    out_ingress_qos_group = v.payloads.ip_qos_mapping_result.fwd_class_qos_group_u.fwd_class_qos_group.qos_group;
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_mpls_qos_group_mapping(la_mpls_tc mpls_tc, la_qos_group_t ingress_qos_group)
{
    // Read table
    npl_mpls_qos_mapping_table_t::value_type v;
    la_status status = read_mpls_qos_mapping_table_entry(mpls_tc, v);
    if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    // Modify
    v.payloads.mpls_qos_mapping_result.fwd_class_qos_group_u.fwd_class_qos_group.qos_group = ingress_qos_group;

    // Write table
    status = write_mpls_qos_mapping_table_entry(mpls_tc, v);
    return status;
}

la_status
la_ingress_qos_profile_impl::get_mpls_qos_group_mapping(la_mpls_tc mpls_tc, la_qos_group_t& out_ingress_qos_group) const
{
    // Read table
    npl_mpls_qos_mapping_table_t::value_type v;
    la_status status = read_mpls_qos_mapping_table_entry(mpls_tc, v);
    return_on_error(status);

    // Modify output
    out_ingress_qos_group = v.payloads.mpls_qos_mapping_result.fwd_class_qos_group_u.fwd_class_qos_group.qos_group;
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_mac_qos_mapping_table(la_slice_pair_id_t slice_pair, la_acl_id_t qos_id, uint pcpdei)
{
    const auto& table(m_device->m_tables.mac_qos_mapping_table[slice_pair]);
    npl_mac_qos_mapping_table_t::key_type k;

    // Set key
    k.qos_id = qos_id;
    k.qos_key = pcpdei;

    npl_mac_qos_mapping_table_t::entry_pointer_type entry_ptr = nullptr;
    return (table->set(k, m_mac_qos_map[pcpdei], entry_ptr));
}

la_status
la_ingress_qos_profile_impl::set_ip_qos_mapping_table(la_ip_version_e ip_version,
                                                      la_slice_pair_id_t slice_pair,
                                                      la_acl_id_t qos_id,
                                                      uint dscp)
{
    const auto& table(m_device->m_tables.ingress_ip_qos_mapping_table[slice_pair]);
    npl_ingress_ip_qos_mapping_table_t::key_type k;

    // Set key
    k.qos_id = qos_id;
    if (ip_version == la_ip_version_e::IPV6) {
        k.l3_qos_mapping_key = dscp | LA_MAX_DSCP;
    } else {
        k.l3_qos_mapping_key = dscp;
    }

    npl_ingress_ip_qos_mapping_table_t::entry_pointer_type entry_ptr = nullptr;
    if (ip_version == la_ip_version_e::IPV6) {
        return (table->set(k, m_ipv6_qos_map[dscp], entry_ptr));
    } else {
        return (table->set(k, m_ip_qos_map[dscp], entry_ptr));
    }
}

la_status
la_ingress_qos_profile_impl::set_mpls_qos_mapping_table(la_slice_pair_id_t slice_pair, la_acl_id_t qos_id, uint mpls_tc)
{
    const auto& table(m_device->m_tables.mpls_qos_mapping_table[slice_pair]);
    npl_mpls_qos_mapping_table_t::key_type k;

    // Set key
    k.qos_id = qos_id;
    k.l3_qos_mapping_key = mpls_tc;

    npl_mpls_qos_mapping_table_t::entry_pointer_type entry_ptr = nullptr;
    return (table->set(k, m_mpls_qos_map[mpls_tc], entry_ptr));
}

la_status
la_ingress_qos_profile_impl::set_qos_mappings(la_slice_pair_id_t slice_pair, la_acl_id_t qos_id)
{
    la_status status = LA_STATUS_SUCCESS;

    // program mac qos mapping
    for (uint pcpdei = 0; pcpdei < LA_MAX_PCPDEI; pcpdei++) {
        status = set_mac_qos_mapping_table(slice_pair, qos_id, pcpdei);
        return_on_error(status);
    }

    // program ip qos mapping for both ipv4 and ipv6
    for (uint dscp = 0; dscp < LA_MAX_DSCP; dscp++) {
        status = set_ip_qos_mapping_table(la_ip_version_e::IPV4, slice_pair, qos_id, dscp);
        status = set_ip_qos_mapping_table(la_ip_version_e::IPV6, slice_pair, qos_id, dscp);
        return_on_error(status);
    }

    // program mpls qos mapping
    for (uint mpls_tc = 0; mpls_tc < LA_MAX_EXP; mpls_tc++) {
        status = set_mpls_qos_mapping_table(slice_pair, qos_id, mpls_tc);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::set_eth_meter_profile_mapping_table(la_slice_id_t slice_id, uint64_t qos_id, uint64_t profile_id)
{
    npl_eth_meter_profile_mapping_table_t::key_type k;
    npl_eth_meter_profile_mapping_table_t::value_type v;
    npl_eth_meter_profile_mapping_table_t::entry_pointer_type entry_ptr = nullptr;

    k.qos_id = qos_id;
    v.payloads.slp_qos_id = profile_id;
    v.action = NPL_ETH_METER_PROFILE_MAPPING_TABLE_ACTION_WRITE;

    return m_device->m_tables.eth_meter_profile_mapping_table[slice_id]->set(k, v, entry_ptr);
}

la_status
la_ingress_qos_profile_impl::set_ip_meter_profile_mapping_table(la_slice_id_t slice_id, uint64_t qos_id, uint64_t profile_id)
{
    npl_ip_meter_profile_mapping_table_t::key_type k;
    npl_ip_meter_profile_mapping_table_t::value_type v;
    npl_ip_meter_profile_mapping_table_t::entry_pointer_type entry_ptr = nullptr;

    k.qos_id = qos_id;
    v.payloads.slp_qos_id = profile_id;
    v.action = NPL_IP_METER_PROFILE_MAPPING_TABLE_ACTION_WRITE;

    return m_device->m_tables.ip_meter_profile_mapping_table[slice_id]->set(k, v, entry_ptr);
}

la_status
la_ingress_qos_profile_impl::set_meter_markdown_profile_mapping(uint64_t profile_id)
{
    la_status status = LA_STATUS_SUCCESS;
    auto slices = m_ifg_use_count->get_slices();
    for (auto slice_id : slices) {
        auto slice_pair = slice_id / 2;
        auto qos_id = m_slice_pair_data[slice_pair].qos_id;

        status = set_eth_meter_profile_mapping_table(slice_id, qos_id, profile_id);
        return_on_error(status);

        status = set_ip_meter_profile_mapping_table(slice_id, qos_id, profile_id);
        return_on_error(status);
    }
    return status;
}

la_status
la_ingress_qos_profile_impl::set_meter_markdown_profile(const la_meter_markdown_profile* meter_markdown_profile)
{
    start_api_call("meter_markdown_profile=", meter_markdown_profile);

    if (meter_markdown_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(meter_markdown_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_meter_markdown_profile == meter_markdown_profile) {
        return LA_STATUS_SUCCESS;
    }
    auto old_profile = m_meter_markdown_profile;

    auto meter_markdown_profile_impl = m_device->get_sptr<const la_meter_markdown_profile_impl>(meter_markdown_profile);
    uint64_t profile_id = meter_markdown_profile_impl->get_gid();

    m_device->add_object_dependency(meter_markdown_profile_impl, this);
    m_meter_markdown_profile = meter_markdown_profile_impl;

    la_status status = set_meter_markdown_profile_mapping(profile_id);
    return_on_error(status);

    if (old_profile) {
        m_device->remove_object_dependency(old_profile, this);
    }

    return status;
}

la_status
la_ingress_qos_profile_impl::get_meter_markdown_profile(const la_meter_markdown_profile*& out_meter_markdown_profile) const
{
    start_api_getter_call();

    if (m_meter_markdown_profile == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }
    out_meter_markdown_profile = m_meter_markdown_profile.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::clear_meter_markdown_profile()
{
    start_api_call("");

    if (m_meter_markdown_profile) {
        m_device->remove_object_dependency(m_meter_markdown_profile, this);
        m_meter_markdown_profile = nullptr;
    }

    la_status status = set_meter_markdown_profile_mapping(LA_RSVD_METER_MARKDOWN_PROFILE_ID);
    return_on_error(status);

    return status;
}

la_status
la_ingress_qos_profile_impl::add_ifg(la_slice_ifg ifg)
{
    la_status status = LA_STATUS_SUCCESS;
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
        la_acl_id_t qos_id = la_device_impl::ACL_INVALID_ID;

        bool allocated = m_device->m_index_generators.slice_pair[slice_pair].ingress_qos_profiles.allocate(qos_id);
        if (!allocated) {
            log_err(HLD, "Failed to allocate ingress qos profile in slice_pair: %d", slice_pair);
            txn.status = LA_STATUS_ERESOURCE;
            return txn.status;
        }

        txn.on_fail([=]() {
            la_slice_pair_id_t slice_pair = (ifg.slice / 2);
            m_device->m_index_generators.slice_pair[slice_pair].ingress_qos_profiles.release(m_slice_pair_data[slice_pair].qos_id);
            m_slice_pair_data[slice_pair].qos_id = la_device_impl::ACL_INVALID_ID;
        });

        m_slice_pair_data[slice_pair].qos_id = qos_id;

        // Program qos mapping tables for this new qos_id on this slice_pair
        txn.status = set_qos_mappings(slice_pair, qos_id);
        if (txn.status != LA_STATUS_SUCCESS) {
            return txn.status;
        }

        // Update ACL-s with relevant QoS ID-s
        for (auto& delegate : m_acls) {
            if (!delegate) {
                continue;
            }

            for (la_slice_pair_id_t slice_pair : m_device->get_used_slice_pairs()) {
                // Set ACL id. Must be done before tcam programming.
                delegate->set_qos_id(slice_pair, m_slice_pair_data[slice_pair].qos_id);
            }
        }
    }

    if (slice_added) {
        auto profile_id = LA_RSVD_METER_MARKDOWN_PROFILE_ID;
        if (m_meter_markdown_profile) {
            auto meter_markdown_profile_impl
                = m_meter_markdown_profile.weak_ptr_static_cast<const la_meter_markdown_profile_impl>();
            profile_id = meter_markdown_profile_impl->get_gid();
        }

        auto slice_pair = ifg.slice / 2;
        auto qos_id = m_slice_pair_data[slice_pair].qos_id;

        status = set_eth_meter_profile_mapping_table(ifg.slice, qos_id, profile_id);
        return_on_error(status);

        status = set_ip_meter_profile_mapping_table(ifg.slice, qos_id, profile_id);
        return_on_error(status);
    }

    // Notify users
    txn.status = m_device->notify_ifg_added(this, ifg);
    if (txn.status != LA_STATUS_SUCCESS) {
        return txn.status;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ingress_qos_profile_impl::remove_ifg(la_slice_ifg ifg)
{
    la_status status = LA_STATUS_SUCCESS;
    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);

    if (!ifg_removed) {
        return status;
    }

    if (slice_pair_removed) {
        la_slice_pair_id_t slice_pair = (ifg.slice / 2);
        m_device->m_index_generators.slice_pair[slice_pair].ingress_qos_profiles.release(m_slice_pair_data[slice_pair].qos_id);
        m_slice_pair_data[slice_pair].qos_id = la_device_impl::ACL_INVALID_ID;
    }

    // Notify users
    status = m_device->notify_ifg_removed(this, ifg);
    return_on_error(status);

    return status;
}

la_status
la_ingress_qos_profile_impl::notify_change(dependency_management_op op)
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
                "la_ingress_qos_profile_impl::notify_change received unsupported notification (%s)",
                silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

slice_ifg_vec_t
la_ingress_qos_profile_impl::get_ifgs() const
{
    return m_ifg_use_count->get_ifgs();
}

} // namespace silicon_one
