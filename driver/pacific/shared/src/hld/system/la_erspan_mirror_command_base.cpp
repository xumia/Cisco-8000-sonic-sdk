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

#include "system/la_erspan_mirror_command_base.h"
#include "npu/counter_utils.h"
#include "npu/la_counter_set_impl.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_svi_port_base.h"
#include "system/la_device_impl.h"
#include "system/la_spa_port_base.h"
#include "tm/la_unicast_tc_profile_impl.h"

#include "nplapi/npl_constants.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/la_ip_addr.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "lld/device_reg_structs.h"
#include "lld/device_tree.h"
#include "lld/ll_device.h"
#include <sstream>

namespace silicon_one
{

la_erspan_mirror_command_base::la_erspan_mirror_command_base(const la_device_impl_wptr& device)
    : m_device(device),
      m_mirror_gid(0),
      m_session_id(0),
      m_mac_addr(),
      m_source_mac_addr(),
      m_tunnel_dest_addr(),
      m_tunnel_source_addr(),
      m_ttl(0),
      m_dscp(),
      m_voq_offset(0),
      m_probability(1.0f),
      m_truncate(false)
{
}

la_erspan_mirror_command_base::~la_erspan_mirror_command_base()
{
}

la_status
la_erspan_mirror_command_base::initialize_common(la_uint_t mirror_gid)
{
    if (mirror_gid > la_device_impl::MAX_EGRESS_MIRROR_GID) {
        m_mirror_type = MIRROR_INGRESS;
        m_mirror_hw_id = mirror_gid - la_device_impl::MIRROR_GID_INGRESS_OFFSET;
    } else {
        m_mirror_type = MIRROR_EGRESS;
        m_mirror_hw_id = mirror_gid;
    }

    m_encap_ptr = m_mirror_type == MIRROR_EGRESS ? m_mirror_hw_id : m_mirror_hw_id + la_device_impl::MIRROR_GID_INGRESS_OFFSET;

    transaction txn;

    switch (m_mirror_type) {
    case MIRROR_INGRESS: {

        txn.status = configure_cud_entry(m_mirror_hw_id, m_mirror_gid, m_encap_ptr);
        return_on_error(txn.status);
        txn.on_fail([=]() { teardown_cud_entry(m_mirror_hw_id); });

        txn.status = configure_ibm_uc_cmd_to_encap_data_table(m_encap_ptr);
        return_on_error(txn.status);
        txn.on_fail([=]() { teardown_ibm_uc_cmd_to_encap_data_table(m_mirror_hw_id); });

        for (la_slice_id_t slice : get_slices(m_device, la_slice_mode_e::NETWORK)) {
            txn.status = configure_mirror_egress_attributes_table(slice, nullptr);
            return_on_error(txn.status);
            txn.on_fail([=]() { teardown_mirror_egress_attributes_table(slice); });
        }

        txn.status = m_device->configure_mirror_code_to_ibm(m_mirror_hw_id, m_mirror_hw_id);
        return_on_error(txn.status);
        txn.on_fail([=]() { m_device->clear_mirror_code_to_ibm(m_mirror_hw_id); });

        if (m_session_id == la_device_impl::MAX_ERSPAN_SESSION_ID) {
            bool dsp_mode = false;

            m_device->get_bool_property(la_device_property_e::DESTINATION_SYSTEM_PORT_IN_IBM_METADATA, dsp_mode);

            txn.status = configure_mirror_to_dsp_in_npu_soft_header_table(dsp_mode);
            return_on_error(txn.status);
            txn.on_fail([=]() { teardown_mirror_to_dsp_in_npu_soft_header_table(); });
        } else {
            txn.status = configure_mirror_to_dsp_in_npu_soft_header_table(0);
            return_on_error(txn.status);
            txn.on_fail([=]() { teardown_mirror_to_dsp_in_npu_soft_header_table(); });
        }

        break;
    }
    case MIRROR_EGRESS: {
        return LA_STATUS_ENOTIMPLEMENTED;
    }
    }

    txn.status = configure_redirect_encap(m_encap_ptr, 1 /* is_rx_redirect */);
    return_on_error(txn.status);
    txn.on_fail([=]() { m_device->clear_redirect_eth_encap(m_encap_ptr); });

    txn.status = configure_punt_tunnel_transport_encap_table(m_encap_ptr);
    return_on_error(txn.status);
    txn.on_fail([=]() { teardown_punt_tunnel_transport_encap_table(m_encap_ptr); });

    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::initialize(la_object_id_t oid,
                                          type_e type,
                                          la_mirror_gid_t mirror_gid,
                                          la_erspan_session_id_t session_id,
                                          la_mac_addr_t mac_addr,
                                          la_mac_addr_t source_mac_addr,
                                          la_vlan_tag_t vlan_tag,
                                          la_ip_addr tunnel_dest_addr,
                                          la_ip_addr tunnel_source_addr,
                                          la_uint_t ttl,
                                          la_ip_dscp dscp,
                                          la_uint_t voq_offset,
                                          const la_system_port* dsp,
                                          double probability,
                                          la_ip_version_e ip_version)
{
    m_oid = oid;

    if (m_dsp != nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (session_id >= la_device_impl::MAX_ERSPAN_SESSION_ID) {
        return LA_STATUS_EINVAL;
    }

    // Check the offset value against the Number of OQs. For ERSPAN rate-limiting,
    // this value is expected to be directly added to the base voq.
    if (voq_offset >= NUM_OQ_PER_PIF) {
        return LA_STATUS_EINVAL;
    }

    la_status status = verify_parameters(dsp);
    return_on_error(status);

    m_mirror_gid = mirror_gid;
    m_type = type;
    m_session_id = session_id;
    m_mac_addr.flat = mac_addr.flat;
    m_source_mac_addr.flat = source_mac_addr.flat;
    m_vlan_tag = vlan_tag;
    m_ip_version = ip_version;
    m_tunnel_dest_addr = tunnel_dest_addr;
    m_tunnel_source_addr = tunnel_source_addr;
    m_ttl = ttl;
    m_dscp.value = dscp.value;
    m_voq_offset = voq_offset;
    m_dsp = m_device->get_sptr(dsp);
    m_probability = probability;

    status = set_probability(probability);
    return_on_error(status);

    status = initialize_common(m_mirror_gid);
    return_on_error(status);

    // Update object dependencies
    m_device->add_object_dependency(dsp, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::initialize(la_object_id_t oid,
                                          type_e type,
                                          la_mirror_gid_t mirror_gid,
                                          la_mac_addr_t mac_addr,
                                          la_mac_addr_t source_mac_addr,
                                          la_vlan_tag_t vlan_tag,
                                          la_ip_addr tunnel_dest_addr,
                                          la_ip_addr tunnel_source_addr,
                                          la_uint_t ttl,
                                          la_ip_dscp dscp,
                                          la_uint16_t sport,
                                          la_uint16_t dport,
                                          la_uint_t voq_offset,
                                          const la_system_port* dsp,
                                          double probability,
                                          la_ip_version_e ip_version)
{
    m_oid = oid;

    if (m_dsp != nullptr) {
        return LA_STATUS_EINVAL;
    }

    // Check the offset value against the Number of OQs. For ERSPAN rate-limiting,
    // this value is expected to be directly added to the base voq.
    if (voq_offset >= NUM_OQ_PER_PIF) {
        return LA_STATUS_EINVAL;
    }

    la_status status = verify_parameters(dsp);
    return_on_error(status);

    m_mirror_gid = mirror_gid;
    m_type = type;
    m_session_id = la_device_impl::MAX_ERSPAN_SESSION_ID;
    m_mac_addr.flat = mac_addr.flat;
    m_source_mac_addr.flat = source_mac_addr.flat;
    m_vlan_tag = vlan_tag;
    m_ip_version = ip_version;
    m_tunnel_dest_addr = tunnel_dest_addr;
    m_tunnel_source_addr = tunnel_source_addr;
    m_ttl = ttl;
    m_dscp.value = dscp.value;
    m_sport = sport;
    m_dport = dport;
    m_voq_offset = voq_offset;
    m_dsp = m_device->get_sptr(dsp);
    m_probability = probability;

    status = set_probability(probability);
    return_on_error(status);

    status = initialize_common(m_mirror_gid);
    return_on_error(status);

    // Update object dependencies
    m_device->add_object_dependency(dsp, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::destroy()
{
    if (m_dsp == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_status status;

    switch (m_mirror_type) {
    case MIRROR_INGRESS: {
        status = teardown_mirror_to_dsp_in_npu_soft_header_table();
        return_on_error(status);

        status = teardown_cud_entry(m_mirror_hw_id);
        return_on_error(status);

        status = teardown_ibm_uc_cmd_to_encap_data_table(m_encap_ptr);
        return_on_error(status);

        status = m_device->clear_mirror_code_to_ibm(m_mirror_hw_id);
        return_on_error(status);

        break;
    }
    case MIRROR_EGRESS: {
        return LA_STATUS_ENOTIMPLEMENTED;
    }
    default:
        break;
    }

    status = teardown_punt_tunnel_transport_encap_table(m_encap_ptr);
    return_on_error(status);

    // only when egress attributes like counters are set, egress_attributes_table
    // entries need to be tore down.
    if (m_counter != nullptr) {
        for (la_slice_id_t slice : get_slices(m_device, la_slice_mode_e::NETWORK)) {
            la_status status = teardown_mirror_egress_attributes_table(slice);
            return_on_error(status);
        }
    }

    status = remove_erspan_session_counter();
    return_on_error(status);

    // Remove object dependencies
    m_device->remove_object_dependency(m_dsp, this);

    m_dsp = nullptr;

    return LA_STATUS_SUCCESS;
}

la_mirror_gid_t
la_erspan_mirror_command_base::get_gid() const
{
    return m_mirror_gid;
}

la_object::object_type_e
la_erspan_mirror_command_base::type() const
{
    return object_type_e::ERSPAN_MIRROR_COMMAND;
}

const la_device*
la_erspan_mirror_command_base::get_device() const
{
    return m_device.get();
}

std::string
la_erspan_mirror_command_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_erspan_mirror_command_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_erspan_mirror_command_base::oid() const
{
    return m_oid;
}

la_status
la_erspan_mirror_command_base::verify_parameters(const la_system_port* dsp) const
{
    if (m_dsp.get() == dsp) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = verify_dsp(dsp);

    return status;
}

la_status
la_erspan_mirror_command_base::verify_dsp(const la_system_port* dsp) const
{
    if (dsp == nullptr) {
        log_err(HLD, "%s: NULL DSP", __func__);
        return LA_STATUS_EINVAL;
    }

    const la_system_port_base* dspi = static_cast<const la_system_port_base*>(dsp);
    la_system_port_base::port_type_e dsp_type = dspi->get_port_type();
    if ((dsp_type != la_system_port_base::port_type_e::MAC) && (dsp_type != la_system_port_base::port_type_e::REMOTE)) {
        log_err(HLD, "%s: DSP type %s is not supported", __func__, silicon_one::to_string(dsp_type).c_str());
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_erspan_session_id_t
la_erspan_mirror_command_base::get_session_id() const
{
    start_api_getter_call();

    return m_session_id;
}

la_status
la_erspan_mirror_command_base::set_mac(la_mac_addr_t mac_addr)
{
    start_api_call("mac_addr=", mac_addr);

    if (m_mac_addr.flat == mac_addr.flat) {
        return LA_STATUS_SUCCESS;
    }

    la_mac_addr_t old_mac_addr;

    old_mac_addr.flat = m_mac_addr.flat;
    m_mac_addr.flat = mac_addr.flat;

    la_status status = configure_redirect_encap(m_mirror_gid, 1 /* is_rx_redirect */);
    if (status != LA_STATUS_SUCCESS) {
        m_mac_addr.flat = old_mac_addr.flat;
    }

    return status;
}

la_status
la_erspan_mirror_command_base::get_mac(la_mac_addr_t& out_mac_addr) const
{
    start_api_getter_call();
    out_mac_addr.flat = m_mac_addr.flat;
    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::set_source_mac(la_mac_addr_t mac_addr)
{
    start_api_call("mac_addr=", mac_addr);

    if (m_source_mac_addr.flat == mac_addr.flat) {
        return LA_STATUS_SUCCESS;
    }

    la_mac_addr_t old_mac_addr;

    old_mac_addr.flat = m_source_mac_addr.flat;
    m_source_mac_addr.flat = mac_addr.flat;

    la_status status = configure_redirect_encap(m_encap_ptr, 1 /* is_rx_redirect */);
    if (status != LA_STATUS_SUCCESS) {
        m_source_mac_addr.flat = old_mac_addr.flat;
    }

    return status;
}

la_status
la_erspan_mirror_command_base::get_source_mac(la_mac_addr_t& out_mac_addr) const
{
    start_api_getter_call();
    out_mac_addr.flat = m_source_mac_addr.flat;
    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::set_egress_vlan_tag(la_vlan_tag_t vlan_tag)
{
    start_api_call("vlan_tag=", vlan_tag);

    if (is_vlan_tag_eq(m_vlan_tag, vlan_tag)) {
        return LA_STATUS_SUCCESS;
    }

    la_vlan_tag_t old_vlan_tag;

    old_vlan_tag = m_vlan_tag;
    m_vlan_tag = vlan_tag;

    // Configure encapsulation of the mirror command
    la_status status = configure_cud_entry(m_mirror_hw_id, m_mirror_gid, m_encap_ptr);
    if (status != LA_STATUS_SUCCESS) {
        m_vlan_tag = old_vlan_tag;
        return status;
    }

    status = configure_ibm_uc_cmd_to_encap_data_table(m_encap_ptr);
    if (status != LA_STATUS_SUCCESS) {
        m_vlan_tag = old_vlan_tag;
        return status;
    }

    status = configure_redirect_encap(m_encap_ptr, 1 /* is_rx_redirect */);
    if (status != LA_STATUS_SUCCESS) {
        m_vlan_tag = old_vlan_tag;
    }

    return status;
}

la_status
la_erspan_mirror_command_base::get_egress_vlan_tag(la_vlan_tag_t& out_vlan_tag) const
{
    start_api_getter_call();
    out_vlan_tag = m_vlan_tag;
    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::set_tunnel_destination(la_ip_addr ip_addr)
{
    start_api_call("ip_addr=", ip_addr);
    if (m_tunnel_dest_addr == ip_addr) {
        return LA_STATUS_SUCCESS;
    }
    la_ip_addr old_ip_addr = m_tunnel_dest_addr;
    m_tunnel_dest_addr = ip_addr;
    la_status status = configure_punt_tunnel_transport_encap_table(m_mirror_gid);
    if (status != LA_STATUS_SUCCESS) {
        m_tunnel_dest_addr = old_ip_addr;
    }
    return status;
}

la_ip_addr
la_erspan_mirror_command_base::get_tunnel_destination() const
{
    start_api_getter_call();
    return m_tunnel_dest_addr;
}

la_status
la_erspan_mirror_command_base::set_tunnel_source(la_ip_addr ip_addr)
{
    start_api_call("ip_addr=", ip_addr);
    if (m_tunnel_source_addr == ip_addr) {
        return LA_STATUS_SUCCESS;
    }
    la_ip_addr old_ip_addr = m_tunnel_source_addr;
    m_tunnel_source_addr = ip_addr;
    la_status status = configure_punt_tunnel_transport_encap_table(m_mirror_gid);
    if (status != LA_STATUS_SUCCESS) {
        m_tunnel_source_addr = old_ip_addr;
    }

    return status;
}

la_ip_addr
la_erspan_mirror_command_base::get_tunnel_source() const
{
    start_api_getter_call();
    return m_tunnel_source_addr;
}

la_status
la_erspan_mirror_command_base::set_ttl(la_uint_t ttl)
{
    start_api_call("ttl=", ttl);

    if (m_ttl == ttl) {
        return LA_STATUS_SUCCESS;
    }

    la_uint_t old_ttl = m_ttl;

    m_ttl = ttl;
    la_status status = configure_punt_tunnel_transport_encap_table(m_mirror_gid);
    if (status != LA_STATUS_SUCCESS) {
        m_ttl = old_ttl;
    }

    return status;
}

la_uint_t
la_erspan_mirror_command_base::get_ttl() const
{
    start_api_getter_call();
    return m_ttl;
}

la_status
la_erspan_mirror_command_base::set_dscp(la_ip_dscp dscp)
{
    start_api_call("dscp=", dscp);

    if (m_dscp.value == dscp.value) {
        return LA_STATUS_SUCCESS;
    }

    la_ip_dscp old_dscp;
    old_dscp.value = m_dscp.value;

    m_dscp.value = dscp.value;
    la_status status = configure_punt_tunnel_transport_encap_table(m_mirror_gid);
    if (status != LA_STATUS_SUCCESS) {
        m_dscp.value = old_dscp.value;
    }

    return status;
}

la_ip_dscp
la_erspan_mirror_command_base::get_dscp() const
{
    start_api_getter_call();
    return m_dscp;
}

la_status
la_erspan_mirror_command_base::set_source_port(la_uint16_t sport)
{
    start_api_call("sport=", sport);

    if (m_type != type_e::SFLOW_TUNNEL) {
        return LA_STATUS_EINVAL;
    }

    la_uint16_t old_sport;
    old_sport = m_sport;

    m_sport = sport;
    la_status status = configure_punt_tunnel_transport_encap_table(m_mirror_gid);
    if (status != LA_STATUS_SUCCESS) {
        m_sport = old_sport;
    }

    return status;
}

la_status
la_erspan_mirror_command_base::get_source_port(la_uint16_t& out_sport) const
{
    start_api_getter_call();

    if (m_type != type_e::SFLOW_TUNNEL) {
        return LA_STATUS_EINVAL;
    }

    out_sport = m_sport;
    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::set_destination_port(la_uint16_t dport)
{
    start_api_call("dport=", dport);

    if (m_type != type_e::SFLOW_TUNNEL) {
        return LA_STATUS_EINVAL;
    }

    la_uint16_t old_dport;
    old_dport = m_dport;

    m_dport = dport;
    la_status status = configure_punt_tunnel_transport_encap_table(m_mirror_gid);
    if (status != LA_STATUS_SUCCESS) {
        m_dport = old_dport;
    }

    return status;
}

la_status
la_erspan_mirror_command_base::get_destination_port(la_uint16_t& out_dport) const
{
    start_api_getter_call();

    if (m_type != type_e::SFLOW_TUNNEL) {
        return LA_STATUS_EINVAL;
    }

    out_dport = m_dport;
    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::set_voq_offset(la_uint_t voq_offset)
{
    start_api_call("voq_offset=", voq_offset);

    // Check the offset value against the Number of OQs. For ERSPAN rate-limiting,
    // this value is expected to be directly added to the base voq.
    if (voq_offset >= NUM_OQ_PER_PIF) {
        return LA_STATUS_EINVAL;
    }

    if (m_voq_offset == voq_offset) {
        return LA_STATUS_SUCCESS;
    }

    la_traffic_class_t old_voq_offset = m_voq_offset;

    m_voq_offset = voq_offset;
    la_status status = do_set_probability(m_probability);
    if (status != LA_STATUS_SUCCESS) {
        m_voq_offset = old_voq_offset;
    }

    return status;
}

la_uint_t
la_erspan_mirror_command_base::get_voq_offset() const
{
    start_api_getter_call();
    return m_voq_offset;
}

la_status
la_erspan_mirror_command_base::add_erspan_session_counter(la_counter_set* counter)
{
    if (counter == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    if (!of_same_device(counter, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    size_t counter_set_size = counter->get_set_size();
    if (counter_set_size != 1) {
        return LA_STATUS_EINVAL;
    }

    la_counter_set* prev_counter = m_counter.get();
    if (counter == prev_counter) {
        return LA_STATUS_SUCCESS;
    }

    la_counter_set_impl* counter_impl = static_cast<la_counter_set_impl*>(counter);
    la_status status = counter_impl->add_erspan_session_counter();
    return_on_error(status);

    m_device->add_object_dependency(counter_impl, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::remove_erspan_session_counter()
{
    la_counter_set* counter = m_counter.get();

    if (counter == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    la_counter_set_impl* counter_impl = static_cast<la_counter_set_impl*>(counter);
    m_device->remove_object_dependency(counter_impl, this);

    la_status status = counter_impl->remove_erspan_session_counter();
    return_on_error(status);

    m_counter = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::do_set_counter(la_counter_set* counter)
{
    la_status status = add_erspan_session_counter(counter);
    return_on_error(status);

    for (la_slice_id_t slice : get_slices(m_device, la_slice_mode_e::NETWORK)) {
        status = configure_mirror_egress_attributes_table(slice, counter);
        if (status != LA_STATUS_SUCCESS) {
            remove_erspan_session_counter();
        }
        return_on_error(status);
    }

    // Remove the previous counter
    la_counter_or_meter_set* prev_counter = m_counter.get();
    if (prev_counter != counter) {
        la_status status = remove_erspan_session_counter();
        return_on_error(status);
    }

    m_counter = m_device->get_sptr(counter);

    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::set_counter(la_counter_set* counter)
{
    start_api_call("counter=", counter);

    return do_set_counter(counter);
}

la_status
la_erspan_mirror_command_base::get_counter(la_counter_set*& out_counter) const
{
    start_api_getter_call();

    out_counter = m_counter.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::set_egress_port(const la_system_port* dsp)
{
    start_api_call("dsp=", dsp);

    la_status status = verify_parameters(dsp);
    return_on_error(status);

    auto old_dsp = m_dsp;

    m_dsp = m_device->get_sptr(dsp);

    status = set_probability(m_probability);
    if (status != LA_STATUS_SUCCESS) {
        m_dsp = old_dsp;
        return status;
    }

    // Configure encapsulation of the mirror command
    status = configure_cud_entry(m_mirror_hw_id, m_mirror_gid, m_encap_ptr);
    if (status != LA_STATUS_SUCCESS) {
        m_dsp = old_dsp;
        return status;
    }

    status = configure_ibm_uc_cmd_to_encap_data_table(m_encap_ptr);
    if (status != LA_STATUS_SUCCESS) {
        m_dsp = old_dsp;
        return status;
    }

    status = configure_redirect_encap(m_encap_ptr, 1 /* is_rx_redirect */);
    if (status != LA_STATUS_SUCCESS) {
        m_dsp = old_dsp;
        return status;
    }

    // Clear object dependencies
    m_device->remove_object_dependency(old_dsp, this);

    // Update object dependencies
    m_device->add_object_dependency(m_dsp, this);

    return LA_STATUS_SUCCESS;
}

const la_system_port*
la_erspan_mirror_command_base::get_system_port() const
{
    start_api_getter_call();
    return m_dsp.get();
}

la_status
la_erspan_mirror_command_base::set_probability(double probability)
{
    start_api_call("probability=", probability);

    if ((probability < 0.0) || (probability > 1.0f)) {
        return LA_STATUS_EINVAL;
    }

    la_status status = do_set_probability(probability);
    return_on_error(status);

    m_probability = probability;

    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::get_probability(double& out_probability) const
{
    out_probability = m_probability;

    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::do_set_probability(double probability)
{
    la_uint_t sampling_rate = probability * (MIRROR_SAMPLING_SPACE_SIZE - 1);
    return configure_ibm_command_table(sampling_rate);
}

bool
la_erspan_mirror_command_base::get_truncate(void) const
{
    return m_truncate;
}

la_status
la_erspan_mirror_command_base::teardown_ibm_uc_cmd_to_encap_data_table(la_uint_t encap_ptr)
{
    npl_ibm_uc_cmd_to_encap_data_table_t::key_type k;
    k.tx_fabric_tx_cud_4_0_ = encap_ptr;

    const auto& tables(m_device->m_tables.ibm_uc_cmd_to_encap_data_table);
    la_status status = per_slice_tables_erase(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k);

    return status;
}

la_status
la_erspan_mirror_command_base::configure_ibm_uc_cmd_to_encap_data_table(la_uint_t key)
{
    npl_ibm_uc_cmd_to_encap_data_table_t::key_type k;
    npl_ibm_uc_cmd_to_encap_data_table_t::value_type v;

    k.tx_fabric_tx_cud_4_0_ = key;
    v.action = NPL_IBM_UC_CMD_TO_ENCAP_DATA_TABLE_ACTION_WRITE;

    npl_punt_encap_data_t& punt_encap_data(v.payloads.ibm_uc_fabric_encap.punt_encap_data);
    la_status status = populate_punt_encap_data(key, punt_encap_data, m_encap_ptr);
    return_on_error(status);

    const auto& tables(m_device->m_tables.ibm_uc_cmd_to_encap_data_table);
    status = per_slice_tables_set(m_device->m_slice_mode, tables, {la_slice_mode_e::CARRIER_FABRIC}, k, v);

    return status;
}

la_status
la_erspan_mirror_command_base::configure_redirect_encap(uint64_t encap_ptr, int is_rx_redirect) const
{
    return m_device->configure_redirect_eth_encap(encap_ptr, m_mac_addr, m_source_mac_addr, m_vlan_tag.tci);
}

la_status
la_erspan_mirror_command_base::configure_mirror_egress_attributes_table(la_slice_id_t slice, la_counter_set* counter)
{
    npl_mirror_egress_attributes_table_t::key_type k;
    npl_mirror_egress_attributes_table_t::value_type v;
    npl_mirror_egress_attributes_table_t::entry_pointer_type e = nullptr;

    k.mirror_code = m_mirror_gid;
    k.is_ibm.val = NPL_TRUE_VALUE;
    v.payloads.set_mirror_egress_attributes.session_id = m_session_id;
    v.payloads.set_mirror_egress_attributes.counter
        = populate_counter_ptr_slice(m_device->get_sptr(counter), slice, COUNTER_DIRECTION_EGRESS);

    la_status status = m_device->m_tables.mirror_egress_attributes_table[slice]->set(k, v, e);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::teardown_mirror_egress_attributes_table(la_slice_id_t slice)
{
    npl_mirror_egress_attributes_table_t::key_type k;

    k.mirror_code = m_mirror_gid;
    k.is_ibm.val = NPL_TRUE_VALUE;

    la_status status = m_device->m_tables.mirror_egress_attributes_table[slice]->erase(k);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::configure_punt_tunnel_transport_encap_table(uint64_t encap_ptr)
{
    la_status status;
    npl_punt_tunnel_transport_encap_table_t::key_type k;
    npl_punt_tunnel_transport_encap_table_t::value_type v;
    npl_punt_tunnel_transport_encap_table_t::entry_pointer_type e = nullptr;

    k.punt_nw_encap_ptr.ptr = encap_ptr;
    v.payloads.ip_gre.tos = m_dscp.value << 2;
    if (m_ip_version == la_ip_version_e::IPV4) {
        la_ipv4_addr_t src_v4 = m_tunnel_source_addr.to_v4();
        la_ipv4_addr_t dst_v4 = m_tunnel_dest_addr.to_v4();
        v.payloads.ip_gre.ip_encap_data.ip.v4.ene_ipv4_sip_dip.sip = src_v4.s_addr;
        v.payloads.ip_gre.ip_encap_data.ip.v4.ene_ipv4_sip_dip.dip = dst_v4.s_addr;
        v.payloads.ip_gre.ip_encap_data.ip.v4.ene_ttl_and_protocol.ttl = m_ttl;
    } else {
        la_ipv6_addr_t src_v6 = m_tunnel_source_addr.to_v6();
        la_ipv6_addr_t dst_v6 = m_tunnel_dest_addr.to_v6();
        v.payloads.ip_gre.ip_encap_data.ip.v6.ene_nh_and_hl.hop_limit = m_ttl;

        npl_punt_tunnel_transport_extended_encap_table_t::key_type extended_k;
        npl_punt_tunnel_transport_extended_encap_table_t::value_type extended_v;
        npl_punt_tunnel_transport_extended_encap_table_t::entry_pointer_type extended_e = nullptr;
        extended_k.punt_nw_encap_ptr.ptr = encap_ptr;

        v.payloads.ip_gre.ip_encap_data.ip.v6.ene_ipv6_sip_msb = src_v6.s_addr >> 64;
        extended_v.payloads.extended_encap_data.ene_ipv6_dip_msb[0]
            = (dst_v6.s_addr >> 48) & ((static_cast<la_uint128_t>(1) << 64) - 1);
        extended_v.payloads.extended_encap_data.ene_ipv6_dip_msb[1] = dst_v6.s_addr >> 112;

        status = m_device->m_tables.punt_tunnel_transport_extended_encap_table->set(extended_k, extended_v, extended_e);
        return_on_error(status);

        npl_punt_tunnel_transport_extended_encap_table2_t::key_type extended_k2;
        npl_punt_tunnel_transport_extended_encap_table2_t::value_type extended_v2;
        npl_punt_tunnel_transport_extended_encap_table2_t::entry_pointer_type extended_e2 = nullptr;
        extended_k2.punt_nw_encap_ptr.ptr = encap_ptr;

        extended_v2.payloads.extended_encap_data2.ene_ipv6_dip_lsb = (dst_v6.s_addr) & ((static_cast<la_uint128_t>(1) << 48) - 1);

        status = m_device->m_tables.punt_tunnel_transport_extended_encap_table2->set(extended_k2, extended_v2, extended_e2);
        return_on_error(status);
    }

    if (m_type == type_e::SFLOW_TUNNEL) {
        if (m_ip_version == la_ip_version_e::IPV4) {
            v.payloads.ip_gre.ip_encap_data.ip.v4.ene_ttl_and_protocol.protocol = static_cast<uint64_t>(la_l4_protocol_e::UDP);
        } else {
            v.payloads.ip_gre.ip_encap_data.ip.v6.ene_nh_and_hl.next_header = static_cast<uint64_t>(la_l4_protocol_e::UDP);
        }
        v.payloads.ip_gre.ip_encap_data.upper_layer.udp_data.sport = m_sport;
        v.payloads.ip_gre.ip_encap_data.upper_layer.udp_data.dport = m_dport;
    } else {
        if (m_ip_version == la_ip_version_e::IPV4) {
            v.payloads.ip_gre.ip_encap_data.ip.v4.ene_ttl_and_protocol.protocol = static_cast<uint64_t>(la_l4_protocol_e::GRE);
        } else {
            v.payloads.ip_gre.ip_encap_data.ip.v6.ene_nh_and_hl.next_header = static_cast<uint64_t>(la_l4_protocol_e::GRE);
        }
        v.payloads.ip_gre.ip_encap_data.upper_layer.gre_data.proto = NPL_ETHER_TYPE_ERSPAN_II;
        v.payloads.ip_gre.ip_encap_data.upper_layer.gre_data.flag_res_version = 0x1000;
    }

    status = m_device->m_tables.punt_tunnel_transport_encap_table->set(k, v, e);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::teardown_punt_tunnel_transport_encap_table(uint64_t code)
{
    npl_punt_tunnel_transport_encap_table_t::key_type k;

    k.punt_nw_encap_ptr.ptr = code;

    la_status status = m_device->m_tables.punt_tunnel_transport_encap_table->erase(k);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_erspan_mirror_command_base::notify_change(dependency_management_op op)
{
    switch (op.type_e) {
    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT:
    default:
        log_err(HLD, "received unsupported notification (%s)", silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

mirror_type_e
la_erspan_mirror_command_base::get_mirror_type() const
{
    return m_mirror_type;
}
}
