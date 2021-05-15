// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "la_ip_over_ip_tunnel_port_impl.h"

#include "api_tracer.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "counter_utils.h"
#include "hld_types.h"
#include "la_strings.h"
#include "la_vrf_impl.h"
#include "npu/la_vrf_port_common_base.h"
#include "qos/la_egress_qos_profile_impl.h"
#include "qos/la_ingress_qos_profile_impl.h"
#include "resolution_utils.h"
#include "system/la_device_impl.h"

#include <sstream>

namespace silicon_one
{

la_ip_over_ip_tunnel_port_impl::la_ip_over_ip_tunnel_port_impl(const la_device_impl_wptr& device)
    : m_device(device),
      m_lp_attribute_inheritance_mode(la_lp_attribute_inheritance_mode_e::PORT),
      m_ttl(255),
      m_decrement_inner_ttl(true),
      m_encap_qos_mode(la_tunnel_encap_qos_mode_e::UNIFORM),
      m_vrf_port_common(),
      m_dip_entropy_mode(la_ip_tunnel_dip_entropy_mode_e::IP_TUNNEL_DIP_ENTROPY_NONE),
      m_npl_dip_entropy_mode(NPL_GRE_DIP_ENTROPY_NONE),
      m_slice_data(ASIC_MAX_SLICES_PER_DEVICE_NUM, slice_data()),
      m_slice_pair_data(NUM_SLICE_PAIRS_PER_DEVICE, slice_pair_data())
{
    m_encap_tos.flat = 0;
}

la_ip_over_ip_tunnel_port_impl::~la_ip_over_ip_tunnel_port_impl()
{
}

la_status
la_ip_over_ip_tunnel_port_impl::ipv4_tunnel_add(const la_vrf_impl_wcptr& underlay_vrf,
                                                la_ipv4_prefix_t local_ip_prefix,
                                                la_ipv4_addr_t remote_ip_addr,
                                                const la_l3_port_wptr& port)
{
    la_status status;
    la_device_impl::ipv4_tunnel_id_t tun_id;

    // set tunnel ID
    tun_id.local_ip_prefix = local_ip_prefix;
    tun_id.remote_ip_prefix.addr = remote_ip_addr;
    tun_id.remote_ip_prefix.length = 32;
    tun_id.vrf_gid = underlay_vrf->get_gid();
    tun_id.tunnel_type = NPL_IP_TUNNEL_IP_IN_IP;

    // search for tunnel ID in device tunnel map
    auto it = m_device->m_ipv4_tunnel_map.find(tun_id);

    if (it != m_device->m_ipv4_tunnel_map.end()) {
        return LA_STATUS_EEXIST;
    }

    // add port to device tunnel map if not already present
    m_device->m_ipv4_tunnel_map[tun_id] = port;

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::ipv4_tunnel_remove(const la_vrf_impl_wcptr& underlay_vrf,
                                                   la_ipv4_prefix_t local_ip_prefix,
                                                   la_ipv4_addr_t remote_ip_addr,
                                                   const la_l3_port_wptr& port)
{
    la_status status;
    la_device_impl::ipv4_tunnel_id_t tun_id;

    // set tunnel ID
    tun_id.local_ip_prefix = local_ip_prefix;
    tun_id.remote_ip_prefix.addr = remote_ip_addr;
    tun_id.remote_ip_prefix.length = 32;
    tun_id.vrf_gid = underlay_vrf->get_gid();
    tun_id.tunnel_type = NPL_IP_TUNNEL_IP_IN_IP;

    // search for tunnel ID in device tunnel map
    auto it = m_device->m_ipv4_tunnel_map.find(tun_id);

    if (it == m_device->m_ipv4_tunnel_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    if (it->second != port) {
        return LA_STATUS_EINVAL;
    }

    // remove port from device tunnel map if found
    m_device->m_ipv4_tunnel_map.erase(tun_id);

    return LA_STATUS_SUCCESS;
}

la_l3_port_wptr
la_ip_over_ip_tunnel_port_impl::ipv4_tunnel_search(const la_vrf_impl_wcptr& underlay_vrf,
                                                   la_ipv4_prefix_t local_ip_prefix,
                                                   la_ipv4_addr_t remote_ip_addr)
{
    la_device_impl::ipv4_tunnel_id_t tun_id;

    // set tunnel ID
    tun_id.local_ip_prefix = local_ip_prefix;
    tun_id.remote_ip_prefix.addr = remote_ip_addr;
    tun_id.remote_ip_prefix.length = 32;
    tun_id.vrf_gid = underlay_vrf->get_gid();
    tun_id.tunnel_type = NPL_IP_TUNNEL_IP_IN_IP;

    // search for tunnel ID in device tunnel map
    auto it = m_device->m_ipv4_tunnel_map.find(tun_id);

    if (it == m_device->m_ipv4_tunnel_map.end()) {
        return nullptr;
    }

    return (it->second);
}

la_status
la_ip_over_ip_tunnel_port_impl::initialize(la_object_id_t oid,
                                           la_l3_port_gid_t gid,
                                           la_ip_tunnel_mode_e tunnel_mode,
                                           const la_vrf* underlay_vrf,
                                           la_ipv4_prefix_t prefix,
                                           la_ipv4_addr_t ip_addr,
                                           const la_vrf* vrf,
                                           la_ingress_qos_profile_impl* ingress_qos_profile_impl,
                                           la_egress_qos_profile_impl* egress_qos_profile_impl)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    m_oid = oid;
    if (vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (underlay_vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(vrf, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (!of_same_device(underlay_vrf, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    la_status status = m_device->create_vrf_port_common(m_device->get_sptr(this), m_vrf_port_common);
    return_on_error(status);

    la_uint32_t prefix_mask = bit_utils::get_range_mask(bit_utils::BITS_IN_UINT32 - prefix.length, prefix.length);
    prefix.addr.s_addr &= prefix_mask;

    auto underlay_vrf_sptr = m_device->get_sptr<const la_vrf_impl>(underlay_vrf);
    if (ipv4_tunnel_search(underlay_vrf_sptr, prefix, ip_addr) != nullptr) {
        return LA_STATUS_EEXIST;
    }

    m_gid = gid;
    m_tunnel_mode = tunnel_mode;
    m_underlay_vrf = underlay_vrf_sptr;
    m_ip_addr = ip_addr;
    m_prefix = prefix;
    m_vrf = m_device->get_sptr<const la_vrf_impl>(vrf);

    m_addl_l3_lp_attributes.load_balance_profile = NPL_LB_PROFILE_IP;
    m_addl_l3_lp_attributes.enable_monitor = 0;
    m_addl_l3_lp_attributes.slp_based_fwd_and_per_vrf_mpls_fwd.slp_based_forwarding = 0;
    m_addl_l3_lp_attributes.slp_based_fwd_and_per_vrf_mpls_fwd.per_vrf_mpls_fwd = 0;
    m_addl_l3_lp_attributes.qos_id = 0;

    // allocate compressed index for the local prefix
    status = m_device->m_ipv4_sip_index_manager->allocate_sip_index(m_prefix, m_my_ipv4_index);
    return_on_error(status);

    la_mac_addr_t mac_addr;
    mac_addr.flat = 0;

    status = m_vrf_port_common->initialize(gid,
                                           mac_addr,
                                           nullptr /* sw */,
                                           m_vrf,
                                           m_device->get_sptr(ingress_qos_profile_impl),
                                           m_device->get_sptr(egress_qos_profile_impl));
    return_on_error(status);

    slice_ifg_vec_t slice_ifgs = get_ifgs();
    for (auto ifg : slice_ifgs) {
        status = add_ifg(ifg);
        return_on_error(status);
    }

    status = add_tunnel_endpoint();
    return_on_error(status);

    status = ipv4_tunnel_add(m_underlay_vrf, prefix, ip_addr, m_device->get_sptr(this));
    return_on_error(status, HLD, ERROR, "failed to add ipv4 tunnel");

    register_vrf_dependency(m_underlay_vrf);
    register_vrf_dependency(m_vrf);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    la_status status = remove_tunnel_endpoint();
    return_on_error(status);

    auto ifgs = m_ifg_use_count->get_ifgs();

    for (la_slice_ifg ifg : ifgs) {
        status = remove_ifg(ifg);
        return_on_error(status);
    }

    status = m_vrf_port_common->destroy();
    return_on_error(status);

    status = m_device->m_ipv4_sip_index_manager->free_sip_index(m_my_ipv4_index);
    return_on_error(status);

    status = ipv4_tunnel_remove(m_underlay_vrf, m_prefix, m_ip_addr, m_device->get_sptr(this));
    return_on_error(status, HLD, ERROR, "failed to remove ipv4 tunnel");

    deregister_vrf_dependency(m_vrf);
    deregister_vrf_dependency(m_underlay_vrf);

    m_vrf = nullptr;
    m_underlay_vrf = nullptr;

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_ip_over_ip_tunnel_port_impl::type() const
{
    return la_object::object_type_e::IP_OVER_IP_TUNNEL_PORT;
}

std::string
la_ip_over_ip_tunnel_port_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_ip_over_ip_tunnel_port_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_ip_over_ip_tunnel_port_impl::oid() const
{
    return m_oid;
}

const la_device*
la_ip_over_ip_tunnel_port_impl::get_device() const
{
    return m_device.get();
}

la_l3_port_gid_t
la_ip_over_ip_tunnel_port_impl::get_gid() const
{
    return m_gid;
}

la_status
la_ip_over_ip_tunnel_port_impl::add_tunnel_endpoint()
{
    // for encap only we do not need to update the termination tables
    if (m_tunnel_mode == la_ip_tunnel_mode_e::ENCAP_ONLY) {
        return LA_STATUS_SUCCESS;
    }

    if (m_ip_addr.s_addr == LA_IPV4_ANY_IP.s_addr) {
        // add_local_ep_entry
        la_status status = m_device->m_ipv4_tunnel_ep_manager->add_local_ep_entry(
            m_prefix, m_underlay_vrf, m_my_ipv4_index->id(), NPL_PROTOCOL_TYPE_IPV4, NPL_TERMINATION_DIP_INDEX_LDB);
        return_on_error(status, HLD, ERROR, "add_local_ep_entry failed");
    } else {
        // add_local_ep_entry
        la_status status = m_device->m_ipv4_tunnel_ep_manager->add_local_ep_entry(
            m_prefix, m_underlay_vrf, m_my_ipv4_index->id(), NPL_PROTOCOL_TYPE_IPV4, NPL_TERMINATION_SIP_DIP_INDEX_LDB);
        return_on_error(status, HLD, ERROR, "add_local_ep_entry failed");
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::remove_tunnel_endpoint()
{
    // for encap only we do not need to update the termination tables
    if (m_tunnel_mode == la_ip_tunnel_mode_e::ENCAP_ONLY) {
        return LA_STATUS_SUCCESS;
    }

    // remove the local IP address from the tunnel endpoint database
    la_status status = m_device->m_ipv4_tunnel_ep_manager->remove_local_ep_entry(
        m_prefix, m_underlay_vrf, NPL_PROTOCOL_TYPE_IPV4, m_my_ipv4_index->id());
    return_on_error(status, HLD, ERROR, "failed to remove tunnel endpoint");

    return LA_STATUS_SUCCESS;
}

const la_vrf*
la_ip_over_ip_tunnel_port_impl::get_overlay_vrf() const
{
    start_api_getter_call();
    return m_vrf.get();
}

la_status
la_ip_over_ip_tunnel_port_impl::set_overlay_vrf(const la_vrf* vrf)
{
    start_api_call("vrf=", vrf);

    if (vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(vrf, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (vrf == m_vrf.get()) {
        return LA_STATUS_SUCCESS;
    }

    if (m_vrf_port_common->has_subnets()) {
        return LA_STATUS_EBUSY;
    }

    deregister_vrf_dependency(m_vrf);
    auto vrf_impl_sptr = m_device->get_sptr<const la_vrf_impl>(vrf);
    la_status status = m_vrf_port_common->set_vrf(vrf_impl_sptr);
    return_on_error(status);

    m_vrf = vrf_impl_sptr;
    register_vrf_dependency(m_vrf);

    return LA_STATUS_SUCCESS;
}

const la_vrf*
la_ip_over_ip_tunnel_port_impl::get_underlay_vrf() const
{
    start_api_getter_call();
    return m_underlay_vrf.get();
}

la_status
la_ip_over_ip_tunnel_port_impl::set_underlay_vrf(const la_vrf* underlay_vrf)
{
    start_api_call("underlay_vrf=", underlay_vrf);

    if (underlay_vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(underlay_vrf, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (underlay_vrf == m_underlay_vrf.get()) {
        return LA_STATUS_SUCCESS;
    }

    if (underlay_vrf->get_gid() == m_underlay_vrf->get_gid()) {
        return LA_STATUS_SUCCESS;
    }

    auto underlay_vrf_sptr = m_device->get_sptr<const la_vrf_impl>(underlay_vrf);
    if (ipv4_tunnel_search(underlay_vrf_sptr, m_prefix, m_ip_addr) != nullptr) {
        return LA_STATUS_EEXIST;
    }

    // remove the local ip address from the tunnel ep database
    la_status status = remove_tunnel_endpoint();
    return_on_error(status);

    status = teardown_tunnel_termination_table();
    return_on_error(status);

    // remove the current tunnel from the tunnel database
    status = ipv4_tunnel_remove(m_underlay_vrf, m_prefix, m_ip_addr, m_device->get_sptr(this));
    return_on_error(status, HLD, ERROR, "failed to remove ipv4 tunnel");

    deregister_vrf_dependency(m_underlay_vrf);

    m_underlay_vrf = underlay_vrf_sptr;

    status = add_tunnel_endpoint();
    return_on_error(status);

    // program the ip tunnel termination table
    status = update_tunnel_term_attributes();
    return_on_error(status);

    // save the updated tunnel in the tunnel database
    status = ipv4_tunnel_add(m_underlay_vrf, m_prefix, m_ip_addr, m_device->get_sptr(this));
    return_on_error(status, HLD, ERROR, "failed to add ipv4 tunnel");

    register_vrf_dependency(m_underlay_vrf);

    return LA_STATUS_SUCCESS;
}

la_ipv4_addr_t
la_ip_over_ip_tunnel_port_impl::get_remote_ip_addr() const
{
    start_api_getter_call();
    return m_ip_addr;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_remote_ip_address(const la_ipv4_addr_t ip_addr)
{
    start_api_call("ip_addr=", ip_addr);

    if (ip_addr.s_addr == m_ip_addr.s_addr) {
        return LA_STATUS_SUCCESS;
    }

    if (ipv4_tunnel_search(m_underlay_vrf, m_prefix, ip_addr) != nullptr) {
        return LA_STATUS_EEXIST;
    }

    la_status status = remove_tunnel_endpoint();
    return_on_error(status);

    status = teardown_tunnel_termination_table();
    return_on_error(status);

    status = ipv4_tunnel_remove(m_underlay_vrf, m_prefix, m_ip_addr, m_device->get_sptr(this));
    return_on_error(status, HLD, ERROR, "failed to remove ipv4 tunnel");

    m_ip_addr = ip_addr;

    status = add_tunnel_endpoint();
    return_on_error(status);

    // update IP tunnel DLP table
    status = update_ip_tunnel_dlp_table();
    return_on_error(status);

    status = update_tunnel_term_attributes();
    return_on_error(status);

    status = ipv4_tunnel_add(m_underlay_vrf, m_prefix, m_ip_addr, m_device->get_sptr(this));
    return_on_error(status, HLD, ERROR, "failed to add ipv4 tunnel");

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_local_ip_prefix(la_ipv4_prefix_t& out_prefix) const
{
    start_api_getter_call();
    out_prefix = m_prefix;
    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_local_ip_prefix(const la_ipv4_prefix_t prefix)
{
    start_api_call("prefix=", prefix);

    la_ipv4_prefix_t new_prefix, old_prefix;

    old_prefix = m_prefix;
    new_prefix = prefix;

    la_uint32_t old_prefix_mask = bit_utils::get_range_mask(bit_utils::BITS_IN_UINT32 - old_prefix.length, old_prefix.length);
    old_prefix.addr.s_addr &= old_prefix_mask;

    la_uint32_t new_prefix_mask = bit_utils::get_range_mask(bit_utils::BITS_IN_UINT32 - new_prefix.length, new_prefix.length);
    new_prefix.addr.s_addr &= new_prefix_mask;

    if ((new_prefix.addr.s_addr == old_prefix.addr.s_addr) && (new_prefix.length == old_prefix.length)) {
        return LA_STATUS_SUCCESS;
    }

    // make sure tunnel with the new address does not exist
    if (ipv4_tunnel_search(m_underlay_vrf, new_prefix, m_ip_addr) != nullptr) {
        return LA_STATUS_EEXIST;
    }

    if (m_tunnel_mode != la_ip_tunnel_mode_e::ENCAP_ONLY) {
        la_status status = m_device->m_ipv4_tunnel_ep_manager->remove_local_ep_entry(
            old_prefix, m_underlay_vrf, NPL_PROTOCOL_TYPE_IPV4, m_my_ipv4_index->id());
        return_on_error(status, HLD, ERROR, "failed to remove tunnel endpoint");
    }

    la_status status = teardown_tunnel_termination_table();
    return_on_error(status);

    // remove the current tunnel from the tunnel database
    status = ipv4_tunnel_remove(m_underlay_vrf, old_prefix, m_ip_addr, m_device->get_sptr(this));
    return_on_error(status, HLD, ERROR, "failed to remove ipv4 tunnel");

    status = m_device->m_ipv4_sip_index_manager->free_sip_index(m_my_ipv4_index);
    return_on_error(status);

    m_prefix = prefix;

    status = m_device->m_ipv4_sip_index_manager->allocate_sip_index(m_prefix, m_my_ipv4_index);
    return_on_error(status);

    // update tunnel DLP table
    status = update_ip_tunnel_dlp_table();
    return_on_error(status);

    status = add_tunnel_endpoint();
    return_on_error(status);

    status = update_tunnel_term_attributes();
    return_on_error(status);

    // save the updated tunnel in the tunnel database
    status = ipv4_tunnel_add(m_underlay_vrf, m_prefix, m_ip_addr, m_device->get_sptr(this));
    return_on_error(status, HLD, ERROR, "failed to add ipv4 tunnel");

    return LA_STATUS_SUCCESS;
}

void
la_ip_over_ip_tunnel_port_impl::register_vrf_dependency(const la_vrf_impl_wcptr& vrf)
{
    m_device->add_object_dependency(vrf, this);
}

void
la_ip_over_ip_tunnel_port_impl::deregister_vrf_dependency(const la_vrf_impl_wcptr& vrf)
{
    m_device->remove_object_dependency(vrf, this);
}

la_status
la_ip_over_ip_tunnel_port_impl::configure_tunnel_termination_table_per_slice(la_slice_id_t slice_idx)
{
    la_status status = update_tunnel_term_attributes_per_slice(slice_idx, m_slice_data[slice_idx].m_base_l3_lp_attributes);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::update_tunnel_term_attributes()
{
    // don't program the termination tables for encap only mode
    if (m_tunnel_mode == la_ip_tunnel_mode_e::ENCAP_ONLY) {
        return LA_STATUS_SUCCESS;
    }

    slice_ifg_vec_t slice_ifgs = get_ifgs();
    for (auto slice : get_slices_from_ifgs(slice_ifgs)) {
        la_status status = update_tunnel_term_attributes_per_slice(slice, m_slice_data[slice].m_base_l3_lp_attributes);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::update_tunnel_term_attributes_per_slice(la_slice_id_t slice, npl_base_l3_lp_attributes_t& attribs)
{
    // don't program the termination tables for encap only mode
    if (m_tunnel_mode == la_ip_tunnel_mode_e::ENCAP_ONLY) {
        return LA_STATUS_SUCCESS;
    }

    if (m_ip_addr.s_addr == LA_IPV4_ANY_IP.s_addr) {
        la_status status = update_tunnel_term_attributes_per_slice_with_dip(slice, attribs, m_addl_l3_lp_attributes);
        return_on_error(status);
    } else {
        la_status status = update_tunnel_term_attributes_per_slice_with_sip_dip(slice, attribs, m_addl_l3_lp_attributes);
        return_on_error(status);
    }

    m_slice_data[slice].m_base_l3_lp_attributes = attribs;
    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::update_tunnel_term_attributes_per_slice_with_sip_dip(
    la_slice_id_t slice,
    const npl_base_l3_lp_attributes_t& attribs,
    const npl_l3_lp_additional_attributes_t& addl_attribs)
{
    const auto& table(m_device->m_tables.ipv4_ip_tunnel_termination_sip_dip_index_tt0_table[slice]);
    npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t k;
    npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t v;
    npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_entry_wptr_t e;

    k.l3_relay_id.id = m_underlay_vrf->get_gid();
    k.sip = m_ip_addr.s_addr;
    k.my_dip_index = m_my_ipv4_index->id();
    k.tunnel_type = NPL_IP_TUNNEL_IP_IN_IP;

    npl_base_l3_lp_attributes_t& base_attrib(v.payloads.term_tt0_attributes.base);
    npl_l3_lp_additional_attributes_t& addl_attrib(v.payloads.term_tt0_attributes.additional);
    base_attrib = attribs;
    addl_attrib = addl_attribs;

    la_status status = table->set(k, v, e);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::update_tunnel_term_attributes_per_slice_with_dip(
    la_slice_id_t slice,
    const npl_base_l3_lp_attributes_t& attribs,
    const npl_l3_lp_additional_attributes_t& addl_attribs)
{
    const auto& table(m_device->m_tables.ipv4_ip_tunnel_termination_dip_index_tt0_table[slice]);
    npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t k;
    npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t v;
    npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_entry_wptr_t e;

    k.l3_relay_id.id = m_underlay_vrf->get_gid();
    k.my_dip_index = m_my_ipv4_index->id();
    k.tunnel_type = NPL_IP_TUNNEL_IP_IN_IP;

    npl_base_l3_lp_attributes_t& base_attrib(v.payloads.term_tt0_attributes.base);
    npl_l3_lp_additional_attributes_t& addl_attrib(v.payloads.term_tt0_attributes.additional);
    base_attrib = attribs;
    addl_attrib = addl_attribs;

    la_status status = table->set(k, v, e);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::teardown_tunnel_termination_table()
{
    // we don't program these tables in encap only mode
    if (m_tunnel_mode == la_ip_tunnel_mode_e::ENCAP_ONLY) {
        return LA_STATUS_SUCCESS;
    }

    slice_ifg_vec_t slice_ifgs = get_ifgs();
    for (auto slice : get_slices_from_ifgs(slice_ifgs)) {
        la_status status = teardown_tunnel_termination_table_per_slice(slice);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::teardown_tunnel_termination_table_per_slice(la_slice_id_t slice)
{
    // we don't program these tables in encap only mode
    if (m_tunnel_mode == la_ip_tunnel_mode_e::ENCAP_ONLY) {
        return LA_STATUS_SUCCESS;
    }

    if (m_ip_addr.s_addr == LA_IPV4_ANY_IP.s_addr) {
        la_status status = teardown_tunnel_termination_table_per_slice_dip(slice);
        return_on_error(status);
    } else {
        la_status status = teardown_tunnel_termination_table_per_slice_sip_dip(slice);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::teardown_tunnel_termination_table_per_slice_sip_dip(la_slice_id_t slice)
{
    const auto& table(m_device->m_tables.ipv4_ip_tunnel_termination_sip_dip_index_tt0_table[slice]);
    npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t k;

    k.l3_relay_id.id = m_underlay_vrf->get_gid();
    k.sip = m_ip_addr.s_addr;
    k.my_dip_index = m_my_ipv4_index->id();
    k.tunnel_type = NPL_IP_TUNNEL_IP_IN_IP;

    la_status status = table->erase(k);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::teardown_tunnel_termination_table_per_slice_dip(la_slice_id_t slice)
{
    const auto& table(m_device->m_tables.ipv4_ip_tunnel_termination_dip_index_tt0_table[slice]);
    npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t k;

    k.l3_relay_id.id = m_underlay_vrf->get_gid();
    k.my_dip_index = m_my_ipv4_index->id();
    k.tunnel_type = NPL_IP_TUNNEL_IP_IN_IP;

    la_status status = table->erase(k);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_active(bool& out_active) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_active(bool active)
{
    start_api_call("active=", active);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_protocol_enabled(la_l3_protocol_e protocol, bool& out_enabled) const
{
    start_api_getter_call();
    la_status status = m_vrf_port_common->get_protocol_enabled(protocol, out_enabled);

    return status;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_protocol_enabled(la_l3_protocol_e protocol, bool enabled)
{
    start_api_call("protocol=", protocol, " enabled=", enabled);
    la_status status = m_vrf_port_common->set_protocol_enabled(protocol, enabled);

    return status;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_event_enabled(la_event_e event, bool& out_enabled) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_event_enabled(la_event_e event, bool enabled)
{
    start_api_call("event=", event, " enabled=", enabled);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_urpf_mode(la_l3_port::urpf_mode_e& out_urpf_mode) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_urpf_mode(la_l3_port::urpf_mode_e urpf_mode)
{
    start_api_call("urpf_mode=", urpf_mode);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_ingress_qos_profile(la_ingress_qos_profile*& out_ingress_qos_profile) const
{
    start_api_getter_call();
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_ingress_qos_profile(la_ingress_qos_profile* ingress_qos_profile)
{
    start_api_call("ingress_qos_profile=", ingress_qos_profile);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_egress_qos_profile(la_egress_qos_profile*& out_egress_qos_profile) const
{
    start_api_getter_call();
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_egress_qos_profile(la_egress_qos_profile* egress_qos_profile)
{
    start_api_call("egress_qos_profile=", egress_qos_profile);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_acl_group(la_acl_direction_e dir, la_acl_group* acl_group)
{
    start_api_call("dir=", dir, "acl_group=", acl_group);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_acl_group(la_acl_direction_e dir, la_acl_group*& out_acl_group) const
{
    start_api_getter_call("dir=", dir);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::clear_acl_group(la_acl_direction_e dir)
{
    start_api_call("dir=", dir);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_pbr_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);
    return m_vrf_port_common->set_pbr_enabled(enabled);
}

la_status
la_ip_over_ip_tunnel_port_impl::get_pbr_enabled(bool& out_enabled) const
{
    start_api_getter_call("");
    return m_vrf_port_common->get_pbr_enabled(out_enabled);
}

la_status
la_ip_over_ip_tunnel_port_impl::get_ingress_mirror_command(const la_mirror_command*& out_mirror_cmd,
                                                           bool& out_is_acl_conditioned) const
{
    start_api_getter_call("");
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_ingress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned)
{
    start_api_call("mirror_cmd=", mirror_cmd, "is_acl_conditioned=", is_acl_conditioned);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_egress_mirror_command(const la_mirror_command*& out_mirror_cmd,
                                                          bool& out_is_acl_conditioned) const
{
    start_api_getter_call("");
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned)
{
    start_api_call("mirror_cmd=", mirror_cmd, "is_acl_conditioned=", is_acl_conditioned);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_ttl_inheritance_mode(la_ttl_inheritance_mode_e mode)
{
    start_api_call("ttl_inheritance_mode=", mode);

    la_mpls_ttl_inheritance_mode_e ttl_mode;
    if (mode == la_ip_tunnel_port::la_ttl_inheritance_mode_e::PIPE) {
        ttl_mode = la_mpls_ttl_inheritance_mode_e::PIPE;
    } else {
        ttl_mode = la_mpls_ttl_inheritance_mode_e::UNIFORM;
    }
    return m_vrf_port_common->set_ttl_inheritance_mode(ttl_mode);
}

la_ip_tunnel_port::la_ttl_inheritance_mode_e
la_ip_over_ip_tunnel_port_impl::get_ttl_inheritance_mode() const
{
    start_api_getter_call();

    la_ttl_inheritance_mode_e mode;

    la_mpls_ttl_inheritance_mode_e ttl_mode = m_vrf_port_common->get_ttl_inheritance_mode();
    if (ttl_mode == la_mpls_ttl_inheritance_mode_e::PIPE) {
        mode = la_ip_tunnel_port::la_ttl_inheritance_mode_e::PIPE;
    } else {
        mode = la_ip_tunnel_port::la_ttl_inheritance_mode_e::UNIFORM;
    }

    return (mode);
}

la_status
la_ip_over_ip_tunnel_port_impl::set_lp_attribute_inheritance_mode(la_lp_attribute_inheritance_mode_e mode)
{
    start_api_call("mode=", mode);

    la_status status = m_vrf_port_common->set_lp_attribute_inheritance_mode(mode);
    return_on_error(status);

    m_lp_attribute_inheritance_mode = mode;

    return update_ip_tunnel_dlp_table();
}

la_lp_attribute_inheritance_mode_e
la_ip_over_ip_tunnel_port_impl::get_lp_attribute_inheritance_mode() const
{
    start_api_getter_call();

    return m_vrf_port_common->get_lp_attribute_inheritance_mode();
}

la_mpls_qos_inheritance_mode_e
la_ip_over_ip_tunnel_port_impl::get_qos_inheritance_mode() const
{
    start_api_getter_call();
    return m_vrf_port_common->get_qos_inheritance_mode();
}

la_status
la_ip_over_ip_tunnel_port_impl::set_qos_inheritance_mode(la_mpls_qos_inheritance_mode_e mode)
{
    start_api_call("mode=", mode);
    return m_vrf_port_common->set_qos_inheritance_mode(mode);
}

la_status
la_ip_over_ip_tunnel_port_impl::get_ingress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const
{
    start_api_getter_call();
    return m_vrf_port_common->get_ingress_counter(type, out_counter);
}

la_status
la_ip_over_ip_tunnel_port_impl::set_ingress_counter(la_counter_set::type_e type, la_counter_set* counter)
{
    start_api_call("type=", type, " counter=", counter);
    return m_vrf_port_common->set_ingress_counter(type, counter);
}

la_status
la_ip_over_ip_tunnel_port_impl::get_egress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_egress_counter(la_counter_set::type_e type, la_counter_set* counter)
{
    start_api_call("type=", type, " counter=", counter);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_ecn_remark_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_ecn_remark_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_ecn_counting_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_ecn_counting_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_uint8_t
la_ip_over_ip_tunnel_port_impl::get_ttl() const
{
    start_api_getter_call("");
    return (m_ttl);
}

la_status
la_ip_over_ip_tunnel_port_impl::set_ttl(la_uint8_t ttl)
{
    start_api_call("ttl=", ttl);

    m_ttl = ttl;

    return (update_ip_tunnel_dlp_table());
}

bool
la_ip_over_ip_tunnel_port_impl::get_decrement_inner_ttl() const
{
    start_api_getter_call("");

    return m_decrement_inner_ttl;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_decrement_inner_ttl(bool decrement_inner_ttl)
{
    start_api_call("decrement_inner_ttl=", decrement_inner_ttl);

    m_decrement_inner_ttl = decrement_inner_ttl;

    return (update_ip_tunnel_dlp_table());
}

la_status
la_ip_over_ip_tunnel_port_impl::get_encap_tos(la_ip_tos& out_encap_tos) const
{
    start_api_getter_call("");

    out_encap_tos = m_encap_tos;

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_encap_tos(la_ip_tos encap_tos)
{
    start_api_call("encap_tos=", encap_tos);

    m_encap_tos = encap_tos;

    return update_ip_tunnel_dlp_table();
}

la_tunnel_encap_qos_mode_e
la_ip_over_ip_tunnel_port_impl::get_encap_qos_mode() const
{
    start_api_getter_call("");

    return m_encap_qos_mode;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_encap_qos_mode(la_tunnel_encap_qos_mode_e mode)
{
    start_api_call("mode=", mode);

    m_encap_qos_mode = mode;

    return update_ip_tunnel_dlp_table();
}

la_ipv4_addr_t
la_ip_over_ip_tunnel_port_impl::get_local_ip_addr() const
{
    start_api_getter_call("");

    return (m_prefix.addr);
}

la_status
la_ip_over_ip_tunnel_port_impl::set_local_ip_address(la_ipv4_addr_t local_ip_address)
{
    start_api_call("local_ip_address=", local_ip_address);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_meter(const la_meter_set*& out_meter) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_meter(const la_meter_set* meter)
{
    start_api_call("meter=", meter);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_drop_counter_offset(la_stage_e stage, size_t& out_offset) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_drop_counter_offset(la_stage_e stage, size_t offset)
{
    start_api_call("stage=", stage, "offset=", offset);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_source_based_forwarding(const la_l3_destination* l3_destination,
                                                            bool label_present,
                                                            la_mpls_label label)
{
    start_api_call("l3_destination=", l3_destination, "label_present=", label_present, "label=", label);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::clear_source_based_forwarding()
{
    start_api_call("");

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_source_based_forwarding(const la_l3_destination*& out_l3_destination,
                                                            bool& out_label_present,
                                                            la_mpls_label& out_label) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_load_balancing_profile(la_l3_port::lb_profile_e& out_lb_profile) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_load_balancing_profile(la_l3_port::lb_profile_e lb_profile)
{
    start_api_call("lb_profile=", lb_profile);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_slice_pair_id_vec_t
la_ip_over_ip_tunnel_port_impl::get_used_nw_slice_pairs()
{
    la_slice_pair_id_vec_t slice_pairs;
    size_t pair_idx;

    slice_pairs.clear();
    for (la_slice_id_t slice : get_slices(m_device, la_slice_mode_e::NETWORK)) {
        pair_idx = slice / 2;
        if (!contains(slice_pairs, pair_idx)) {
            slice_pairs.push_back(pair_idx);
        }
    }
    return slice_pairs;
}

la_status
la_ip_over_ip_tunnel_port_impl::update_ip_tunnel_dlp_table()
{
    for (la_slice_pair_id_t pair_idx : get_used_nw_slice_pairs()) {
        auto status = configure_ip_tunnel_dlp_table(pair_idx);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::configure_ip_tunnel_dlp_table(la_slice_pair_id_t pair_idx)
{
    la_status status;
    la_egress_qos_profile* cur_egress_qos_profile;
    la_counter_set* egress_p_counter;

    // for decap only we don't configure encap_ip_tunnel_table
    if (m_tunnel_mode == la_ip_tunnel_mode_e::DECAP_ONLY) {
        return LA_STATUS_SUCCESS;
    }

    // get egress qos profile
    status = m_vrf_port_common->get_egress_qos_profile(cur_egress_qos_profile);
    return_on_error(status);
    m_egress_qos_profile = m_device->get_sptr<la_egress_qos_profile_impl>(cur_egress_qos_profile);

    // get egress counter
    status = m_vrf_port_common->get_egress_counter(la_counter_set::type_e::PORT, egress_p_counter);
    return_on_error(status);
    const auto& egress_p_counter_impl = m_device->get_sptr<const la_counter_set_impl>(egress_p_counter);

    const auto& table(m_device->m_tables.large_encap_ip_tunnel_table[pair_idx]);
    npl_large_encap_ip_tunnel_table_key_t key;
    npl_large_encap_ip_tunnel_table_value_t value;
    npl_gre_tunnel_attributes_t& attrib(value.payloads.gre_tunnel_attributes);

    // set up key
    key.gre_tunnel_dlp = m_gid;

    // set up attribute
    if (m_lp_attribute_inheritance_mode == la_lp_attribute_inheritance_mode_e::TUNNEL) {
        attrib.tunnel_control.lp_set = 1;
    } else {
        attrib.tunnel_control.lp_set = 0;
    }

    la_egress_qos_marking_source_e marking_source{};
    status = m_egress_qos_profile->get_marking_source(marking_source);
    return_on_error(status);
    attrib.qos_info.is_group_qos = (marking_source == la_egress_qos_marking_source_e::QOS_GROUP);

    bool demux_count = (egress_p_counter_impl != nullptr) ? egress_p_counter_impl->get_set_size() > 1 : false;

    attrib.tunnel_type_q_counter.tunnel_type = NPL_IP_TUNNEL_ENCAP_TYPE_IP;
    attrib.p_counter = populate_counter_ptr_slice_pair(egress_p_counter_impl, pair_idx, COUNTER_DIRECTION_EGRESS);
    attrib.demux_count = demux_count ? 1 : 0;
    attrib.qos_info.qos_id = m_egress_qos_profile->get_id(pair_idx);
    attrib.sip_index = m_my_ipv4_index->id();
    attrib.dip = m_ip_addr.s_addr;
    attrib.gre_flags = 0;
    attrib.ttl = m_ttl;
    attrib.tunnel_control.decrement_inner_ttl = m_decrement_inner_ttl;
    if (m_encap_qos_mode == la_tunnel_encap_qos_mode_e::PIPE) {
        attrib.tunnel_control.is_tos_from_tunnel = 1;
    } else {
        attrib.tunnel_control.is_tos_from_tunnel = 0;
    }
    attrib.tunnel_qos_encap.tos = m_encap_tos.flat;
    attrib.dip_entropy = m_npl_dip_entropy_mode;

    if (m_slice_pair_data[pair_idx].large_encap_ip_tunnel_table_entry != nullptr) {
        status = m_slice_pair_data[pair_idx].large_encap_ip_tunnel_table_entry->update(value);
        return_on_error(status, HLD, ERROR, "ip tunnel dlp table update failed");
    } else {
        status = table->insert(key, value, m_slice_pair_data[pair_idx].large_encap_ip_tunnel_table_entry);
        return_on_error(status, HLD, ERROR, "ip tunnel dlp table insertion failed");
    }

    return status;
}

la_status
la_ip_over_ip_tunnel_port_impl::teardown_ip_tunnel_dlp_table()
{
    for (la_slice_pair_id_t pair_idx : get_used_nw_slice_pairs()) {
        if (m_slice_pair_data[pair_idx].large_encap_ip_tunnel_table_entry != nullptr) {
            la_status status = teardown_ip_tunnel_dlp_table(pair_idx);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::teardown_ip_tunnel_dlp_table(la_slice_pair_id_t pair_idx)
{
    // for decap only we don't teardown encap_ip_tunnel_table
    if (m_tunnel_mode == la_ip_tunnel_mode_e::DECAP_ONLY) {
        return LA_STATUS_SUCCESS;
    }

    const auto& table(m_device->m_tables.large_encap_ip_tunnel_table[pair_idx]);
    if (m_slice_pair_data[pair_idx].large_encap_ip_tunnel_table_entry == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    npl_large_encap_ip_tunnel_table_key_t key;
    key.gre_tunnel_dlp = m_gid;

    la_status status = table->erase(key);
    return_on_error(status, HLD, ERROR, "ip tunnel dlp table erase failed");

    m_slice_pair_data[pair_idx].large_encap_ip_tunnel_table_entry = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::notify_change(dependency_management_op op)
{
    switch (op.type_e) {

    case dependency_management_op::management_type_e::IFG_MANAGEMENT:
        if (op.action.ifg_management.ifg_op == ifg_management_op::IFG_ADD) {
            return add_ifg(op.action.ifg_management.ifg);
        } else {
            return remove_ifg(op.action.ifg_management.ifg);
        }

    default:
        log_err(HLD, "notify_change received unsupported notification (%s)", silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

slice_ifg_vec_t
la_ip_over_ip_tunnel_port_impl::get_ifgs() const
{
    return get_all_network_ifgs(m_device);
}

la_status
la_ip_over_ip_tunnel_port_impl::add_ifg(la_slice_ifg ifg)
{
    transaction txn;

    bool ifg_added, slice_added, slice_pair_added;
    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);
    txn.on_fail([&]() {
        bool dummy;
        m_ifg_use_count->remove_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (!ifg_added) {
        return LA_STATUS_SUCCESS;
    }

    if (slice_pair_added) {
        la_slice_pair_id_t pair_idx = ifg.slice / 2;
        txn.status = configure_ip_tunnel_dlp_table(pair_idx);
        txn.on_fail([&]() { teardown_ip_tunnel_dlp_table(pair_idx); });
        return_on_error(txn.status);
    }

    if (slice_added) {
        txn.status = configure_tunnel_termination_table_per_slice(ifg.slice);
        return_on_error(txn.status);
        txn.on_fail([&]() { teardown_tunnel_termination_table_per_slice(ifg.slice); });
    }

    // Notify users
    txn.status = m_device->notify_ifg_added(this, ifg);
    return_on_error(txn.status);
    txn.on_fail([&]() { m_device->notify_ifg_removed(this, ifg); });

    txn.status = m_vrf_port_common->add_ifg(ifg);
    return_on_error(txn.status);
    txn.on_fail([&]() { m_vrf_port_common->remove_ifg(ifg); });

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::remove_ifg(la_slice_ifg ifg)
{
    transaction txn;

    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);
    txn.on_fail([&]() {
        bool dummy;
        m_ifg_use_count->add_ifg_user(ifg, dummy, dummy, dummy);
    });

    if (!ifg_removed) {
        return LA_STATUS_SUCCESS;
    }

    if (slice_pair_removed) {
        la_slice_pair_id_t pair_idx = ifg.slice / 2;
        txn.status = teardown_ip_tunnel_dlp_table(pair_idx);
        txn.on_fail([&]() { configure_ip_tunnel_dlp_table(pair_idx); });
        return_on_error(txn.status);
    }

    if (slice_removed) {
        txn.status = teardown_tunnel_termination_table_per_slice(ifg.slice);
        return_on_error(txn.status);
        txn.on_fail([&]() { configure_tunnel_termination_table_per_slice(ifg.slice); });
    }

    // Notify users
    txn.status = m_device->notify_ifg_removed(this, ifg);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ip_over_ip_tunnel_port_impl::add_virtual_mac(const la_mac_addr_t& mac_addr)
{
    start_api_call("mac_addr=", mac_addr);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::remove_virtual_mac(const la_mac_addr_t& mac_addr)
{
    start_api_call("mac_addr=", mac_addr);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_virtual_macs(la_mac_addr_vec& out_mac_addresses) const
{
    start_api_getter_call();
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_ingress_sflow_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_ingress_sflow_enabled(bool& out_enabled) const
{
    start_api_getter_call();
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_csc_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_csc_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_egress_sflow_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_egress_sflow_enabled(bool& out_enabled) const
{
    start_api_getter_call();
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::set_filter_group(la_filter_group* filter_group)
{
    start_api_call("filter_group=", filter_group);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_ip_over_ip_tunnel_port_impl::get_filter_group(const la_filter_group*& out_filter_group) const
{
    start_api_getter_call();
    return LA_STATUS_ENOTIMPLEMENTED;
}

} // namespace silicon_one
