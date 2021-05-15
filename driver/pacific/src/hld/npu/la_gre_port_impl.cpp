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

#include "la_gre_port_impl.h"

#include "la_acl_delegate.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "counter_utils.h"
#include "hld_types.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "la_switch_impl.h"
#include "la_vrf_impl.h"
#include "npu/la_vrf_port_common_base.h"
#include "qos/la_egress_qos_profile_impl.h"
#include "qos/la_ingress_qos_profile_impl.h"
#include "resolution_utils.h"
#include "system/la_device_impl.h"
#include "tm/la_unicast_tc_profile_impl.h"

#include <sstream>

namespace silicon_one
{

la_gre_port_impl::la_gre_port_impl(const la_device_impl_wptr& device)
    : m_device(device),
      m_lp_attribute_inheritance_mode(la_lp_attribute_inheritance_mode_e::PORT),
      m_ttl(255),
      m_decrement_inner_ttl(true),
      m_encap_qos_mode(la_tunnel_encap_qos_mode_e::UNIFORM),
      m_vrf_port_common(),
      m_key(0),
      m_sequence_number(0),
      m_termination_type(tunnel_termination_type_e::P2P),
      m_dip_entropy_mode(la_gre_dip_entropy_mode_e::GRE_DIP_ENTROPY_NONE),
      m_npl_dip_entropy_mode(NPL_GRE_DIP_ENTROPY_NONE),
      m_slice_data(ASIC_MAX_SLICES_PER_DEVICE_NUM, slice_data()),
      m_slice_pair_data(NUM_SLICE_PAIRS_PER_DEVICE, slice_pair_data())
{
    m_encap_tos.flat = 0;
}

la_gre_port_impl::~la_gre_port_impl()
{
}

npl_termination_logical_db_e
la_gre_port_impl::termination_type_to_npl(tunnel_termination_type_e term_type) const
{
    static const npl_termination_logical_db_e npl_terms[]
        = {[(int)la_gre_port::tunnel_termination_type_e::P2P] = NPL_TERMINATION_SIP_DIP_INDEX_LDB,
           [(int)la_gre_port::tunnel_termination_type_e::P2MP] = NPL_TERMINATION_DIP_INDEX_LDB};

    if ((size_t)term_type < array_size(npl_terms)) {
        return (npl_terms[(size_t)term_type]);
    }

    return NPL_TERMINATION_SIP_DIP_INDEX_LDB;
}

la_status
la_gre_port_impl::validate_ipv4_prefix(const la_ipv4_prefix_t prefix)
{
    if ((prefix.addr.s_addr & ((1 << (32 - prefix.length)) - 1)) != 0) {
        log_err(HLD, "Invalid prefix %s", silicon_one::to_string(prefix).c_str());
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::ipv4_tunnel_add(const la_vrf_impl_wcptr& underlay_vrf,
                                  const la_ipv4_prefix_t local_ip_prefix,
                                  const la_ipv4_prefix_t remote_ip_prefix,
                                  const la_l3_port_wptr& port)
{
    // validate prefixes
    la_status status;
    status = validate_ipv4_prefix(local_ip_prefix);
    return_on_error(status);
    status = validate_ipv4_prefix(remote_ip_prefix);
    return_on_error(status);

    // build tunnel ID key
    la_device_impl::ipv4_tunnel_id_t tun_id;
    tun_id.local_ip_prefix = local_ip_prefix;
    tun_id.remote_ip_prefix = remote_ip_prefix;
    tun_id.vrf_gid = underlay_vrf->get_gid();
    tun_id.tunnel_type = NPL_IP_TUNNEL_GRE;

    // search for tunnel ID in device tunnel map
    auto it = m_device->m_ipv4_tunnel_map.find(tun_id);

    if (it != m_device->m_ipv4_tunnel_map.end()) {
        return LA_STATUS_EEXIST;
    }

    // add tunnel ID to device tunnel map if not found
    m_device->m_ipv4_tunnel_map[tun_id] = port;

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::ipv4_tunnel_remove(const la_vrf_impl_wcptr& underlay_vrf,
                                     const la_ipv4_prefix_t local_ip_prefix,
                                     const la_ipv4_prefix_t remote_ip_prefix,
                                     const la_l3_port_wptr& port)
{
    // validate prefixes
    la_status status;
    status = validate_ipv4_prefix(local_ip_prefix);
    return_on_error(status);
    status = validate_ipv4_prefix(remote_ip_prefix);
    return_on_error(status);

    // build tunnel ID key
    la_device_impl::ipv4_tunnel_id_t tun_id;
    tun_id.local_ip_prefix = local_ip_prefix;
    tun_id.remote_ip_prefix = remote_ip_prefix;
    tun_id.vrf_gid = underlay_vrf->get_gid();
    tun_id.tunnel_type = NPL_IP_TUNNEL_GRE;

    // search for tunnel ID in device tunnel map
    auto it = m_device->m_ipv4_tunnel_map.find(tun_id);

    if (it == m_device->m_ipv4_tunnel_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    if (it->second != port) {
        return LA_STATUS_EINVAL;
    }

    // erase tunnel ID from device tunnel map if found
    m_device->m_ipv4_tunnel_map.erase(tun_id);

    return LA_STATUS_SUCCESS;
}

la_l3_port_wptr
la_gre_port_impl::ipv4_tunnel_search(const la_vrf_impl_wcptr& underlay_vrf,
                                     const la_ipv4_prefix_t local_ip_prefix,
                                     const la_ipv4_prefix_t remote_ip_prefix)
{
    // validate prefixes
    la_status status;

    status = validate_ipv4_prefix(local_ip_prefix);

    if (status != LA_STATUS_SUCCESS) {
        return nullptr;
    }

    status = validate_ipv4_prefix(remote_ip_prefix);

    if (status != LA_STATUS_SUCCESS) {
        return nullptr;
    }

    // build tunnel ID key
    la_device_impl::ipv4_tunnel_id_t tun_id;
    tun_id.local_ip_prefix = local_ip_prefix;
    tun_id.remote_ip_prefix = remote_ip_prefix;
    tun_id.vrf_gid = underlay_vrf->get_gid();
    tun_id.tunnel_type = NPL_IP_TUNNEL_GRE;

    // search for tunnel ID in device tunnel map
    auto it = m_device->m_ipv4_tunnel_map.find(tun_id);

    if (it == m_device->m_ipv4_tunnel_map.end()) {
        return nullptr;
    }

    return (it->second);
}

la_status
la_gre_port_impl::initialize(la_object_id_t oid,
                             la_l3_port_gid_t gid,
                             la_ip_tunnel_mode_e tunnel_mode,
                             const la_vrf* underlay_vrf,
                             la_ipv4_addr_t local_ip_addr,
                             la_ipv4_addr_t remote_ip_addr,
                             const la_vrf* overlay_vrf,
                             la_ingress_qos_profile_impl* ingress_qos_profile_impl,
                             la_egress_qos_profile_impl* egress_qos_profile_impl)
{
    m_oid = oid;
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    la_status status = m_device->create_vrf_port_common(m_device->get_sptr(this), m_vrf_port_common);
    return_on_error(status);

    m_gid = gid;
    m_tunnel_mode = tunnel_mode;
    m_underlay_vrf = m_device->get_sptr<const la_vrf_impl>(underlay_vrf);
    m_local_ip_prefix.addr = local_ip_addr;
    m_local_ip_prefix.length = 32;
    m_remote_ip_prefix.addr = remote_ip_addr;
    m_remote_ip_prefix.length = 32;
    m_overlay_vrf = m_device->get_sptr<const la_vrf_impl>(overlay_vrf);
    m_ingress_qos_profile = m_device->get_sptr(ingress_qos_profile_impl);
    m_egress_qos_profile = m_device->get_sptr(egress_qos_profile_impl);

    la_mac_addr_t mac_addr;
    mac_addr.flat = 0;

    // check if tunnel to the same endpoints exists
    if (ipv4_tunnel_search(m_underlay_vrf, m_local_ip_prefix, m_remote_ip_prefix) != nullptr) {
        log_err(HLD,
                "IPv4 GRE tunnel (%s, %s) already exists",
                silicon_one::to_string(m_local_ip_prefix).c_str(),
                silicon_one::to_string(m_remote_ip_prefix).c_str());
        return LA_STATUS_EEXIST;
    }

    // for encap only we do not need to query the termination tables
    if (m_tunnel_mode != la_ip_tunnel_mode_e::ENCAP_ONLY) {
        uint32_t ref_cnt = 0;
        uint64_t sip_index = 0;
        npl_termination_logical_db_e term_db;
        status = m_device->m_ipv4_tunnel_ep_manager->get_local_ep_entry_info(
            m_local_ip_prefix, m_underlay_vrf, NPL_PROTOCOL_TYPE_GRE, ref_cnt, sip_index, term_db);
        if (status == LA_STATUS_SUCCESS) {
            if (term_db == NPL_TERMINATION_DIP_INDEX_LDB) {
                log_err(HLD, "dip-only termination tunnel already exist");
                return LA_STATUS_EEXIST;
            }
        }
    }

    // allocate SIP index for the local IP address
    transaction txn;
    txn.status = m_device->m_ipv4_sip_index_manager->allocate_sip_index(m_local_ip_prefix, m_sip_index);
    return_on_error(txn.status);
    txn.on_fail([=]() { m_device->m_ipv4_sip_index_manager->free_sip_index(m_sip_index); });

    txn.status = m_vrf_port_common->initialize(
        gid, mac_addr, nullptr /* sw */, m_overlay_vrf, m_ingress_qos_profile, m_egress_qos_profile);
    return_on_error(txn.status);
    txn.on_fail([=]() {
        m_vrf_port_common->destroy();
        // the vrf port common destroy does not clear up the slp
        // release the hw resource here
        release_lps();
    });

    for (la_slice_ifg ifg : get_all_network_ifgs(m_device)) {
        txn.status = add_ifg(ifg);
        return_on_error(txn.status);
        txn.on_fail([=]() { remove_ifg(ifg); });
    }

    txn.status = add_tunnel_endpoint();
    return_on_error(txn.status,
                    HLD,
                    ERROR,
                    "Failed to add IPv4 GRE tunnel (%s, %s) endpoint",
                    silicon_one::to_string(m_local_ip_prefix).c_str(),
                    silicon_one::to_string(m_remote_ip_prefix).c_str());
    txn.on_fail([=]() {
        m_device->m_ipv4_tunnel_ep_manager->remove_local_ep_entry(
            m_local_ip_prefix, m_underlay_vrf, NPL_PROTOCOL_TYPE_GRE, m_sip_index->id());
    });

    // add the tunnel to the device tunnel database
    txn.status = ipv4_tunnel_add(m_underlay_vrf, m_local_ip_prefix, m_remote_ip_prefix, m_device->get_sptr(this));
    return_on_error(txn.status,
                    HLD,
                    ERROR,
                    "Failed to add IPv4 GRE tunnel (%s, %s)",
                    silicon_one::to_string(m_local_ip_prefix).c_str(),
                    silicon_one::to_string(m_remote_ip_prefix).c_str());
    txn.on_fail([=]() { ipv4_tunnel_remove(m_underlay_vrf, m_local_ip_prefix, m_remote_ip_prefix, m_device->get_sptr(this)); });

    // The dependencies of ingress_qos_profile_impl, egress_qos_profile_impl are managed by m_vrf_port_common
    m_device->add_object_dependency(m_underlay_vrf, this);
    txn.on_fail([=]() { m_device->remove_object_dependency(m_underlay_vrf, this); });
    register_vrf_dependency(m_overlay_vrf);
    txn.on_fail([=]() { deregister_vrf_dependency(m_overlay_vrf); });

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::destroy()
{
    la_status status;
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    status = remove_tunnel_endpoint();
    return_on_error(status);

    auto ifgs = m_ifg_use_count->get_ifgs();

    for (la_slice_ifg ifg : ifgs) {
        la_status status = remove_ifg(ifg);
        return_on_error(status);
    }

    status = m_vrf_port_common->destroy();
    return_on_error(status);

    // delete entry from SIP index
    status = m_device->m_ipv4_sip_index_manager->free_sip_index(m_sip_index);
    return_on_error(status);

    // remove the tunnel from the database if present
    status = ipv4_tunnel_remove(m_underlay_vrf, m_local_ip_prefix, m_remote_ip_prefix, m_device->get_sptr(this));

    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status,
                        HLD,
                        ERROR,
                        "Failed to remove IPv4 GRE tunnel (%s, %s)",
                        silicon_one::to_string(m_local_ip_prefix).c_str(),
                        silicon_one::to_string(m_remote_ip_prefix).c_str());
    }

    deregister_vrf_dependency(m_overlay_vrf);
    m_device->remove_object_dependency(m_underlay_vrf, this);

    return status;
}

la_object::object_type_e
la_gre_port_impl::type() const
{
    return la_object::object_type_e::GRE_PORT;
}

std::string
la_gre_port_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_gre_port_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_gre_port_impl::oid() const
{
    return m_oid;
}

const la_device*
la_gre_port_impl::get_device() const
{
    return m_device.get();
}

la_l3_port_gid_t
la_gre_port_impl::get_gid() const
{
    return m_gid;
}

const la_vrf*
la_gre_port_impl::get_underlay_vrf() const
{
    start_api_getter_call("");
    return m_underlay_vrf.get();
}

la_status
la_gre_port_impl::set_underlay_vrf(const la_vrf* underlay_vrf)
{
    start_api_call("underlay_vrf=", underlay_vrf);
    la_status status;

    if (underlay_vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    auto new_underlay_vrf_sptr = m_device->get_sptr<const la_vrf_impl>(underlay_vrf);

    if (new_underlay_vrf_sptr->get_gid() == m_underlay_vrf->get_gid()) {
        return LA_STATUS_SUCCESS;
    }

    // make sure tunnel with the new underlay VRF does not exist
    if (ipv4_tunnel_search(new_underlay_vrf_sptr, m_local_ip_prefix, m_remote_ip_prefix) != nullptr) {
        log_err(HLD,
                "IPv4 GRE tunnel (%s, %s) already exists",
                silicon_one::to_string(m_local_ip_prefix).c_str(),
                silicon_one::to_string(m_remote_ip_prefix).c_str());
        return LA_STATUS_EEXIST;
    }

    status = remove_tunnel_endpoint();
    return_on_error(status,
                    HLD,
                    ERROR,
                    "Failed to remove IPv4 GRE tunnel (%s, %s) endpoint",
                    silicon_one::to_string(m_local_ip_prefix).c_str(),
                    silicon_one::to_string(m_remote_ip_prefix).c_str());

    // remove ip tunnel termination table entry
    status = teardown_lp_attributes_table();
    return_on_error(status);

    // remove the current tunnel from the tunnel database if present
    status = ipv4_tunnel_remove(m_underlay_vrf, m_local_ip_prefix, m_remote_ip_prefix, m_device->get_sptr(this));

    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status,
                        HLD,
                        ERROR,
                        "Failed to remove IPv4 GRE tunnel (%s, %s)",
                        silicon_one::to_string(m_local_ip_prefix).c_str(),
                        silicon_one::to_string(m_remote_ip_prefix).c_str());
    }

    // update underlay VRF
    m_device->remove_object_dependency(m_underlay_vrf, this);
    m_underlay_vrf = new_underlay_vrf_sptr;

    status = add_tunnel_endpoint();
    return_on_error(status,
                    HLD,
                    ERROR,
                    "Failed to add IPv4 GRE tunnel (%s, %s) endpoint",
                    silicon_one::to_string(m_local_ip_prefix).c_str(),
                    silicon_one::to_string(m_remote_ip_prefix).c_str());
    // program the IP tunnel termination table
    status = update_l3_lp_attributes();
    return_on_error(status);

    // save the updated tunnel in the tunnel database
    status = ipv4_tunnel_add(m_underlay_vrf, m_local_ip_prefix, m_remote_ip_prefix, m_device->get_sptr(this));
    return_on_error(status,
                    HLD,
                    ERROR,
                    "Failed to add IPv4 GRE tunnel (%s, %s)",
                    silicon_one::to_string(m_local_ip_prefix).c_str(),
                    silicon_one::to_string(m_remote_ip_prefix).c_str());
    m_device->add_object_dependency(m_underlay_vrf, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::set_csc_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::get_csc_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_ipv4_addr_t
la_gre_port_impl::get_local_ip_addr() const
{
    start_api_getter_call("");
    return m_local_ip_prefix.addr;
}

la_status
la_gre_port_impl::set_local_ip_address(la_ipv4_addr_t local_ip_address)
{
    start_api_call("local_ip_address=", local_ip_address);

    la_ipv4_prefix_t local_ip_prefix;
    local_ip_prefix.addr = local_ip_address;
    local_ip_prefix.length = 32;

    return set_local_ip_prefix(local_ip_prefix);
}

la_status
la_gre_port_impl::get_local_ip_prefix(la_ipv4_prefix_t& local_ip_prefix) const
{
    start_api_getter_call("");
    local_ip_prefix = m_local_ip_prefix;
    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::set_local_ip_prefix(const la_ipv4_prefix_t local_ip_prefix)
{
    start_api_call("local_ip_prefix=", local_ip_prefix);
    ipv4_sip_index_manager::ipv4_sip_index_profile_t sip_index{};
    la_status status;

    // return if local IP prefix has not changed
    if (m_local_ip_prefix == local_ip_prefix) {
        return LA_STATUS_SUCCESS;
    }

    // make sure tunnel with the new local IP address does not exist
    if (ipv4_tunnel_search(m_underlay_vrf, local_ip_prefix, m_remote_ip_prefix) != nullptr) {
        log_err(HLD,
                "IPv4 GRE tunnel (%s, %s) already exists",
                silicon_one::to_string(local_ip_prefix).c_str(),
                silicon_one::to_string(m_remote_ip_prefix).c_str());
        return LA_STATUS_EEXIST;
    }

    // allocate SIP index
    status = m_device->m_ipv4_sip_index_manager->allocate_sip_index(local_ip_prefix, sip_index);
    return_on_error(status);

    status = remove_tunnel_endpoint();
    return_on_error(status,
                    HLD,
                    ERROR,
                    "Failed to remove IPv4 GRE tunnel (%s, %s) endpoint",
                    silicon_one::to_string(m_local_ip_prefix).c_str(),
                    silicon_one::to_string(m_remote_ip_prefix).c_str());

    // remove IP tunnel termination table entry
    status = teardown_lp_attributes_table();
    return_on_error(status);

    // remove the current tunnel from the tunnel database if present
    status = ipv4_tunnel_remove(m_underlay_vrf, m_local_ip_prefix, m_remote_ip_prefix, m_device->get_sptr(this));

    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status,
                        HLD,
                        ERROR,
                        "Failed to remove IPv4 GRE tunnel (%s, %s)",
                        silicon_one::to_string(m_local_ip_prefix).c_str(),
                        silicon_one::to_string(m_remote_ip_prefix).c_str());
    }

    status = m_device->m_ipv4_sip_index_manager->free_sip_index(m_sip_index);
    return_on_error(status);

    // update local IP prefix
    m_local_ip_prefix = local_ip_prefix;
    m_sip_index = sip_index;

    // update tunnel DLP table
    status = update_ip_tunnel_dlp_table();
    return_on_error(status);

    status = add_tunnel_endpoint();
    return_on_error(status,
                    HLD,
                    ERROR,
                    "Failed to add IPv4 GRE tunnel (%s, %s) endpoint",
                    silicon_one::to_string(m_local_ip_prefix).c_str(),
                    silicon_one::to_string(m_remote_ip_prefix).c_str());

    // program the IP tunnel termination table
    status = update_l3_lp_attributes();
    return_on_error(status);

    // save the updated tunnel in the tunnel database
    status = ipv4_tunnel_add(m_underlay_vrf, m_local_ip_prefix, m_remote_ip_prefix, m_device->get_sptr(this));
    return_on_error(status,
                    HLD,
                    ERROR,
                    "Failed to add IPv4 GRE tunnel (%s, %s)",
                    silicon_one::to_string(m_local_ip_prefix).c_str(),
                    silicon_one::to_string(m_remote_ip_prefix).c_str());

    return LA_STATUS_SUCCESS;
}

la_ipv4_addr_t
la_gre_port_impl::get_remote_ip_addr() const
{
    start_api_getter_call("");
    return m_remote_ip_prefix.addr;
}

la_status
la_gre_port_impl::set_remote_ip_address(la_ipv4_addr_t remote_ip_address)
{
    start_api_call("remote_ip_address=", remote_ip_address);

    la_ipv4_prefix_t remote_ip_prefix;
    remote_ip_prefix.addr = remote_ip_address;
    remote_ip_prefix.length = 32;

    return set_remote_ip_prefix(remote_ip_prefix);
}

la_status
la_gre_port_impl::get_remote_ip_prefix(la_ipv4_prefix_t& remote_ip_prefix) const
{
    start_api_getter_call("");
    remote_ip_prefix = m_remote_ip_prefix;
    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::set_remote_ip_prefix(const la_ipv4_prefix_t remote_ip_prefix)
{
    start_api_call("remote_ip_prefix=", remote_ip_prefix);

    // return if remote IP prefix has not changed
    if (m_remote_ip_prefix == remote_ip_prefix) {
        return LA_STATUS_SUCCESS;
    }

    // Make sure a tunnel with the same local IP prefix and
    // the new remote IP prefix does not already exist.
    if (ipv4_tunnel_search(m_underlay_vrf, m_local_ip_prefix, remote_ip_prefix) != nullptr) {
        log_err(HLD,
                "IPv4 GRE tunnel (%s, %s) already exists",
                silicon_one::to_string(m_local_ip_prefix).c_str(),
                silicon_one::to_string(remote_ip_prefix).c_str());
        return LA_STATUS_EEXIST;
    }

    // remove IP tunnel termination table entry
    auto status = teardown_lp_attributes_table();
    return_on_error(status);

    // remove the current tunnel from the database if present
    status = ipv4_tunnel_remove(m_underlay_vrf, m_local_ip_prefix, m_remote_ip_prefix, m_device->get_sptr(this));

    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status,
                        HLD,
                        ERROR,
                        "Failed to remove IPv4 GRE tunnel (%s, %s)",
                        silicon_one::to_string(m_local_ip_prefix).c_str(),
                        silicon_one::to_string(m_remote_ip_prefix).c_str());
    }

    // update DIP entropy mode
    status = set_dip_entropy_mode(remote_ip_prefix);
    return_on_error(status);

    // update remote IP prefix
    m_remote_ip_prefix = remote_ip_prefix;

    // update IP tunnel DLP table
    status = update_ip_tunnel_dlp_table();
    return_on_error(status);

    // program the IP tunnel termination table
    status = update_l3_lp_attributes();
    return_on_error(status);

    // save the updated tunnel in the tunnel database
    status = ipv4_tunnel_add(m_underlay_vrf, m_local_ip_prefix, m_remote_ip_prefix, m_device->get_sptr(this));
    return_on_error(status,
                    HLD,
                    ERROR,
                    "Failed to add IPv4 GRE tunnel (%s, %s)",
                    silicon_one::to_string(m_local_ip_prefix).c_str(),
                    silicon_one::to_string(m_remote_ip_prefix).c_str());

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::set_local_and_remote_ip_prefix(const la_ipv4_prefix_t local_ip_prefix, const la_ipv4_prefix_t remote_ip_prefix)
{
    start_api_call("local_ip_prefix=", local_ip_prefix, "remote_ip_prefix=", remote_ip_prefix);

    // return if local and remote IP prefix have not changed
    if (m_local_ip_prefix == local_ip_prefix && m_remote_ip_prefix == remote_ip_prefix) {
        return LA_STATUS_SUCCESS;
    }

    // Make sure a tunnel with the same local IP prefix and
    // the new remote IP prefix does not already exist.
    if (ipv4_tunnel_search(m_underlay_vrf, local_ip_prefix, remote_ip_prefix) != nullptr) {
        log_err(HLD,
                "IPv4 GRE tunnel (%s, %s) already exists",
                silicon_one::to_string(m_local_ip_prefix).c_str(),
                silicon_one::to_string(remote_ip_prefix).c_str());
        return LA_STATUS_EEXIST;
    }

    auto status = remove_tunnel_endpoint();
    return_on_error(status,
                    HLD,
                    ERROR,
                    "Failed to remove IPv4 GRE tunnel (%s, %s) endpoint",
                    silicon_one::to_string(m_local_ip_prefix).c_str(),
                    silicon_one::to_string(m_remote_ip_prefix).c_str());

    // remove IP tunnel termination table entry
    status = teardown_lp_attributes_table();
    return_on_error(status);

    // remove the current tunnel from the database if present
    status = ipv4_tunnel_remove(m_underlay_vrf, m_local_ip_prefix, m_remote_ip_prefix, m_device->get_sptr(this));
    if (status != LA_STATUS_ENOTFOUND) {
        return_on_error(status,
                        HLD,
                        ERROR,
                        "Failed to remove IPv4 GRE tunnel (%s, %s)",
                        silicon_one::to_string(m_local_ip_prefix).c_str(),
                        silicon_one::to_string(m_remote_ip_prefix).c_str());
    }

    status = m_device->m_ipv4_sip_index_manager->free_sip_index(m_sip_index);
    return_on_error(status);

    // allocate SIP index
    status = m_device->m_ipv4_sip_index_manager->allocate_sip_index(local_ip_prefix, m_sip_index);
    return_on_error(status);

    // update DIP entropy mode
    status = set_dip_entropy_mode(remote_ip_prefix);
    return_on_error(status);

    // update local IP prefix
    m_local_ip_prefix = local_ip_prefix;

    // update remote IP prefix
    m_remote_ip_prefix = remote_ip_prefix;

    // update IP tunnel DLP table
    status = update_ip_tunnel_dlp_table();
    return_on_error(status);

    // update endpoint table based on local_ip and sip_index
    status = add_tunnel_endpoint();
    return_on_error(status,
                    HLD,
                    ERROR,
                    "Failed to add IPv4 GRE tunnel (%s, %s) endpoint",
                    silicon_one::to_string(m_local_ip_prefix).c_str(),
                    silicon_one::to_string(m_sip_index).c_str());

    // program the IP tunnel termination table for the new remote_ip and sip_index
    status = update_l3_lp_attributes();
    return_on_error(status);

    // save the updated tunnel in the tunnel database
    status = ipv4_tunnel_add(m_underlay_vrf, m_local_ip_prefix, m_remote_ip_prefix, m_device->get_sptr(this));
    return_on_error(status,
                    HLD,
                    ERROR,
                    "Failed to add IPv4 GRE tunnel (%s, %s)",
                    silicon_one::to_string(m_local_ip_prefix).c_str(),
                    silicon_one::to_string(m_remote_ip_prefix).c_str());

    return LA_STATUS_SUCCESS;
}

const la_vrf*
la_gre_port_impl::get_overlay_vrf() const
{
    start_api_getter_call("");
    return m_overlay_vrf.get();
}

la_status
la_gre_port_impl::set_overlay_vrf(const la_vrf* overlay_vrf)
{
    start_api_call("overlay_vrf=", overlay_vrf);

    if (overlay_vrf == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(overlay_vrf, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_vrf_port_common->has_subnets()) {
        return LA_STATUS_EBUSY;
    }

    deregister_vrf_dependency(m_overlay_vrf);

    auto overlay_vrf_sptr = m_device->get_sptr<const la_vrf_impl>(overlay_vrf);
    la_status status = m_vrf_port_common->set_vrf(overlay_vrf_sptr);
    return_on_error(status);

    m_overlay_vrf = overlay_vrf_sptr;
    register_vrf_dependency(m_overlay_vrf);

    return LA_STATUS_SUCCESS;
}

void
la_gre_port_impl::register_vrf_dependency(const la_vrf_impl_wcptr& overlay_vrf)
{
    m_device->add_object_dependency(overlay_vrf, this);
    bit_vector registered_attributes((la_uint64_t)attribute_management_op::VRF_FALLBACK_CHANGED);
    m_device->add_attribute_dependency(overlay_vrf, this, registered_attributes);
}

void
la_gre_port_impl::deregister_vrf_dependency(const la_vrf_impl_wcptr& overlay_vrf)
{
    bit_vector registered_attributes((la_uint64_t)attribute_management_op::VRF_FALLBACK_CHANGED);
    m_device->remove_attribute_dependency(overlay_vrf, this, registered_attributes);
    m_device->remove_object_dependency(overlay_vrf, this);
}

la_status
la_gre_port_impl::update_dependent_attributes(dependency_management_op op)
{
    switch (op.action.attribute_management.op) {

    case (attribute_management_op::VRF_FALLBACK_CHANGED):
        return update_fallback_vrf();

    default:
        return LA_STATUS_SUCCESS;
    }
}

la_slice_pair_id_vec_t
la_gre_port_impl::get_used_nw_slice_pairs()
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
la_gre_port_impl::update_ip_tunnel_dlp_table()
{
    for (la_slice_pair_id_t pair_idx : get_used_nw_slice_pairs()) {
        auto status = configure_ip_tunnel_dlp_table(pair_idx);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::configure_ip_tunnel_dlp_table(la_slice_pair_id_t pair_idx)
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

    attrib.tunnel_type_q_counter.tunnel_type = NPL_IP_TUNNEL_ENCAP_TYPE_GRE;
    attrib.p_counter = populate_counter_ptr_slice_pair(egress_p_counter_impl, pair_idx, COUNTER_DIRECTION_EGRESS);
    attrib.demux_count = demux_count ? 1 : 0;
    ;
    // attrib.qos_and_acl_info.acl_drop_offset.cntr_offset.offset.base_cntr_offset = 0;
    attrib.qos_info.qos_id = m_egress_qos_profile->get_id(pair_idx);
    attrib.sip_index = m_sip_index->id();
    attrib.dip = m_remote_ip_prefix.addr.s_addr;
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
la_gre_port_impl::teardown_ip_tunnel_dlp_table()
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
la_gre_port_impl::teardown_ip_tunnel_dlp_table(la_slice_pair_id_t pair_idx)
{
    // for decap only we don't teardown encap_ip_tunnel_table
    if (m_tunnel_mode == la_ip_tunnel_mode_e::DECAP_ONLY) {
        return LA_STATUS_SUCCESS;
    }

    const auto& table(m_device->m_tables.large_encap_ip_tunnel_table[pair_idx]);
    if (m_slice_pair_data[pair_idx].large_encap_ip_tunnel_table_entry == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    npl_large_encap_ip_tunnel_table_key_t key = m_slice_pair_data[pair_idx].large_encap_ip_tunnel_table_entry->key();

    la_status status = table->erase(key);
    return_on_error(status, HLD, ERROR, "ip tunnel dlp table erase failed");

    m_slice_pair_data[pair_idx].large_encap_ip_tunnel_table_entry = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::add_ifg(la_slice_ifg ifg)
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
la_gre_port_impl::remove_ifg(la_slice_ifg ifg)
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
        txn.status = teardown_lp_attributes_table(ifg.slice);
        return_on_error(txn.status);
        txn.on_fail([&]() { configure_lp_attributes_table(ifg.slice); });
    }

    // Notify users
    txn.status = m_device->notify_ifg_removed(this, ifg);
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::configure_lp_attributes_table(la_slice_id_t slice_idx)
{
    la_status status
        = update_l3_lp_attributes(slice_idx, m_slice_data[slice_idx].base_l3_atrrib, m_slice_data[slice_idx].additional_attribs);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::update_l3_lp_attributes()
{
    for (auto slice_id : get_slices(m_device, la_slice_mode_e::NETWORK)) {
        la_status status
            = update_l3_lp_attributes(slice_id, m_slice_data[slice_id].base_l3_atrrib, m_slice_data[slice_id].additional_attribs);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::update_l3_lp_attributes_sip_dip(la_slice_id_t slice,
                                                  const npl_base_l3_lp_attributes_t& attribs,
                                                  const npl_l3_lp_additional_attributes_t& additional_attribs)
{
    m_slice_data[slice].base_l3_atrrib = attribs;
    m_slice_data[slice].additional_attribs = additional_attribs;

    const auto& table(m_device->m_tables.ipv4_ip_tunnel_termination_sip_dip_index_tt0_table[slice]);
    npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t key;
    npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t value;
    npl_l3_lp_attributes_t& attrib(value.payloads.term_tt0_attributes);

    key.l3_relay_id.id = m_underlay_vrf->get_gid();
    key.sip = m_remote_ip_prefix.addr.s_addr;
    key.my_dip_index = m_sip_index->id();
    key.tunnel_type = NPL_IP_TUNNEL_GRE;

    attrib.base = attribs;
    attrib.additional = additional_attribs;

    la_status status;
    if (m_slice_data[slice].ipv4_gre_tunnel_termination_sip_dip_index_tt0_table_entry != nullptr) {
        status = m_slice_data[slice].ipv4_gre_tunnel_termination_sip_dip_index_tt0_table_entry->update(value);
        return_on_error(status, HLD, ERROR, "ipv4 tunnel termination table update failed");
    } else {
        status = table->insert(key, value, m_slice_data[slice].ipv4_gre_tunnel_termination_sip_dip_index_tt0_table_entry);
        return_on_error(status, HLD, ERROR, "ip tunnel termination table insertion failed");
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::update_l3_lp_attributes_dip(la_slice_id_t slice,
                                              const npl_base_l3_lp_attributes_t& attribs,
                                              const npl_l3_lp_additional_attributes_t& additional_attribs)
{
    m_slice_data[slice].base_l3_atrrib = attribs;
    m_slice_data[slice].additional_attribs = additional_attribs;

    const auto& table(m_device->m_tables.ipv4_ip_tunnel_termination_dip_index_tt0_table[slice]);
    npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t key;
    npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t value;
    npl_l3_lp_attributes_t& attrib(value.payloads.term_tt0_attributes);

    key.l3_relay_id.id = m_underlay_vrf->get_gid();
    key.my_dip_index = m_sip_index->id();
    key.tunnel_type = NPL_IP_TUNNEL_GRE;

    attrib.base = attribs;

    la_status status;
    if (m_slice_data[slice].ipv4_gre_tunnel_termination_dip_index_tt0_table_entry != nullptr) {
        status = m_slice_data[slice].ipv4_gre_tunnel_termination_dip_index_tt0_table_entry->update(value);
        return_on_error(status, HLD, ERROR, "ipv4 tunnel dip termination table update failed");
    } else {
        status = table->insert(key, value, m_slice_data[slice].ipv4_gre_tunnel_termination_dip_index_tt0_table_entry);
        return_on_error(status, HLD, ERROR, "ip tunnel dip termination table insertion failed");
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::update_l3_lp_attributes(la_slice_id_t slice,
                                          const npl_base_l3_lp_attributes_t& attribs,
                                          const npl_l3_lp_additional_attributes_t& additional_attribs)
{
    la_status status = LA_STATUS_SUCCESS;

    // don't program the termination tables for encap only mode
    if (m_tunnel_mode == la_ip_tunnel_mode_e::ENCAP_ONLY) {
        return LA_STATUS_SUCCESS;
    }

    if (m_termination_type == tunnel_termination_type_e::P2MP) {
        status = update_l3_lp_attributes_dip(slice, attribs, additional_attribs);
    } else {
        status = update_l3_lp_attributes_sip_dip(slice, attribs, additional_attribs);
    }
    return status;
}

la_status
la_gre_port_impl::teardown_lp_attributes_table_sip_dip()
{
    for (auto slice_id : get_slices(m_device, la_slice_mode_e::NETWORK)) {
        if (m_slice_data[slice_id].ipv4_gre_tunnel_termination_sip_dip_index_tt0_table_entry != nullptr) {
            la_status status = teardown_lp_attributes_table_sip_dip(slice_id);
            return_on_error(status);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::teardown_lp_attributes_table_dip()
{
    for (auto slice_id : get_slices(m_device, la_slice_mode_e::NETWORK)) {
        if (m_slice_data[slice_id].ipv4_gre_tunnel_termination_dip_index_tt0_table_entry != nullptr) {
            la_status status = teardown_lp_attributes_table_dip(slice_id);
            return_on_error(status);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::teardown_lp_attributes_table()
{
    start_api_call("");
    la_status status = LA_STATUS_SUCCESS;
    if (m_termination_type == tunnel_termination_type_e::P2MP) {
        status = teardown_lp_attributes_table_dip();
    } else {
        status = teardown_lp_attributes_table_sip_dip();
    }
    return status;
}

la_status
la_gre_port_impl::teardown_lp_attributes_table_sip_dip(la_slice_id_t slice)
{
    start_api_call("slice=", slice);
    // we don't program these tables in encap only mode
    if (m_tunnel_mode == la_ip_tunnel_mode_e::ENCAP_ONLY) {
        return LA_STATUS_SUCCESS;
    }

    const auto& table(m_device->m_tables.ipv4_ip_tunnel_termination_sip_dip_index_tt0_table[slice]);
    npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t key;

    if (m_slice_data[slice].ipv4_gre_tunnel_termination_sip_dip_index_tt0_table_entry != nullptr) {
        key = m_slice_data[slice].ipv4_gre_tunnel_termination_sip_dip_index_tt0_table_entry->key();

        la_status status = table->erase(key);
        return_on_error(status);

        m_slice_data[slice].ipv4_gre_tunnel_termination_sip_dip_index_tt0_table_entry = nullptr;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::teardown_lp_attributes_table_dip(la_slice_id_t slice)
{
    start_api_call("slice=", slice);
    // we don't program these tables in encap only mode
    if (m_tunnel_mode == la_ip_tunnel_mode_e::ENCAP_ONLY) {
        return LA_STATUS_SUCCESS;
    }

    const auto& table(m_device->m_tables.ipv4_ip_tunnel_termination_dip_index_tt0_table[slice]);
    npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t key;

    key = m_slice_data[slice].ipv4_gre_tunnel_termination_dip_index_tt0_table_entry->key();

    la_status status = table->erase(key);
    return_on_error(status);

    m_slice_data[slice].ipv4_gre_tunnel_termination_dip_index_tt0_table_entry = nullptr;
    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::teardown_lp_attributes_table(la_slice_id_t slice)
{
    start_api_call("slice=", slice);
    la_status status = LA_STATUS_SUCCESS;

    if (m_termination_type == tunnel_termination_type_e::P2MP) {
        status = teardown_lp_attributes_table_dip(slice);
    } else {
        status = teardown_lp_attributes_table_sip_dip(slice);
    }
    return status;
}

la_status
la_gre_port_impl::notify_change(dependency_management_op op)
{
    switch (op.type_e) {

    case dependency_management_op::management_type_e::IFG_MANAGEMENT:
        if (op.action.ifg_management.ifg_op == ifg_management_op::IFG_ADD) {
            return add_ifg(op.action.ifg_management.ifg);
        } else {
            return remove_ifg(op.action.ifg_management.ifg);
        }

    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT:
        return update_dependent_attributes(op);

    default:
        log_err(HLD, "notify_change received unsupported notification (%s)", silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

slice_ifg_vec_t
la_gre_port_impl::get_ifgs() const
{
    return m_ifg_use_count->get_ifgs();
}

la_status
la_gre_port_impl::set_active(bool active)
{
    start_api_call("active=", active);

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::get_active(bool& out_active) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::get_protocol_enabled(la_l3_protocol_e protocol, bool& out_enabled) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::set_protocol_enabled(la_l3_protocol_e protocol, bool enabled)
{
    start_api_call("protocol=", protocol, " enabled=", enabled);
    la_status status = m_vrf_port_common->set_protocol_enabled(protocol, enabled);
    return status;
}

la_status
la_gre_port_impl::get_event_enabled(la_event_e event, bool& out_enabled) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::set_event_enabled(la_event_e event, bool enabled)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::get_urpf_mode(la_l3_port::urpf_mode_e& out_urpf_mode) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::set_urpf_mode(la_l3_port::urpf_mode_e urpf_mode)
{
    // do not allow set urpf on GRE
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::set_ingress_qos_profile(la_ingress_qos_profile* ingress_qos_profile)
{
    start_api_call("ingress_qos_profile=", ingress_qos_profile);

    return (m_vrf_port_common->set_ingress_qos_profile(ingress_qos_profile));
}

la_status
la_gre_port_impl::get_ingress_qos_profile(la_ingress_qos_profile*& out_ingress_qos_profile) const
{
    start_api_getter_call();

    out_ingress_qos_profile = m_ingress_qos_profile.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::set_egress_qos_profile(la_egress_qos_profile* egress_qos_profile)
{
    start_api_call("egress_qos_profile=", egress_qos_profile);

    return (m_vrf_port_common->set_egress_qos_profile(egress_qos_profile));
}

la_status
la_gre_port_impl::get_egress_qos_profile(la_egress_qos_profile*& out_egress_qos_profile) const
{
    start_api_getter_call();

    out_egress_qos_profile = m_egress_qos_profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::set_ecn_remark_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::get_ecn_remark_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::set_ecn_counting_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::get_ecn_counting_enabled(bool& out_enabled) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::set_acl_group(la_acl_direction_e dir, la_acl_group* acl_group)
{
    start_api_call("dir=", dir, "acl_group=", acl_group);
    return m_vrf_port_common->set_acl_group(dir, acl_group);
}

la_status
la_gre_port_impl::get_acl_group(la_acl_direction_e dir, la_acl_group*& out_acl_group) const
{
    start_api_getter_call("dir=", dir);
    return m_vrf_port_common->get_acl_group(dir, out_acl_group);
}

la_status
la_gre_port_impl::clear_acl_group(la_acl_direction_e dir)
{
    start_api_call("dir=", dir);
    return m_vrf_port_common->clear_acl_group(dir);
}

la_status
la_gre_port_impl::set_pbr_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);
    return m_vrf_port_common->set_pbr_enabled(enabled);
}

la_status
la_gre_port_impl::get_pbr_enabled(bool& out_enabled) const
{
    start_api_getter_call("");
    return m_vrf_port_common->get_pbr_enabled(out_enabled);
}

la_status
la_gre_port_impl::set_ingress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned)
{
    // no plan to support it till we have real use case
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::get_ingress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::get_egress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::get_load_balancing_profile(la_l3_port::lb_profile_e& out_lb_profile) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::set_load_balancing_profile(la_l3_port::lb_profile_e lb_profile)
{
    start_api_call("lb_profile=", lb_profile);

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::set_qos_inheritance_mode(la_mpls_qos_inheritance_mode_e mode)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_mpls_qos_inheritance_mode_e
la_gre_port_impl::get_qos_inheritance_mode() const
{
    // we dont support MPLS over GRE yet. The function is not
    // supposed to be called. But it have to a value. Use default
    return la_mpls_qos_inheritance_mode_e::PIPE;
}

la_status
la_gre_port_impl::update_fallback_vrf()
{
    return m_vrf_port_common->update_fallback_vrf();
}

la_status
la_gre_port_impl::set_ingress_counter(la_counter_set::type_e type, la_counter_set* counter)
{
    start_api_call("type=", type, " counter=", counter);
    return m_vrf_port_common->set_ingress_counter(type, counter);
}

la_status
la_gre_port_impl::get_ingress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const
{
    return m_vrf_port_common->get_ingress_counter(type, out_counter);
}

la_status
la_gre_port_impl::set_egress_counter(la_counter_set::type_e type, la_counter_set* counter)
{
    start_api_call("type=", type, " counter=", counter);
    // currently GRE does not support QoS coutner on encap
    if (type != la_counter_set::type_e::PORT) {
        return LA_STATUS_EINVAL;
    }
    return m_vrf_port_common->set_egress_counter(type, counter);
}

la_status
la_gre_port_impl::get_egress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const
{
    return m_vrf_port_common->get_egress_counter(type, out_counter);
}

la_status
la_gre_port_impl::set_meter(const la_meter_set* meter)
{
    start_api_call("meter=", meter);

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::get_meter(const la_meter_set*& out_meter) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::set_drop_counter_offset(la_stage_e stage, size_t offset)
{
    start_api_call("stage=", stage, "offset=", offset);

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::get_drop_counter_offset(la_stage_e stage, size_t& out_offset) const
{
    start_api_getter_call("stage=", stage, "offset=", offset);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::set_source_based_forwarding(const la_l3_destination* l3_destination, bool label_present, la_mpls_label label)
{
    start_api_call("l3_destination=", l3_destination, "label_present=", label_present, "label=", label);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::clear_source_based_forwarding()
{
    start_api_call("");

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::get_source_based_forwarding(const la_l3_destination*& out_l3_destination,
                                              bool& out_label_present,
                                              la_mpls_label& out_label) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_uint8_t
la_gre_port_impl::get_ttl() const
{
    start_api_getter_call("");
    return (m_ttl);
}

la_gre_port_impl::la_ttl_inheritance_mode_e
la_gre_port_impl::get_ttl_inheritance_mode() const
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
la_gre_port_impl::set_ttl_inheritance_mode(la_ttl_inheritance_mode_e mode)
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

la_lp_attribute_inheritance_mode_e
la_gre_port_impl::get_lp_attribute_inheritance_mode() const
{
    return m_lp_attribute_inheritance_mode;
}

la_status
la_gre_port_impl::set_lp_attribute_inheritance_mode(la_lp_attribute_inheritance_mode_e mode)
{
    start_api_call("mode=", mode);

    la_status status = m_vrf_port_common->set_lp_attribute_inheritance_mode(mode);
    return_on_error(status);

    m_lp_attribute_inheritance_mode = mode;

    return update_ip_tunnel_dlp_table();
}

la_status
la_gre_port_impl::set_ttl(la_uint8_t ttl)
{
    start_api_call("ttl=", ttl);

    m_ttl = ttl;

    return (update_ip_tunnel_dlp_table());
}

bool
la_gre_port_impl::get_decrement_inner_ttl() const
{
    start_api_getter_call("");

    return m_decrement_inner_ttl;
}

la_status
la_gre_port_impl::set_decrement_inner_ttl(bool decrement_inner_ttl)
{
    start_api_call("decrement_inner_ttl=", decrement_inner_ttl);

    m_decrement_inner_ttl = decrement_inner_ttl;

    return (update_ip_tunnel_dlp_table());
}

la_status
la_gre_port_impl::get_encap_tos(la_ip_tos& out_encap_tos) const
{
    start_api_getter_call("");

    out_encap_tos = m_encap_tos;

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::set_encap_tos(la_ip_tos encap_tos)
{
    start_api_call("encap_tos=", encap_tos);

    m_encap_tos = encap_tos;

    return update_ip_tunnel_dlp_table();
}

la_tunnel_encap_qos_mode_e
la_gre_port_impl::get_encap_qos_mode() const
{
    start_api_getter_call("");

    return m_encap_qos_mode;
}

la_status
la_gre_port_impl::set_encap_qos_mode(la_tunnel_encap_qos_mode_e mode)
{
    start_api_call("mode=", mode);

    m_encap_qos_mode = mode;

    return update_ip_tunnel_dlp_table();
}

void
la_gre_port_impl::release_lps()
{
    teardown_ip_tunnel_dlp_table();
    teardown_lp_attributes_table();
}

la_gre_key_t
la_gre_port_impl::get_key() const
{
    return m_key;
}

la_status
la_gre_port_impl::set_key(la_gre_key_t key)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_gre_seq_num_t
la_gre_port_impl::get_sequence_number() const
{
    return m_sequence_number;
}

la_status
la_gre_port_impl::set_sequence_number(la_gre_seq_num_t sequence_number)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::set_ingress_sflow_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    la_status status = m_vrf_port_common->set_ingress_sflow_enabled(enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::get_ingress_sflow_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    la_status status = m_vrf_port_common->get_ingress_sflow_enabled(out_enabled);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::set_egress_sflow_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::get_egress_sflow_enabled(bool& out_enabled) const
{
    start_api_getter_call();
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::set_tunnel_termination_type(tunnel_termination_type_e tunnel_termination_type)
{
    start_api_call("term_type=", tunnel_termination_type);
    transaction txn = {};
    tunnel_termination_type_e prev_tunnel_termination_type = m_termination_type;
    la_status status = LA_STATUS_SUCCESS;

    if (m_termination_type == tunnel_termination_type) {
        return LA_STATUS_SUCCESS;
    }

    // for encap only tunnels termination is not applicable, return here
    if (m_tunnel_mode == la_ip_tunnel_mode_e::ENCAP_ONLY) {
        return LA_STATUS_SUCCESS;
    }

    if (tunnel_termination_type == tunnel_termination_type_e::P2MP) {
        /*
        * When changing termination to P2MP cannot have another tunnel
        * with the same local IP address in my_ipv4_table
        * the current tunnel is in the table so we need to verify for ref count greater than 1
        */
        uint32_t ref_cnt = 0;
        uint64_t sip_index = 0;
        npl_termination_logical_db_e term_db;
        auto status = m_device->m_ipv4_tunnel_ep_manager->get_local_ep_entry_info(
            m_local_ip_prefix, m_underlay_vrf, NPL_PROTOCOL_TYPE_GRE, ref_cnt, sip_index, term_db);
        if (status == LA_STATUS_SUCCESS) {
            if (ref_cnt > 1) {
                log_err(HLD, "set termination type tp P2MP: tunnel already exist");
                return LA_STATUS_EEXIST;
            }
        }
    }
    // remove the entry from my_ipv4_table
    status = m_device->m_ipv4_tunnel_ep_manager->remove_local_ep_entry(
        m_local_ip_prefix, m_underlay_vrf, NPL_PROTOCOL_TYPE_GRE, m_sip_index->id());
    return_on_error(status, HLD, ERROR, "failed to remove tunnel endpoint");

    // remove ip tunnel termination table entry
    status = teardown_lp_attributes_table();
    return_on_error(status, HLD, ERROR, "failed to teardown lp attr table");

    // program the ip tunnel termination table for new termination type
    m_termination_type = tunnel_termination_type;
    txn.status = update_l3_lp_attributes();
    return_on_error(txn.status, HLD, ERROR, "failed to update lp attributes");
    txn.on_fail([=]() {
        m_termination_type = prev_tunnel_termination_type;
        update_l3_lp_attributes();
    });

    auto npl_termination_type = termination_type_to_npl(tunnel_termination_type);
    auto prev_npl_termination_type = termination_type_to_npl(prev_tunnel_termination_type);
    txn.status = m_device->m_ipv4_tunnel_ep_manager->add_local_ep_entry(
        m_local_ip_prefix, m_underlay_vrf, m_sip_index->id(), NPL_PROTOCOL_TYPE_GRE, npl_termination_type);
    return_on_error(txn.status, HLD, ERROR, "failed to add tunnel endpoint");
    txn.on_fail([=]() {
        m_termination_type = prev_tunnel_termination_type;
        update_l3_lp_attributes();
        m_device->m_ipv4_tunnel_ep_manager->add_local_ep_entry(
            m_local_ip_prefix, m_underlay_vrf, m_sip_index->id(), NPL_PROTOCOL_TYPE_GRE, prev_npl_termination_type);
    });

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::get_tunnel_termination_type(tunnel_termination_type_e& out_term_type) const
{
    out_term_type = m_termination_type;
    return LA_STATUS_SUCCESS;
}

la_gre_port_impl::la_gre_dip_entropy_mode_e
la_gre_port_impl::get_dip_entropy_mode() const
{
    return (m_dip_entropy_mode);
}

la_status
la_gre_port_impl::set_dip_entropy_mode(const la_ipv4_prefix_t remote_ip_prefix)
{
    switch (remote_ip_prefix.length) {
    case 24:
        m_dip_entropy_mode = la_gre_dip_entropy_mode_e::GRE_DIP_ENTROPY_24;
        m_npl_dip_entropy_mode = NPL_GRE_DIP_ENTROPY_24;
        break;

    case 28:
        m_dip_entropy_mode = la_gre_dip_entropy_mode_e::GRE_DIP_ENTROPY_28;
        m_npl_dip_entropy_mode = NPL_GRE_DIP_ENTROPY_28;
        break;

    case 32:
        m_dip_entropy_mode = la_gre_dip_entropy_mode_e::GRE_DIP_ENTROPY_NONE;
        m_npl_dip_entropy_mode = NPL_GRE_DIP_ENTROPY_NONE;
        break;

    default:
        log_err(HLD,
                "Invalid remote prefix %s for GRE DIP entropy (expected "
                "/24, /28, or /32)",
                silicon_one::to_string(remote_ip_prefix).c_str());
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::add_virtual_mac(const la_mac_addr_t& mac_addr)
{
    start_api_call("mac_addr=", mac_addr);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::remove_virtual_mac(const la_mac_addr_t& mac_addr)
{
    start_api_call("mac_addr=", mac_addr);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::get_virtual_macs(la_mac_addr_vec& out_mac_addresses) const
{
    start_api_getter_call();
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::add_tunnel_endpoint()
{
    // for encap only we do not need to update the termination tables
    if (m_tunnel_mode != la_ip_tunnel_mode_e::ENCAP_ONLY) {
        // add the new endpoint to the endpoint database
        auto npl_termination_type = termination_type_to_npl(m_termination_type);
        return m_device->m_ipv4_tunnel_ep_manager->add_local_ep_entry(
            m_local_ip_prefix, m_underlay_vrf, m_sip_index->id(), NPL_PROTOCOL_TYPE_GRE, npl_termination_type);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::remove_tunnel_endpoint()
{
    if (m_tunnel_mode != la_ip_tunnel_mode_e::ENCAP_ONLY) {
        // remove the local IP address from the tunnel endpoint database
        return m_device->m_ipv4_tunnel_ep_manager->remove_local_ep_entry(
            m_local_ip_prefix, m_underlay_vrf, NPL_PROTOCOL_TYPE_GRE, m_sip_index->id());
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_gre_port_impl::set_filter_group(la_filter_group* filter_group)
{
    start_api_call("filter_group=", filter_group);
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_gre_port_impl::get_filter_group(const la_filter_group*& out_filter_group) const
{
    start_api_getter_call();
    return LA_STATUS_ENOTIMPLEMENTED;
}

} // namespace silicon_one
