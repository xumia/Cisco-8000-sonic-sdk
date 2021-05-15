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

#include "api/npu/la_switch.h"

#include "common/defines.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "npu/counter_utils.h"
#include "npu/la_acl_delegate.h"

#include "api/npu/la_vrf.h"
#include "api_tracer.h"
#include "common/logger.h"
#include "la_l2_service_port_base.h"
#include "la_strings.h"
#include "nplapi/npl_constants.h"
#include "npu/ipv4_sip_index_manager.h"
#include "npu/la_ac_port_common.h"
#include "npu/la_acl_impl.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_filter_group_impl.h"
#include "npu/la_switch_impl.h"
#include "npu/resolution_utils.h"
#include "qos/la_egress_qos_profile_impl.h"
#include "qos/la_ingress_qos_profile_impl.h"
#include "qos/la_meter_set_impl.h"
#include "system/la_erspan_mirror_command_base.h"
#include "system/la_l2_mirror_command_base.h"
#include "system/la_spa_port_base.h"
#include "system/la_system_port_base.h"

#include <sstream>
#include <tuple>

namespace silicon_one
{

la_l2_service_port_base::la_l2_service_port_base(const la_device_impl_wptr& device)
    : m_device(device),
      m_port_type(port_type_e::INVALID),
      m_port_gid(LA_L2_PORT_GID_INVALID),
      m_ac_npl_eve_command(),
      m_ac_npl_ive_command(),
      m_stp_state(la_port_stp_state_e::BLOCKING),
      m_learning_mode(la_lp_mac_learning_mode_e::NONE),
      m_ingress_mirror_type(NPL_PORT_MIRROR_TYPE_CONDITIONED),
      m_egress_mirror_type(NPL_PORT_MIRROR_TYPE_CONDITIONED),
      m_attached_switch(nullptr),
      m_recycle_label(),
      m_recycle_destination(nullptr),
      m_attached_destination(nullptr),
      m_filter_group(nullptr),
      m_slice_data_b(ASIC_MAX_SLICES_PER_DEVICE_NUM, slice_data_base()),
      m_slice_pair_data_b(NUM_SLICE_PAIRS_PER_DEVICE, slice_pair_data_base()),
      m_ac_port_common(device),
      m_acls(),
      m_flow_label_enable(false),
      m_control_word_enable(false),
      m_l3_destination(nullptr),
      m_drop_counter_offset(0),
      m_local_ip_addr(),
      m_remote_ip_addr(),
      m_compressed_vxlan_dlp_id(0),
      m_cur_ovl_nh_id(0),
      m_ingress_sflow_enabled(false),
      m_egress_feature_mode(egress_feature_mode_e::L3),
      m_ttl_mode(la_ttl_inheritance_mode_e::PIPE),
      m_ttl(255),
      m_ingress_acl_group(nullptr),
      m_egress_acl_group(nullptr),
      m_rtf_conf_set_ptr(RTF_CONF_SET_ID_INVALID),
      m_down_mep_level(0),
      m_down_mep_enabled(false),
      m_up_mep_level(0),
      m_up_mep_enabled(false),
      m_group_policy_encap(false),
      m_copc_profile(0)
{
}

la_status
la_l2_service_port_base::initialize_common(slice_ifg_vec_t& ifgs)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    la_status status = LA_STATUS_SUCCESS;

    for (la_slice_pair_id_t slice_pair : m_device->get_used_slice_pairs()) {
        status = configure_txpp_dlp_profile_table(slice_pair);
        return_on_error(status);
    }

    for (la_slice_ifg ifg : ifgs) {
        status = add_ifg(ifg);
        return_on_error(status);
    }

    status = update_ingress_acl_id();
    return_on_error(status);

    status = configure_common_tables();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::initialize_ac(la_object_id_t oid,
                                       la_l2_port_gid_t port_gid,
                                       const la_ethernet_port_base_wcptr& ethernet_port,
                                       la_vlan_id_t vid1,
                                       la_vlan_id_t vid2,
                                       const la_filter_group_impl_wcptr& filter_group,
                                       const la_ingress_qos_profile_impl_wptr& ingress_qos_profile_impl,
                                       const la_egress_qos_profile_impl_wptr& egress_qos_profile_impl)
{
    m_oid = oid;
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    // Initialize members
    m_port_type = port_type_e::AC;
    m_port_gid = port_gid;
    m_ac_ethernet_port = ethernet_port.weak_ptr_const_cast<la_ethernet_port_base>();
    m_ac_npl_eve_command.main_type = NPL_VLAN_EDIT_COMMAND_MAIN_OTHER;
    m_ac_npl_eve_command.secondary_type_or_vid_2.secondary_type_with_padding.secondary_type = NPL_VLAN_EDIT_COMMAND_SECONDARY_NOP;
    m_ac_npl_eve_command.secondary_type_or_vid_2.vid2 = 0x0;
    m_ac_npl_ive_command.main_type = NPL_VLAN_EDIT_COMMAND_MAIN_OTHER;
    m_ac_npl_ive_command.secondary_type_or_vid_2.secondary_type_with_padding.secondary_type = NPL_VLAN_EDIT_COMMAND_SECONDARY_NOP;
    m_ac_npl_ive_command.secondary_type_or_vid_2.vid2 = 0x0;

    m_filter_group = filter_group;
    m_ingress_qos_profile = ingress_qos_profile_impl;
    m_egress_qos_profile = egress_qos_profile_impl;

    la_status status = m_ac_port_common.initialize(m_device->get_sptr(this), port_gid, m_ac_ethernet_port, vid1, vid2);
    return_on_error(status);

    m_device->add_object_dependency(ingress_qos_profile_impl, this);
    m_device->add_ifg_dependency(this, ingress_qos_profile_impl);

    m_device->add_object_dependency(egress_qos_profile_impl, this);
    m_device->add_ifg_dependency(this, egress_qos_profile_impl);

    auto ifgs = m_ac_ethernet_port->get_ifgs();

    status = initialize_common(ifgs);
    return_on_error(status);

    m_device->add_object_dependency(m_filter_group, this);

    m_device->add_object_dependency(m_ac_ethernet_port, this);
    m_device->add_ifg_dependency(m_ac_ethernet_port, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::do_initialize_pwe()
{
    transaction txn;
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());

    txn.status = allocate_pwe_slp_ids();
    return_on_error(txn.status);
    txn.on_fail([&]() { deallocate_pwe_slp_ids(); });

    txn.status = configure_pwe_service_lp_attributes_table();
    return_on_error(txn.status);
    txn.on_fail([&]() { teardown_pwe_service_lp_attributes_table(); });

    txn.status = configure_mpls_termination_table();
    return_on_error(txn.status);
    txn.on_fail([&]() { teardown_mpls_termination_table(); });

    txn.status = configure_pwe_encap_table();
    return_on_error(txn.status);
    txn.on_fail([&]() { teardown_pwe_encap_table(); });

    txn.status = instantiate_pwe_l3_destination(m_l3_destination);
    return_on_error(txn.status);
    txn.on_fail([&]() { uninstantiate_pwe_l3_destination(m_l3_destination); });

    m_device->add_object_dependency(m_ingress_qos_profile, this);
    m_device->add_ifg_dependency(this, m_ingress_qos_profile);

    m_device->add_object_dependency(m_egress_qos_profile, this);
    m_device->add_ifg_dependency(this, m_egress_qos_profile);

    m_device->add_object_dependency(m_l3_destination, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::initialize_pwe(la_object_id_t oid,
                                        la_l2_port_gid_t port_gid,
                                        la_mpls_label local_label,
                                        la_mpls_label remote_label,
                                        la_pwe_gid_t pwe_gid,
                                        const la_l3_destination_wptr& destination,
                                        const la_ingress_qos_profile_impl_wptr& ingress_qos_profile_impl,
                                        const la_egress_qos_profile_impl_wptr& egress_qos_profile_impl)
{
    m_oid = oid;

    // Initialize members
    m_port_type = port_type_e::PWE;
    m_port_gid = port_gid;
    m_local_label = local_label;
    m_remote_label = remote_label;
    m_pwe_gid = pwe_gid;
    m_l3_destination = destination;
    m_ingress_qos_profile = ingress_qos_profile_impl;
    m_egress_qos_profile = egress_qos_profile_impl;
    return do_initialize_pwe();
}

la_status
la_l2_service_port_base::initialize_pwe_tagged(la_object_id_t oid,
                                               la_l2_port_gid_t port_gid,
                                               la_mpls_label local_label,
                                               la_mpls_label remote_label,
                                               la_vlan_id_t vid1,
                                               const la_l3_destination_wptr& destination,
                                               const la_ingress_qos_profile_impl_wptr& ingress_qos_profile_impl,
                                               const la_egress_qos_profile_impl_wptr& egress_qos_profile_impl)
{
    m_oid = oid;

    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::vxlan_add_port(la_ipv4_prefix_t local_ip_prefix,
                                        la_ipv4_addr_t remote_ip_addr,
                                        const la_vrf_wptr& vrf,
                                        const la_l2_service_port_wptr& port)
{
    if (vxlan_lookup_port(local_ip_prefix, remote_ip_addr, vrf) != nullptr) {
        log_err(HLD, "port already exist.");
        return LA_STATUS_EEXIST;
    }

    la_device_impl::ipv4_tunnel_id_t ep;

    // set tunnel ID
    ep.local_ip_prefix.addr = local_ip_prefix.addr;
    ep.local_ip_prefix.length = local_ip_prefix.length;
    ep.remote_ip_prefix.addr = remote_ip_addr;
    ep.remote_ip_prefix.length = 32;
    ep.vrf_gid = vrf->get_gid();
    ep.tunnel_type = NPL_IP_TUNNEL_VXLAN;

    // add port to VXLAN port map
    m_device->m_vxlan_port_map[ep] = port;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::vxlan_remove_port(la_ipv4_prefix_t local_ip_prefix, la_ipv4_addr_t remote_ip_addr, const la_vrf_wptr& vrf)
{
    if (vxlan_lookup_port(local_ip_prefix, remote_ip_addr, vrf) == nullptr) {
        log_err(HLD, "no port found");
        return LA_STATUS_ENOTFOUND;
    }

    la_device_impl::ipv4_tunnel_id_t ep;

    // set tunnel ID
    ep.local_ip_prefix.addr = local_ip_prefix.addr;
    ep.local_ip_prefix.length = local_ip_prefix.length;
    ep.remote_ip_prefix.addr = remote_ip_addr;
    ep.remote_ip_prefix.length = 32;
    ep.vrf_gid = vrf->get_gid();
    ep.tunnel_type = NPL_IP_TUNNEL_VXLAN;

    // remove port from VXLAN port map
    m_device->m_vxlan_port_map.erase(ep);

    return LA_STATUS_SUCCESS;
}

la_l2_service_port_wptr
la_l2_service_port_base::vxlan_lookup_port(la_ipv4_prefix_t local_ip_prefix, la_ipv4_addr_t remote_ip_addr, const la_vrf_wptr& vrf)
{
    la_device_impl::ipv4_tunnel_id_t ep;

    // set tunnel ID
    ep.local_ip_prefix.addr = local_ip_prefix.addr;
    ep.local_ip_prefix.length = local_ip_prefix.length;
    ep.remote_ip_prefix.addr = remote_ip_addr;
    ep.remote_ip_prefix.length = 32;
    ep.vrf_gid = vrf->get_gid();
    ep.tunnel_type = NPL_IP_TUNNEL_VXLAN;

    // search for port in VXLAN port map
    auto it = m_device->m_vxlan_port_map.find(ep);

    if (it == m_device->m_vxlan_port_map.end()) {
        return nullptr;
    }

    return (it->second);
}

la_status
la_l2_service_port_base::initialize_vxlan(la_object_id_t oid,
                                          la_l2_port_gid_t port_gid,
                                          la_ip_tunnel_mode_e tunnel_mode,
                                          la_ipv4_prefix_t local_ip_prefix,
                                          la_ipv4_addr_t remote_ip_addr,
                                          const la_vrf_wptr& vrf)
{
    start_api_call("tunnel_mode=", tunnel_mode);
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    m_oid = oid;
    transaction txn;
    m_port_type = port_type_e::VXLAN;
    m_port_gid = port_gid;
    m_local_ip_prefix = local_ip_prefix;
    m_remote_ip_addr = remote_ip_addr;
    m_vrf = vrf;
    m_tunnel_mode = tunnel_mode;
    m_local_ip_addr = local_ip_prefix.addr;

    // For non-encap mode, local ip can be mcast prefix.
    if (tunnel_mode != la_ip_tunnel_mode_e::ENCAP_ONLY) {
        // Other than mcast prefix is invalid
        if (local_ip_prefix.length != 32) {
            if ((local_ip_prefix.length != LA_IPV4_MC_PREFIX.length)
                || ((local_ip_prefix.addr.s_addr & 0xF0000000) != LA_IPV4_MC_PREFIX.addr.s_addr)) {
                return LA_STATUS_EINVAL;
            }
        }
    }

    // check if the vxlan port already exists
    auto lookup_port = vxlan_lookup_port(local_ip_prefix, remote_ip_addr, m_vrf);
    if (lookup_port != nullptr) {
        log_err(HLD, "vxlan port already exists.");
        return LA_STATUS_EEXIST;
    }

    // SIP allocation is needed for all tunnel modes
    txn.status = m_device->m_ipv4_sip_index_manager->allocate_sip_index(local_ip_prefix, m_sip_index);
    return_on_error(txn.status, HLD, ERROR, "allocate_sip_index failed");
    txn.on_fail([=]() { m_device->m_ipv4_sip_index_manager->free_sip_index(m_sip_index); });

    // Compress DLP id for encap_only and encap_decap modes
    if (tunnel_mode != la_ip_tunnel_mode_e::DECAP_ONLY) {
        // allocate overlay nh id
        // Not required for mcast in encap case
        if ((m_remote_ip_addr.s_addr & 0xF0000000) != LA_IPV4_MC_PREFIX.addr.s_addr) {
            bool success = m_device->m_index_generators.vxlan_compressed_dlp_id.allocate(m_compressed_vxlan_dlp_id);
            if (!success) {
                return LA_STATUS_EOUTOFRANGE;
            }
        }
    }

    auto ifgs = get_all_network_ifgs(m_device);
    txn.status = initialize_common(ifgs);
    return_on_error(txn.status);

    // Configure my ipv4 table for decap_only and encap_decap
    if (tunnel_mode != la_ip_tunnel_mode_e::ENCAP_ONLY) {
        // Map remote mcast address to vxlan slp
        if ((local_ip_prefix.addr.s_addr & 0xF0000000) == LA_IPV4_MC_PREFIX.addr.s_addr) {
            txn.status = map_mcast_vxlan_slp();
            return_on_error(txn.status);
        } else {
            std::vector<uint64_t> sip_index_or_local_slp_id;
            sip_index_or_local_slp_id.resize(ASIC_MAX_SLICES_PER_DEVICE_NUM);

            if (tunnel_mode == la_ip_tunnel_mode_e::DECAP_ONLY) {
                for (la_slice_id_t slice : m_device->get_used_slices()) {
                    sip_index_or_local_slp_id[slice] = get_local_slp_id(slice);
                }
                txn.status = m_device->m_ipv4_tunnel_ep_manager->add_local_ep_entry(
                    local_ip_prefix, m_vrf, sip_index_or_local_slp_id, NPL_PROTOCOL_TYPE_UDP, NPL_TERMINATION_DIP_LDB);
            } else { // encap_decap case
                for (la_slice_id_t slice : m_device->get_used_slices()) {
                    sip_index_or_local_slp_id[slice] = m_sip_index->id();
                }
                txn.status = m_device->m_ipv4_tunnel_ep_manager->add_local_ep_entry(
                    local_ip_prefix, m_vrf, sip_index_or_local_slp_id, NPL_PROTOCOL_TYPE_UDP, NPL_TERMINATION_SIP_DIP_INDEX_LDB);
            }
            return_on_error(txn.status, HLD, ERROR, "add_local_ep_entry falied");
            txn.on_fail([=]() {
                m_device->m_ipv4_tunnel_ep_manager->remove_local_ep_entry(
                    local_ip_prefix, m_vrf, NPL_PROTOCOL_TYPE_UDP, sip_index_or_local_slp_id);
            });
            // slp is not needed for decap_only
            if (tunnel_mode == la_ip_tunnel_mode_e::ENCAP_DECAP) {
                txn.status = map_vxlan_slp();
                return_on_error(txn.status);
            }
        }
    }

    // save the port
    txn.status = vxlan_add_port(local_ip_prefix, remote_ip_addr, m_vrf, m_device->get_sptr(this));
    return_on_error(txn.status, HLD, ERROR, "failed to save the vxlan port");

    m_oid = oid;
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::initialize_vxlan(la_object_id_t oid,
                                          la_l2_port_gid_t port_gid,
                                          la_ipv4_addr_t local_ip_addr,
                                          la_ipv4_addr_t remote_ip_addr,
                                          const la_vrf_wptr& vrf)
{
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());
    m_oid = oid;
    transaction txn;
    m_port_type = port_type_e::VXLAN;
    m_port_gid = port_gid;
    m_local_ip_addr = local_ip_addr;
    m_remote_ip_addr = remote_ip_addr;
    m_tunnel_mode = la_ip_tunnel_mode_e::ENCAP_DECAP;
    m_vrf = vrf;

    // program the local ip address in the sip index table

    m_local_ip_prefix.addr = m_local_ip_addr;
    m_local_ip_prefix.length = 32;

    // check if the vxlan port already exists
    auto lookup_port = vxlan_lookup_port(m_local_ip_prefix, remote_ip_addr, m_vrf);
    if (lookup_port != nullptr) {
        log_err(HLD, "vxlan port already exist.");
        return LA_STATUS_EEXIST;
    }

    // allocate overlay nh id
    bool success = m_device->m_index_generators.vxlan_compressed_dlp_id.allocate(m_compressed_vxlan_dlp_id);
    if (!success) {
        return LA_STATUS_EOUTOFRANGE;
    }

    txn.status = m_device->m_ipv4_sip_index_manager->allocate_sip_index(m_local_ip_prefix, m_sip_index);
    return_on_error(txn.status, HLD, ERROR, "allocate_sip_index falied");
    txn.on_fail([=]() { m_device->m_ipv4_sip_index_manager->free_sip_index(m_sip_index); });

    std::vector<uint64_t> sip_index_or_local_slp_id;
    sip_index_or_local_slp_id.resize(ASIC_MAX_SLICES_PER_DEVICE_NUM);
    for (la_slice_id_t slice : m_device->get_used_slices()) {
        sip_index_or_local_slp_id[slice] = m_sip_index->id();
    }

    txn.status = m_device->m_ipv4_tunnel_ep_manager->add_local_ep_entry(
        m_local_ip_prefix, m_vrf, sip_index_or_local_slp_id, NPL_PROTOCOL_TYPE_UDP, NPL_TERMINATION_SIP_DIP_INDEX_LDB);
    return_on_error(txn.status, HLD, ERROR, "add_local_ep_entry falied");
    txn.on_fail([=]() {
        m_device->m_ipv4_tunnel_ep_manager->remove_local_ep_entry(
            m_local_ip_prefix, m_vrf, NPL_PROTOCOL_TYPE_UDP, sip_index_or_local_slp_id);
    });

    auto ifgs = get_all_network_ifgs(m_device);
    txn.status = initialize_common(ifgs);
    return_on_error(txn.status);

    // map the remote ip address to the vxlan slp
    txn.status = map_vxlan_slp();
    return_on_error(txn.status);

    // save the port
    txn.status = vxlan_add_port(m_local_ip_prefix, remote_ip_addr, m_vrf, m_device->get_sptr(this));
    return_on_error(txn.status, HLD, ERROR, "failed to save the vxlan port");

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::do_destroy_vxlan()
{
    if (m_encap_vni_map.size()) {
        return LA_STATUS_EBUSY;
    }

    la_status status;
    // delete ep entry and vxlan slp mapping table entry
    if (m_tunnel_mode != la_ip_tunnel_mode_e::ENCAP_ONLY) {
        if ((m_local_ip_prefix.addr.s_addr & 0xF0000000) == LA_IPV4_MC_PREFIX.addr.s_addr) {
            status = unmap_mcast_vxlan_slp();
            return_on_error(status);
        } else {
            std::vector<uint64_t> sip_index_or_local_slp_id;
            sip_index_or_local_slp_id.resize(ASIC_MAX_SLICES_PER_DEVICE_NUM);

            if (m_tunnel_mode == la_ip_tunnel_mode_e::DECAP_ONLY) {
                for (la_slice_id_t slice : m_device->get_used_slices()) {
                    sip_index_or_local_slp_id[slice] = get_local_slp_id(slice);
                }
            } else { // encap_decap case
                for (la_slice_id_t slice : m_device->get_used_slices()) {
                    sip_index_or_local_slp_id[slice] = m_sip_index->id();
                }
            }

            status = m_device->m_ipv4_tunnel_ep_manager->remove_local_ep_entry(
                m_local_ip_prefix, m_vrf, NPL_PROTOCOL_TYPE_UDP, sip_index_or_local_slp_id);
            return_on_error(status);

            if (m_tunnel_mode == la_ip_tunnel_mode_e::ENCAP_DECAP) {
                status = unmap_vxlan_slp();
                return_on_error(status);
            }
        }
    }

    status = m_device->m_ipv4_sip_index_manager->free_sip_index(m_sip_index);
    return_on_error(status);

    // delete it from the vxlan port data base
    status = vxlan_remove_port(m_local_ip_prefix, m_remote_ip_addr, m_vrf);
    return_on_error(status);

    // release the tunnel ovl nh id
    if (m_tunnel_mode != la_ip_tunnel_mode_e::DECAP_ONLY) {
        if ((m_remote_ip_addr.s_addr & 0xF0000000) != LA_IPV4_MC_PREFIX.addr.s_addr) {
            m_device->m_index_generators.vxlan_compressed_dlp_id.release(m_compressed_vxlan_dlp_id);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    do_detach();

    if (m_ac_ethernet_port != nullptr) {
        m_device->remove_object_dependency(m_ac_ethernet_port, this);
        m_device->remove_ifg_dependency(m_ac_ethernet_port, this);
    }

    if (m_port_type == port_type_e::AC) {
        m_ac_port_common.destroy();
    }

    if (m_l3_destination != nullptr) {
        m_device->remove_object_dependency(m_l3_destination, this);
    }

    if (m_ingress_mirror_cmd != nullptr) {
        m_device->remove_object_dependency(m_ingress_mirror_cmd, this);
    }

    if (m_egress_mirror_cmd != nullptr) {
        m_device->remove_object_dependency(m_egress_mirror_cmd, this);
    }

    if (m_filter_group != nullptr) {
        m_device->remove_object_dependency(m_filter_group, this);
    }

    if (m_ingress_acl_group != nullptr) {
        m_device->remove_object_dependency(m_ingress_acl_group, this);
    }

    la_status status = teardown_tables();
    return_on_error(status);

    if (m_meter != nullptr) {
        status = m_meter->detach_user(m_device->get_sptr(this));
        return_on_error(status);
        m_meter = nullptr;
    }

    auto ifgs = m_ifg_use_count->get_ifgs();

    for (la_slice_ifg ifg : ifgs) {
        la_status status = remove_ifg(ifg);
        return_on_error(status);
    }

    if (m_port_type == port_type_e::AC) {
        for (la_slice_pair_id_t slice_pair : m_device->get_used_slice_pairs()) {
            status = teardown_txpp_dlp_profile_table(slice_pair);
            return_on_error(status);
        }
    }

    if (m_ingress_qos_profile != nullptr) {
        m_device->remove_object_dependency(m_ingress_qos_profile, this);
        m_device->remove_ifg_dependency(this, m_ingress_qos_profile);
    }

    if (m_egress_qos_profile != nullptr) {
        m_device->remove_object_dependency(m_egress_qos_profile, this);
        m_device->remove_ifg_dependency(this, m_egress_qos_profile);
    }

    auto counters = {m_p_counter[COUNTER_DIRECTION_EGRESS],
                     m_p_counter[COUNTER_DIRECTION_INGRESS],
                     m_q_counter[COUNTER_DIRECTION_EGRESS],
                     m_q_counter[COUNTER_DIRECTION_INGRESS]};

    for (const auto& counter : counters) {
        if (counter != nullptr) {
            m_device->remove_ifg_dependency(this, counter);
            m_device->remove_object_dependency(counter, this);
            counter->remove_pq_counter_user(m_device->get_sptr(this));
        }
    }

    if (m_port_type == port_type_e::VXLAN) {
        status = do_destroy_vxlan();
        return_on_error(status);
    }

    if (m_port_type == port_type_e::PWE) {
        clear_ac_profile_for_pwe();
        status = teardown_mpls_termination_table();
        return_on_error(status);
        status = teardown_pwe_service_lp_attributes_table();
        return_on_error(status);
        status = teardown_pwe_encap_table();
        return_on_error(status);
        status = uninstantiate_pwe_l3_destination(m_l3_destination);
        return_on_error(status);
        m_device->remove_object_dependency(m_l3_destination, this);
        deallocate_pwe_slp_ids();
    }

    if (m_port_type == port_type_e::PWE_TAGGED) {
        status = teardown_pwe_port_tag_table();
        return_on_error(status);

        auto it = m_device->m_pwe_tagged_local_labels_map.find(m_local_label.label);
        if (it == m_device->m_pwe_tagged_local_labels_map.end()) {
            return LA_STATUS_EUNKNOWN;
        }

        auto& desc = it->second;
        desc.use_count--;
        if (desc.use_count == 0) {

            status = teardown_mpls_termination_table();
            return_on_error(status);

            m_device->m_pwe_tagged_local_labels_map.erase(it);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_ingress_qos_profile(la_ingress_qos_profile* ingress_qos_profile)
{
    start_api_call("ingress_qos_profile=", ingress_qos_profile);

    // Sanity
    if (ingress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(ingress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_ingress_qos_profile == ingress_qos_profile) {
        return LA_STATUS_SUCCESS;
    }

    la_ingress_qos_profile_impl* ingress_qos_profile_impl = static_cast<la_ingress_qos_profile_impl*>(ingress_qos_profile);

    la_ingress_qos_profile_impl* old_profile = m_ingress_qos_profile.get();

    la_status status = add_current_ifgs(this, ingress_qos_profile_impl);
    return_on_error(status);

    m_device->add_ifg_dependency(this, ingress_qos_profile_impl);
    m_device->add_object_dependency(ingress_qos_profile, this);

    m_ingress_qos_profile = m_device->get_sptr(ingress_qos_profile_impl);

    // Prepare payload
    npl_mac_lp_attributes_payload_t payload;
    populate_lp_attributes_payload(payload);

    // Update the service LP attributes table
    status = update_lp_attributes_payload(payload);
    return_on_error(status);

    m_device->remove_ifg_dependency(this, old_profile);
    m_device->remove_object_dependency(old_profile, this);

    status = remove_current_ifgs(this, old_profile);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::notify_change(dependency_management_op op)
{
    switch (op.type_e) {
    case dependency_management_op::management_type_e::ATTRIBUTE_MANAGEMENT:
        switch (op.action.attribute_management.op) {
        case attribute_management_op::PWE_L3_DESTINATION_ATTRIB_CHANGED:
            return update_lp_attributes_destination_id(m_attached_destination);
        case attribute_management_op::ACL_GROUP_CHANGED:
            return update_dependent_attributes(op);
        default:
            return LA_STATUS_EUNKNOWN;
        }
        break;

    case dependency_management_op::management_type_e::IFG_MANAGEMENT:
        if (op.action.ifg_management.ifg_op == ifg_management_op::IFG_ADD) {
            return add_ifg(op.action.ifg_management.ifg);
        } else {
            return remove_ifg(op.action.ifg_management.ifg);
        }
    default:
        log_err(HLD,
                "la_l2_service_port_base::notify_change received unsupported notification (%s)",
                silicon_one::to_string(op.type_e).c_str());
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
la_l2_service_port_base::get_ingress_qos_profile(la_ingress_qos_profile*& out_ingress_qos_profile) const
{
    start_api_call("");

    out_ingress_qos_profile = m_ingress_qos_profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_egress_qos_profile(la_egress_qos_profile* egress_qos_profile)
{
    start_api_call("egress_qos_profile=", egress_qos_profile);

    // Sanity
    if (egress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(egress_qos_profile, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_egress_qos_profile == egress_qos_profile) {
        return LA_STATUS_SUCCESS;
    }

    la_egress_qos_profile_impl* egress_qos_profile_impl = static_cast<la_egress_qos_profile_impl*>(egress_qos_profile);
    la_egress_qos_profile_impl* old_profile = m_egress_qos_profile.get();

    // Tell the policy about all our IFGs (triggers TCAM programming)
    la_status status = add_current_ifgs(this, egress_qos_profile_impl);
    return_on_error(status);
    m_device->add_ifg_dependency(this, egress_qos_profile_impl);
    m_device->add_object_dependency(egress_qos_profile, this);

    m_egress_qos_profile = m_device->get_sptr(egress_qos_profile_impl);

    // Update device
    auto slice_pairs = m_ifg_use_count->get_slice_pairs();

    for (la_slice_pair_id_t slice_pair : slice_pairs) {
        configure_txpp_dlp_profile_table(slice_pair);

        status = configure_l2_dlp_table(slice_pair);
        return_on_error(status);
    }

    m_device->remove_ifg_dependency(this, old_profile);
    m_device->remove_object_dependency(old_profile, this);

    status = remove_current_ifgs(this, old_profile);
    return_on_error(status);

    status = notify_l2_dlp_attrib_change();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_egress_qos_profile(la_egress_qos_profile*& out_egress_qos_profile) const
{
    start_api_call("");

    out_egress_qos_profile = m_egress_qos_profile.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_mac_learning_mode(la_lp_mac_learning_mode_e& out_learning_mode)
{
    out_learning_mode = m_learning_mode;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_mac_learning_mode(la_lp_mac_learning_mode_e learning_mode)
{
    start_api_call("learning_mode=", learning_mode);
    npl_mac_lp_attributes_payload_t payload;
    populate_lp_attributes_payload(payload);

    // Update the service LP attributes table
    npl_learn_type_e learn_type = get_npl_learn_type(m_stp_state, learning_mode);

    payload.layer.two.learn_type = learn_type;

    la_status status = update_lp_attributes_payload(payload);
    return_on_error(status);

    // Update cached value
    m_learning_mode = learning_mode;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_remote_ip_addr(la_ipv4_addr_t& out_remote_ip_addr) const
{
    out_remote_ip_addr = m_remote_ip_addr;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_local_ip_addr(la_ipv4_addr_t& out_local_ip_addr) const
{
    out_local_ip_addr = m_local_ip_addr;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_vrf(const la_vrf*& out_vrf) const
{
    out_vrf = m_vrf.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_l3_destination(const la_l3_destination*& out_l3_destination) const
{
    start_api_getter_call("");
    out_l3_destination = m_l3_destination.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_recycle_destination(const la_next_hop*& out_nh) const
{
    if (m_recycle_destination == nullptr) {
        return LA_STATUS_EINVAL;
    }
    out_nh = m_recycle_destination.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_recycle_label(la_mpls_label& out_label) const
{
    out_label = m_recycle_label;

    return LA_STATUS_SUCCESS;
}

la_l2_port_gid_t
la_l2_service_port_base::get_gid() const
{
    start_api_getter_call("");
    return m_port_gid;
}

la_l2_service_port::port_type_e
la_l2_service_port_base::get_port_type() const
{
    start_api_getter_call("");
    return m_port_type;
}

la_status
la_l2_service_port_base::add_service_mapping_vid(la_vlan_id_t vid)
{
    start_api_call("vid=", vid);
    if (m_port_type != port_type_e::AC) {
        return LA_STATUS_EINVAL;
    }

    la_status status = m_ac_port_common.add_service_mapping_vid(vid);
    return status;
}

la_status
la_l2_service_port_base::remove_service_mapping_vid(la_vlan_id_t vid)
{
    start_api_call("vid=", vid);
    if (m_port_type != port_type_e::AC) {
        return LA_STATUS_EINVAL;
    }
    la_status status = m_ac_port_common.remove_service_mapping_vid(vid);
    return status;
}

la_status
la_l2_service_port_base::get_service_mapping_vid_list(la_vid_vec_t& out_mapped_vids) const
{
    if (m_port_type != port_type_e::AC) {
        return LA_STATUS_EINVAL;
    }
    la_status status = m_ac_port_common.get_service_mapping_vid_list(out_mapped_vids);
    return status;
}

la_status
la_l2_service_port_base::set_service_mapping_vids(la_vlan_id_t vid1, la_vlan_id_t vid2)
{
    start_api_call("vid1=", vid1, "vid2=", vid2);
    if (m_port_type != port_type_e::AC) {
        return LA_STATUS_EINVAL;
    }
    la_status status = m_ac_port_common.set_service_mapping_vids(vid1, vid2);
    return status;
}

la_status
la_l2_service_port_base::get_service_mapping_vids(la_vlan_id_t& out_vid1, la_vlan_id_t& out_vid2) const
{
    if (m_port_type != port_type_e::AC) {
        return LA_STATUS_EINVAL;
    }
    la_status status = m_ac_port_common.get_service_mapping_vids(out_vid1, out_vid2);
    return status;
}

const la_ethernet_port_base_wcptr
la_l2_service_port_base::get_ethernet_port() const
{
    return m_ac_ethernet_port;
}

la_status
la_l2_service_port_base::get_ethernet_port(const la_ethernet_port*& out_ethernet_port) const
{
    start_api_getter_call("");
    out_ethernet_port = get_ethernet_port().get();
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_ingress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned)
{
    start_api_call("mirror_cmd=", mirror_cmd, "is_acl_conditioned=", is_acl_conditioned);

    if (mirror_cmd != nullptr && !of_same_device(mirror_cmd, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (mirror_cmd != nullptr) {
        la_status status = verify_matching_mirror_types(mirror_cmd, mirror_type_e::MIRROR_INGRESS);
        return_on_error(status);
    }

    if (m_ingress_mirror_cmd != nullptr) {
        m_device->remove_object_dependency(m_ingress_mirror_cmd, this);
    }

    m_ingress_mirror_cmd = m_device->get_sptr(mirror_cmd);
    m_ingress_mirror_type = is_acl_conditioned ? NPL_PORT_MIRROR_TYPE_CONDITIONED : NPL_PORT_MIRROR_TYPE_UN_CONDITIONED;

    npl_mac_lp_attributes_payload_t payload;
    populate_lp_attributes_payload(payload);

    // Update the service LP attributes table
    la_status status = update_lp_attributes_payload(payload);
    return_on_error(status);

    if (mirror_cmd != nullptr) {
        m_device->add_object_dependency(mirror_cmd, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_ingress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const
{
    start_api_getter_call();

    out_mirror_cmd = m_ingress_mirror_cmd.get();
    out_is_acl_conditioned = (m_ingress_mirror_type == NPL_PORT_MIRROR_TYPE_CONDITIONED);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned)
{
    start_api_call("mirror_cmd=", mirror_cmd, "is_acl_conditioned=", is_acl_conditioned);

    if (mirror_cmd != nullptr && !of_same_device(mirror_cmd, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (mirror_cmd != nullptr) {
        la_status status = verify_matching_mirror_types(mirror_cmd, mirror_type_e::MIRROR_EGRESS);
        return_on_error(status);
    }

    if (m_egress_mirror_cmd != nullptr) {
        m_device->remove_object_dependency(m_egress_mirror_cmd, this);
    }

    m_egress_mirror_cmd = m_device->get_sptr(mirror_cmd);
    m_egress_mirror_type = is_acl_conditioned ? NPL_PORT_MIRROR_TYPE_CONDITIONED : NPL_PORT_MIRROR_TYPE_UN_CONDITIONED;
    auto slices = m_ifg_use_count->get_slices();

    for (auto slice : slices) {
        // Update the L2 DLP table
        la_slice_pair_id_t pair_idx = slice / 2;
        la_status status = configure_l2_dlp_table(pair_idx);
        return_on_error(status);
    }

    if (mirror_cmd != nullptr) {
        m_device->add_object_dependency(mirror_cmd, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_egress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const
{
    start_api_getter_call();

    out_mirror_cmd = m_egress_mirror_cmd.get();
    out_is_acl_conditioned = (m_egress_mirror_type == NPL_PORT_MIRROR_TYPE_CONDITIONED);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_stp_state(la_port_stp_state_e& out_state) const
{
    start_api_call("");
    if (m_port_type == port_type_e::VXLAN) {
        return LA_STATUS_EINVAL;
    }
    out_state = m_stp_state;
    return LA_STATUS_SUCCESS;
}

template <class _EntryType>
la_status
la_l2_service_port_base::do_set_stp_state(const weak_ptr_unsafe<_EntryType>& dlp_entry, bool state)
{
    auto dlp_v(dlp_entry->value());
    dlp_v.payloads.l2_dlp_attributes.stp_state_is_block = state;
    return dlp_entry->update(dlp_v);
}

la_status
la_l2_service_port_base::set_stp_state(la_port_stp_state_e state)
{
    start_api_call("state=", state);
    bool stp_state_block = (state != la_port_stp_state_e::FORWARDING);

    if (m_port_type == port_type_e::VXLAN) {
        return LA_STATUS_EINVAL;
    }

    auto slices = m_ifg_use_count->get_slices();
    for (la_slice_id_t slice : slices) {
        la_status status;
        // Update the L2 DLP table
        la_slice_pair_id_t pair_idx = slice / 2;

        const auto& dlp_entry = m_slice_pair_data_b[pair_idx].l2_dlp_entry;
        status = do_set_stp_state(dlp_entry, stp_state_block);

        return_on_error(status, HLD, ERROR, "failed to update L2 DLP table entry for slice %d.", slice);
    }

    // Update the service LP attributes table
    npl_mac_lp_attributes_payload_t payload;
    populate_lp_attributes_payload(payload);

    payload.layer.two.shared.stp_state_block = stp_state_block;
    payload.layer.two.learn_type = get_npl_learn_type(state, m_learning_mode);

    la_status attribute_status = update_lp_attributes_payload(payload);
    return_on_error(attribute_status);

    // Update cached value
    m_stp_state = state;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_filter_group(const la_filter_group*& out_filter_group) const
{
    start_api_call("");

    out_filter_group = m_filter_group.get();
    return LA_STATUS_SUCCESS;
}

template <class _EntryType>
la_status
la_l2_service_port_base::do_set_vxlan_filter_group(const weak_ptr_unsafe<_EntryType>& dlp_entry, uint64_t group_id)
{
    if (m_tunnel_mode != la_ip_tunnel_mode_e::DECAP_ONLY) {
        auto dlp_v(dlp_entry->value());
        dlp_v.payloads.vxlan_tunnel_attributes.lp_profile = group_id;
        return dlp_entry->update(dlp_v);
    }
    return LA_STATUS_SUCCESS;
}

template <class _EntryType>
la_status
la_l2_service_port_base::do_set_filter_group(const weak_ptr_unsafe<_EntryType>& dlp_entry, uint64_t group_id)
{
    auto dlp_v(dlp_entry->value());
    dlp_v.payloads.l2_dlp_attributes.dlp_attributes.lp_profile = group_id;
    return dlp_entry->update(dlp_v);
}

la_status
la_l2_service_port_base::set_filter_group(la_filter_group* filter_group)
{
    start_api_call("filter_group=", filter_group);
    if (filter_group == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(filter_group, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    auto group_impl = static_cast<const la_filter_group_impl*>(filter_group);
    uint64_t group_id = group_impl->get_id();
    la_slice_id_vec_t slices;
    if (m_port_type == port_type_e::PWE || m_port_type == port_type_e::PWE_TAGGED) {
        slices = get_slice_pairs(m_device, la_slice_mode_e::NETWORK);
    } else {
        slices = m_ifg_use_count->get_slices();
    }

    for (la_slice_id_t slice : slices) {
        la_status status;
        // Update the L2 DLP table
        la_slice_pair_id_t pair_idx = slice / 2;

        if (m_port_type == port_type_e::VXLAN) {
            auto& vxlan_dlp_entry = m_slice_pair_data_b[pair_idx].vxlan_l2_dlp_entry;
            status = do_set_vxlan_filter_group(vxlan_dlp_entry, group_id);
        } else {
            if (m_port_type == port_type_e::PWE || m_port_type == port_type_e::PWE_TAGGED) {
                if (!m_attached_destination) {
                    status = do_set_pwe_vpls_filter_group(pair_idx, group_id);
                }
            } else {
                auto& dlp_entry = m_slice_pair_data_b[pair_idx].l2_dlp_entry;
                status = do_set_filter_group(dlp_entry, group_id);
            }
        }

        // Check update status
        return_on_error(status);
    }

    // Update the service LP attributes table

    npl_mac_lp_attributes_payload_t payload;
    populate_lp_attributes_payload(payload);

    payload.layer.two.shared.lp_profile = group_id;

    la_status attribute_status = update_lp_attributes_payload(payload);
    return_on_error(attribute_status);

    if (m_filter_group != nullptr) {
        m_device->remove_object_dependency(m_filter_group, this);
    }

    m_device->add_object_dependency(group_impl, this);

    m_filter_group = m_device->get_sptr(group_impl);
    return LA_STATUS_SUCCESS;
}

template <class _EntryType>
la_status
la_l2_service_port_base::do_set_egress_vlan_edit_command(const weak_ptr_unsafe<_EntryType>& dlp_entry,
                                                         npl_ive_profile_and_data_t npl_edit_command)
{
    auto dlp_v(dlp_entry->value());
    dlp_v.payloads.l2_dlp_attributes.l2_dlp_specific.ac.eve_types.eve = npl_edit_command;
    return dlp_entry->update(dlp_v);
}

la_status
la_l2_service_port_base::set_egress_vlan_edit_command(const la_vlan_edit_command& edit_command)
{
    start_api_call("edit_command=", edit_command);
    npl_ive_profile_and_data_t npl_edit_command;

    if ((m_port_type == port_type_e::VXLAN) || (m_port_type == port_type_e::PWE)) {
        return LA_STATUS_EINVAL;
    }

    la_status status = m_device->get_npl_vlan_edit_command(edit_command, npl_edit_command);
    return_on_error(status);

    auto slice_pairs = m_ifg_use_count->get_slice_pairs();

    for (la_slice_pair_id_t pair_idx : slice_pairs) {
        const auto& dlp_entry = m_slice_pair_data_b[pair_idx].l2_dlp_entry;
        status = do_set_egress_vlan_edit_command(dlp_entry, npl_edit_command);
        return_on_error(status);
    }

    m_ac_npl_eve_command = npl_edit_command;

    status = notify_l2_dlp_attrib_change();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_egress_vlan_edit_command(la_vlan_edit_command& out_edit_command) const
{
    if (m_port_type == port_type_e::VXLAN) {
        return LA_STATUS_EINVAL;
    }

    la_status status = m_device->get_la_vlan_edit_command(m_ac_npl_eve_command, out_edit_command);
    return status;
}

la_status
la_l2_service_port_base::get_event_enabled(la_event_e event, bool& out_enabled) const
{
    start_api_call("event=", event);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_l2_service_port_base::set_event_enabled(la_event_e event, bool enabled)
{
    start_api_call("event=", event, "enabled=", enabled);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_l2_service_port_base::set_ingress_vlan_edit_command(const la_vlan_edit_command& edit_command)
{
    start_api_call("edit_command=", edit_command);

    if ((m_port_type == port_type_e::VXLAN) || (m_port_type == port_type_e::PWE)) {
        return LA_STATUS_EINVAL;
    }

    npl_ive_profile_and_data_t npl_edit_command;
    la_status status = m_device->get_npl_vlan_edit_command(edit_command, npl_edit_command);
    return_on_error(status);

    npl_mac_lp_attributes_payload_t payload;
    populate_lp_attributes_payload(payload);

    payload.layer.two.term.ive_profile_and_data = npl_edit_command;

    status = update_lp_attributes_payload(payload);
    return_on_error(status);

    m_ac_npl_ive_command = npl_edit_command;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_ingress_vlan_edit_command(la_vlan_edit_command& out_edit_command) const
{
    if ((m_port_type == port_type_e::VXLAN) || (m_port_type == port_type_e::PWE)) {
        return LA_STATUS_EINVAL;
    }

    la_status status = m_device->get_la_vlan_edit_command(m_ac_npl_ive_command, out_edit_command);
    return status;
}

la_status
la_l2_service_port_base::get_destination(const la_l2_destination*& out_destination) const
{
    start_api_call("");
    out_destination = m_attached_destination.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_destination(const la_l3_destination*& out_destination) const
{
    start_api_call("");
    out_destination = m_l3_destination.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::attach_to_switch(const la_switch* sw)
{
    start_api_call("sw=", sw);
    // Check arguments
    if (sw == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(sw, m_device)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (m_attached_destination != nullptr || m_attached_switch != nullptr) {
        return LA_STATUS_EBUSY;
    }

    // Update switch setting - different implementation per service port type
    auto sw_sptr = m_device->get_sptr<la_switch_impl>(const_cast<la_switch*>(sw));
    la_status status = set_switch(sw_sptr);
    return_on_error(status);

    auto sw_impl = const_cast<la_switch_impl*>(static_cast<const la_switch_impl*>(sw));
    status = sw_impl->handle_new_attachment(this);
    return_on_error(status);

    m_device->add_object_dependency(sw, this);
    m_device->add_ifg_dependency(this, sw_impl);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_attached_switch(const la_switch*& out_switch) const
{
    start_api_call("");
    out_switch = m_attached_switch.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::update_lp_attributes_destination_id(const la_l2_destination_wcptr& destination)
{
    uint64_t p2p = (destination) ? 1 : 0;
    uint64_t sgid = (destination) ? 0 : NPL_DESTINATION_MASK_L2_DLP | m_port_gid;

    npl_mac_lp_attributes_payload_t payload;
    populate_lp_attributes_payload(payload);

    uint64_t dgid = 0;
    la_status status = get_attached_destination_id(destination, dgid);
    return_on_error(status);

    payload.layer.two.shared.p2p = p2p;
    payload.layer.two.shared.sec_acl_attributes.slp_dlp.global_slp_id = sgid;
    payload.layer.two.shared.sec_acl_attributes.slp_dlp.global_dlp_id = dgid;

    status = update_lp_attributes_payload(payload);
    if (status != LA_STATUS_SUCCESS) {
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_destination(const la_l2_destination* destination)
{
    start_api_call("destination=", destination);

    if (m_attached_switch != nullptr) {
        return LA_STATUS_EBUSY;
    }

    if (m_attached_destination == destination) {
        return LA_STATUS_SUCCESS;
    }

    const la_l2_destination_wcptr& destination_sptr = m_device->get_sptr(destination);

    // Update table
    la_status status = service_mapping_set_destination_p2p_pwe(destination_sptr);
    return_on_error(status);

    status = update_lp_attributes_destination_id(destination_sptr);
    return_on_error(status);

    auto old_destination = m_attached_destination;
    m_attached_destination = destination_sptr;

    bit_vector l2_attributes((la_uint64_t)attribute_management_op::PWE_L3_DESTINATION_ATTRIB_CHANGED);

    if (m_attached_destination) {
        m_device->add_attribute_dependency(m_attached_destination, this, l2_attributes);
        m_device->add_object_dependency(m_attached_destination, this);
    }

    if (old_destination) {
        m_device->remove_attribute_dependency(old_destination, this, l2_attributes);
        m_device->remove_object_dependency(old_destination, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_pwe_gid(la_pwe_gid_t& out_pwe_gid) const
{
    if (m_port_type != port_type_e::PWE) {
        return LA_STATUS_EINVAL;
    }

    out_pwe_gid = m_pwe_gid;
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_acl_group_by_packet_format(la_acl_direction_e dir,
                                                        la_acl_packet_format_e packet_format,
                                                        const la_acl_group_wcptr& acl_group)
{
    la_status status;
    const auto& acl_group_base = acl_group.weak_ptr_static_cast<const la_acl_group_base>();

    la_acl_wptr_vec_t acls = {};
    status = acl_group_base->get_real_acls(packet_format, acls);
    return_on_error(status);

    std::vector<la_acl_delegate_wptr> old_acls = m_delegate_acls[(int)packet_format][(int)dir];
    m_delegate_acls[(int)packet_format][(int)dir].clear();

    for (auto& acl : acls) {
        if (acl == nullptr) {
            continue;
        }
        if (!of_same_device(acl, m_device)) {
            return LA_STATUS_EDIFFERENT_DEVS;
        }

        const la_acl_key_profile* acl_key_profile;
        const la_acl_command_profile* acl_command_profile;
        la_acl_key_type_e key_type;

        auto acl_delegate = get_delegate(acl);

        if (acl_delegate == nullptr) {
            return LA_STATUS_EUNKNOWN;
        }

        status = acl->get_acl_key_profile(acl_key_profile);
        return_on_error(status);

        status = acl->get_acl_command_profile(acl_command_profile);
        return_on_error(status);

        status = acl_key_profile->get_key_type(key_type);
        return_on_error(status);

        la_acl_direction_e acl_key_dir = acl_key_profile->get_direction();

        status = validate_direction(dir, acl_key_dir);
        return_on_error(status);

        // Make-before-break. Add IFGs to new acl, swap, then remove from old acl
        status = add_current_ifgs(this, acl_delegate);
        return_on_error(status);

        m_device->add_ifg_dependency(this, acl_delegate);
        m_device->add_object_dependency(acl, this);

        m_delegate_acls[(int)packet_format][(int)dir].push_back(acl_delegate);
    }

    for (auto& old_acl : old_acls) {
        m_device->remove_ifg_dependency(this, old_acl);
        m_device->remove_object_dependency(old_acl->get_acl_parent(), this);

        status = remove_current_ifgs(this, old_acl.get());
        return_on_error(status);
    }

    if (dir == la_acl_direction_e::EGRESS) {
        for (la_slice_pair_id_t pair_idx : m_device->get_used_slice_pairs()) {
            la_status status = configure_txpp_dlp_profile_table(pair_idx);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::validate_set_acl_group(la_acl_direction_e dir, const la_acl_group_wcptr& acl_group) const
{
    if (dir == la_acl_direction_e::EGRESS) {
        la_status status;
        const auto& acl_group_base = acl_group.weak_ptr_static_cast<const la_acl_group_base>();
#if 0
        la_acl_wptr_vec_t ipv4_acls;
        la_acl_wptr_vec_t ipv6_acls;

        status = acl_group_base->get_real_acls(la_acl_packet_format_e::IPV4, ipv4_acls);
        status = acl_group_base->get_real_acls(la_acl_packet_format_e::IPV6, ipv6_acls);
        return_on_error(status);

        if (ipv4_acls.size() > 0 || ipv6_acls.size() > 0) {
            log_err(HLD, "la_l2_service_port_base::%s only ethernet acls list can be attached to l2 port", __func__);
            return LA_STATUS_EINVAL;
        }
#endif
        la_acl_wptr_vec_t eth_acls;
        status = acl_group_base->get_real_acls(la_acl_packet_format_e::ETHERNET, eth_acls);

        if (eth_acls.size() > 1) {
            log_err(HLD, "Cannot attach more than 1 ACL to the port at egress, (%ld given)", eth_acls.size());
            return LA_STATUS_EINVAL;
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::validate_direction(la_acl_direction_e dir, la_acl_direction_e acl_key_dir) const
{
    if (dir == la_acl_direction_e::INGRESS && acl_key_dir != la_acl_direction_e::INGRESS) {
        log_err(HLD, "la_l2_service_port_base::%s Acl attached to ingress port can not have key profile of EGRESS type", __func__);
        return LA_STATUS_EINVAL;
    }

    if (dir == la_acl_direction_e::EGRESS && acl_key_dir != la_acl_direction_e::EGRESS) {
        log_err(HLD, "la_l2_service_port_base::%s Acl attached to egress port can not have key profile of INGRESS type", __func__);
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_acl_group(la_acl_direction_e dir, la_acl_group* acl_group)
{
    start_api_call("dir=", dir, "acl_group=", acl_group);
    la_status status;
    const la_acl_group_wptr& acl_group_sp = m_device->get_sptr(acl_group);

    // Add const to input acl_group to verify it is not changed.
    const auto& acl_group_const = acl_group_sp.weak_ptr_const_cast<const la_acl_group>();
    if (dir == la_acl_direction_e::INGRESS && m_ingress_acl_group != nullptr) {
        if (m_ingress_acl_group == acl_group_const) {
            return LA_STATUS_SUCCESS;
        }
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::ACL_GROUP_CHANGED);
        m_device->remove_attribute_dependency(m_ingress_acl_group, this, registered_attributes);
        m_device->remove_object_dependency(m_ingress_acl_group, this);
        m_ingress_acl_group = nullptr;
    }

    if (dir == la_acl_direction_e::EGRESS && m_egress_acl_group != nullptr) {
        if (m_egress_acl_group == acl_group_const) {
            return LA_STATUS_SUCCESS;
        }
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::ACL_GROUP_CHANGED);
        m_device->remove_attribute_dependency(m_egress_acl_group, this, registered_attributes);
        m_device->remove_object_dependency(m_egress_acl_group, this);
        m_egress_acl_group = nullptr;
    }

    status = validate_set_acl_group(dir, acl_group_const);
    return_on_error(status);

    if (dir == la_acl_direction_e::INGRESS) {
        m_ingress_acl_group = acl_group_sp;
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::ACL_GROUP_CHANGED);
        m_device->add_attribute_dependency(m_ingress_acl_group, this, registered_attributes);

        status = set_acl_group_by_packet_format(dir, la_acl_packet_format_e::ETHERNET, acl_group_const);
        return_on_error(status);
        status = set_acl_group_by_packet_format(dir, la_acl_packet_format_e::IPV4, acl_group_const);
        return_on_error(status);
        status = set_acl_group_by_packet_format(dir, la_acl_packet_format_e::IPV6, acl_group_const);
        return_on_error(status);
    }
    if (dir == la_acl_direction_e::EGRESS) {
        m_egress_acl_group = acl_group_sp;
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::ACL_GROUP_CHANGED);
        m_device->add_attribute_dependency(m_egress_acl_group, this, registered_attributes);

        status = set_acl_group_by_packet_format(dir, la_acl_packet_format_e::ETHERNET, acl_group_const);
        return_on_error(status);
    }

    auto slices = m_ifg_use_count->get_slices();
    const auto& acl_group_base
        = acl_group_const.weak_ptr_static_cast<const la_acl_group_base>().weak_ptr_const_cast<la_acl_group_base>();
    acl_group_rtf_conf_set_id_t rtf_conf_set_id;

    status = acl_group_base->allocate_rtf_conf_set_id_and_config_mapping(slices);
    return_on_error(status);

    status = acl_group_base->get_rtf_conf_set_id(rtf_conf_set_id);
    return_on_error(status);

    if (dir == la_acl_direction_e::INGRESS) {
        // Update table
        m_rtf_conf_set_ptr = rtf_conf_set_id;
        npl_mac_lp_attributes_payload_t payload;
        populate_lp_attributes_payload(payload);
        status = update_lp_attributes_payload(payload);
        if (status != LA_STATUS_SUCCESS) {
            return LA_STATUS_EUNKNOWN;
        }
        m_device->add_object_dependency(m_ingress_acl_group, this);
    } else {
        m_device->add_object_dependency(m_egress_acl_group, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_acl_group(la_acl_direction_e dir, la_acl_group*& out_acl_group) const
{
    start_api_getter_call("dir=", dir);
    if (dir == la_acl_direction_e::INGRESS) {
        out_acl_group = m_ingress_acl_group.get();
    }
    if (dir == la_acl_direction_e::EGRESS) {
        out_acl_group = m_egress_acl_group.get();
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::clear_acl_group(la_acl_direction_e dir)
{
    la_status status;

    if (dir == la_acl_direction_e::INGRESS) {
        if (m_ingress_acl_group == nullptr) {
            return LA_STATUS_SUCCESS;
        }
    }
    if (dir == la_acl_direction_e::EGRESS) {
        if (m_egress_acl_group == nullptr) {
            return LA_STATUS_SUCCESS;
        }
    }
    if (dir == la_acl_direction_e::INGRESS) {
        m_rtf_conf_set_ptr = RTF_CONF_SET_ID_INVALID;
        // Update table
        npl_mac_lp_attributes_payload_t payload;
        populate_lp_attributes_payload(payload);
        status = update_lp_attributes_payload(payload);
        if (status != LA_STATUS_SUCCESS) {
            return LA_STATUS_EUNKNOWN;
        }
    } else {
        // EGRESS
        for (auto pair_idx : m_ifg_use_count->get_slice_pairs()) {
            status = configure_txpp_dlp_profile_table(pair_idx);
            return_on_error(status);
        }
    }

    for (auto packet_format : {la_acl_packet_format_e::ETHERNET, la_acl_packet_format_e::IPV4, la_acl_packet_format_e::IPV6}) {
        std::vector<la_acl_delegate_wptr> acls = m_delegate_acls[(int)packet_format][(int)dir];
        m_delegate_acls[(int)packet_format][(int)dir].clear();

        for (auto& old_acl : acls) {
            m_device->remove_ifg_dependency(this, old_acl);
            m_device->remove_object_dependency(old_acl->get_acl_parent(), this);

            status = remove_current_ifgs(this, old_acl.get());
            return_on_error(status);
        }
    }

    if (dir == la_acl_direction_e::INGRESS) {
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::ACL_GROUP_CHANGED);
        m_device->remove_attribute_dependency(m_ingress_acl_group, this, registered_attributes);
        m_device->remove_object_dependency(m_ingress_acl_group, this);
        m_ingress_acl_group = nullptr;
    }

    if (dir == la_acl_direction_e::EGRESS) {
        bit_vector registered_attributes((la_uint64_t)attribute_management_op::ACL_GROUP_CHANGED);
        m_device->remove_attribute_dependency(m_egress_acl_group, this, registered_attributes);
        m_device->remove_object_dependency(m_egress_acl_group, this);
        m_egress_acl_group = nullptr;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_acl_id(la_acl::stage_e stage, la_acl_key_type_e key_type, const la_acl_delegate_wptr& acl_delegate)
{
    m_acls[(int)stage][(int)key_type] = acl_delegate ? acl_delegate->get_acl_parent() : nullptr;

    if (stage == la_acl::stage_e::INGRESS_FWD) {
        return update_ingress_acl_id();
    } else if (stage == la_acl::stage_e::EGRESS) {
        return update_egress_acl_id();
    } else {
        return LA_STATUS_ENOTIMPLEMENTED;
    }
}

la_status
la_l2_service_port_base::update_egress_acl_id()
{
    // Update table
    for (la_slice_pair_id_t slice_pair : m_device->get_used_slice_pairs()) {
        la_status status = configure_txpp_dlp_profile_table(slice_pair);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::update_ingress_acl_id()
{

    // Prepare updated value for the service LP attributes table
    npl_mac_lp_attributes_payload_t payload;
    populate_lp_attributes_payload(payload);

    la_status status = update_lp_attributes_payload(payload);

    if (status != LA_STATUS_SUCCESS) {
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::do_detach()
{
    if (m_attached_switch) {
        auto sw_impl = const_cast<la_switch_impl*>(static_cast<const la_switch_impl*>(m_attached_switch.get()));
        la_status status = sw_impl->remove_attachment(this);
        return_on_error(status);

        m_device->remove_ifg_dependency(this, m_attached_switch);
        m_device->remove_object_dependency(m_attached_switch, this);

        status = set_switch(nullptr /* switch */);
        return_on_error(status);
    }

    if (m_attached_destination) {
        la_status status = set_destination(nullptr /* destination */);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::detach()
{
    start_api_call("");

    return do_detach();
}

la_status
la_l2_service_port_base::disable()
{
    start_api_call("");
    la_status status;

    if (m_port_type != port_type_e::AC) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    status = m_ac_port_common.disable();
    return_on_error(status);

    status = set_port_egress_mode(false);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

template <class _EntryType>
la_status
la_l2_service_port_base::do_set_port_egress_mode(const weak_ptr_unsafe<_EntryType>& dlp_entry, bool active)
{
    auto dlp_v(dlp_entry->value());
    dlp_v.payloads.l2_dlp_attributes.disabled = !active;
    return dlp_entry->update(dlp_v);
}

la_status
la_l2_service_port_base::set_port_egress_mode(bool active)
{
    la_status status = LA_STATUS_SUCCESS;

    auto slices = m_ifg_use_count->get_slices();
    for (la_slice_id_t slice : slices) {
        // Update the L2 DLP table
        la_slice_pair_id_t pair_idx = slice / 2;

        const auto& dlp_entry = m_slice_pair_data_b[pair_idx].l2_dlp_entry;
        status = do_set_port_egress_mode(dlp_entry, active);

        return_on_error(status, HLD, ERROR, "failed to update L2 DLP table entry for slice %d.", slice);
    }
    return status;
}

la_status
la_l2_service_port_base::set_drop_counter_offset(la_stage_e stage, size_t offset)
{
    start_api_call("stage=", stage, "offset=", offset);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_l2_service_port_base::get_drop_counter_offset(la_stage_e stage, size_t& out_offset) const
{
    start_api_getter_call("stage=", stage);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_object::object_type_e
la_l2_service_port_base::type() const
{
    start_api_getter_call("");
    return object_type_e::L2_SERVICE_PORT;
}

std::string
la_l2_service_port_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_l2_service_port_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_l2_service_port_base::oid() const
{
    return m_oid;
}

la_device*
la_l2_service_port_base::get_device() const
{
    return m_device.get();
}

//
// Based on STP state and learning mode, derive NPL learning type
//
npl_learn_type_e
la_l2_service_port_base::get_npl_learn_type(la_port_stp_state_e stp_state, la_lp_mac_learning_mode_e learning_mode) const
{
    npl_learn_type_e learn_type = NPL_LEARN_TYPE_NONE;
    bool is_learning = (stp_state == la_port_stp_state_e::LEARNING || stp_state == la_port_stp_state_e::FORWARDING);

    if (learning_mode == la_lp_mac_learning_mode_e::STANDALONE) {
        learn_type = (is_learning) ? NPL_LEARN_TYPE_HW : NPL_LEARN_TYPE_NONE;
    }
    if (learning_mode == la_lp_mac_learning_mode_e::CPU) {
        learn_type = (is_learning) ? NPL_LEARN_TYPE_CPU : NPL_LEARN_TYPE_NONE;
    }

    return learn_type;
}

void
la_l2_service_port_base::populate_lp_attributes_payload(npl_mac_lp_attributes_payload_t& out_payload)
{
    bool stp_state_block = (m_stp_state != la_port_stp_state_e::FORWARDING);
    npl_learn_type_e learn_type = get_npl_learn_type(m_stp_state, m_learning_mode);

    memset(&out_payload, 0, sizeof(npl_mac_lp_attributes_payload_t));

    // out_payload.sec_acl_on_term = 0;
    out_payload.mac_lp_type = NPL_LP_TYPE_LAYER_2;
    out_payload.layer.two.learn_type = learn_type;
    out_payload.layer.two.learn_prob = NPL_ALWAYS_LEARN;
    out_payload.layer.two.term.enable_monitor = m_ingress_sflow_enabled ? 1 : 0;
    out_payload.layer.two.term.max_mep_level = m_down_mep_level;
    out_payload.layer.two.term.mip_exists = 0;
    out_payload.layer.two.term.mep_exists = m_down_mep_enabled ? 1 : 0;
    out_payload.layer.two.term.ive_profile_and_data = m_ac_npl_ive_command;

    out_payload.layer.two.shared.sec_acl_attributes.port_mirror_type = m_ingress_mirror_type;

    out_payload.layer.two.shared.mirror_cmd = (m_ingress_mirror_cmd) ? m_ingress_mirror_cmd->get_gid() : NPL_RX_NULL_MIRROR_CODE;
    out_payload.layer.two.shared.stp_state_block = stp_state_block;
    if ((m_port_type != port_type_e::VXLAN) && (m_port_type != port_type_e::PWE)) {
        out_payload.layer.two.shared.lp_profile = m_filter_group->get_id();
    } else {
        out_payload.layer.two.shared.stp_state_block = false;
    }

    if ((m_filter_group)
        && ((m_port_type == port_type_e::VXLAN) || (m_port_type == port_type_e::PWE) || (m_port_type == port_type_e::PWE_TAGGED))) {
        out_payload.layer.two.shared.lp_profile = m_filter_group->get_id();
    }

    out_payload.layer.two.shared.p2p = (m_attached_destination) ? 1 : 0;
    bool per_pkt_type_count
        = (m_p_counter[COUNTER_DIRECTION_INGRESS] != nullptr) && (m_p_counter[COUNTER_DIRECTION_INGRESS]->get_set_size() > 1);
    out_payload.layer.two.shared.sec_acl_attributes.per_pkt_type_count = per_pkt_type_count ? 1 : 0;
    if (m_attached_destination) {
        uint64_t dgid = 0;
        get_attached_destination_id(m_attached_destination, dgid);
        out_payload.layer.two.shared.sec_acl_attributes.slp_dlp.global_dlp_id = dgid;
    } else {
        if (m_port_type != port_type_e::PWE) {
            out_payload.layer.two.shared.sec_acl_attributes.slp_dlp.global_slp_id = NPL_DESTINATION_MASK_L2_DLP | m_port_gid;
        } else {
            out_payload.layer.two.shared.sec_acl_attributes.slp_dlp.global_slp_id = NPL_DESTINATION_MASK_L2_PWE_DLP | m_pwe_gid;
        }
    }

    out_payload.layer.two.shared.sec_acl_attributes.l2_lpts_slp_attributes = m_copc_profile;
    out_payload.layer.two.shared.sec_acl_attributes.rtf_conf_set_ptr = m_rtf_conf_set_ptr;
}

la_status
la_l2_service_port_base::teardown_service_lp_attributes_table(la_slice_id_t slice_idx,
                                                              npl_service_lp_attributes_table_entry_wptr_t& lp_attributes_entry)
{
    const auto& table(m_device->m_tables.service_lp_attributes_table[slice_idx / 2]);
    npl_service_lp_attributes_table_key_t k = lp_attributes_entry->key();
    la_status status = table->erase(k);

    return_on_error(status);

    lp_attributes_entry = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_ttl(la_uint8_t ttl)
{
    start_api_call("ttl=", ttl);

    if ((m_port_type != port_type_e::VXLAN) && (m_port_type != port_type_e::PWE)) {
        return LA_STATUS_EINVAL;
    }

    if (m_ttl_mode != la_ttl_inheritance_mode_e::PIPE) {
        return LA_STATUS_EINVAL;
    }

    m_ttl = ttl;

    for (auto pair_idx : m_ifg_use_count->get_slice_pairs()) {
        la_status status = configure_l2_dlp_table(pair_idx);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_ttl(la_uint8_t& out_ttl) const
{
    start_api_getter_call("");

    if ((m_port_type != port_type_e::VXLAN) && (m_port_type != port_type_e::PWE)) {
        return LA_STATUS_EINVAL;
    }
    out_ttl = m_ttl;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_ttl_inheritance_mode(la_ttl_inheritance_mode_e ttl_mode)
{
    start_api_call("ttl_mode=", ttl_mode);

    if ((m_port_type != port_type_e::VXLAN) && (m_port_type != port_type_e::PWE)) {
        return LA_STATUS_EINVAL;
    }

    if (ttl_mode == m_ttl_mode) {
        return LA_STATUS_SUCCESS;
    }

    m_ttl_mode = ttl_mode;
    for (auto pair_idx : m_ifg_use_count->get_slice_pairs()) {
        la_status status = configure_l2_dlp_table(pair_idx);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_ttl_inheritance_mode(la_ttl_inheritance_mode_e& out_mode) const
{
    start_api_getter_call();

    if ((m_port_type != port_type_e::VXLAN) && (m_port_type != port_type_e::PWE)) {
        return LA_STATUS_EINVAL;
    }

    out_mode = m_ttl_mode;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::configure_l2_dlp_table(la_slice_pair_id_t pair_idx)
{
    if (m_port_type != port_type_e::VXLAN) {
        return (do_configure_l2_dlp_table(
            m_device->m_tables.l2_dlp_table[pair_idx], pair_idx, m_slice_pair_data_b[pair_idx].l2_dlp_entry));
    } else {
        // Program DLP for encap_decap and encap_only mode
        if (m_tunnel_mode != la_ip_tunnel_mode_e::DECAP_ONLY) {
            return (do_configure_vxlan_l2_dlp_table(
                m_device->m_tables.vxlan_l2_dlp_table[pair_idx], pair_idx, m_slice_pair_data_b[pair_idx].vxlan_l2_dlp_entry));
        } else {
            return LA_STATUS_SUCCESS;
        }
    }
}

la_status
la_l2_service_port_base::do_configure_l2_dlp_table(const npl_l2_dlp_table_sptr_t& table,
                                                   la_slice_pair_id_t pair_idx,
                                                   npl_l2_dlp_table_entry_wptr_t& l2_dlp_entry)
{
    la_status status;
    typename npl_l2_dlp_table_t::key_type k;
    typename npl_l2_dlp_table_t::value_type v;
    bool is_recycle_ac = silicon_one::is_recycle_ac(m_device->get_sptr(this));

    k.l2_dlp_id_key_id = m_port_gid;

    v.payloads.l2_dlp_attributes.stp_state_is_block = (m_stp_state != la_port_stp_state_e::FORWARDING);
    v.payloads.l2_dlp_attributes.disabled = 0;
    v.payloads.l2_dlp_attributes.dlp_attributes.lp_profile = m_filter_group->get_id();
    v.payloads.l2_dlp_attributes.dlp_attributes.port_mirror_type
        = is_recycle_ac ? NPL_PORT_MIRROR_TYPE_UN_CONDITIONED : m_egress_mirror_type;
    bool demux_count
        = (m_p_counter[COUNTER_DIRECTION_EGRESS] != nullptr) ? m_p_counter[COUNTER_DIRECTION_EGRESS]->get_set_size() > 1 : false;

    v.payloads.l2_dlp_attributes.qos_attributes.demux_count = demux_count ? 1 : 0;
    v.payloads.l2_dlp_attributes.qos_attributes.q_counter
        = populate_counter_ptr_slice_pair(m_q_counter[COUNTER_DIRECTION_EGRESS], pair_idx, COUNTER_DIRECTION_EGRESS);
    v.payloads.l2_dlp_attributes.qos_attributes.p_counter
        = populate_counter_ptr_slice_pair(m_p_counter[COUNTER_DIRECTION_EGRESS], pair_idx, COUNTER_DIRECTION_EGRESS);
    v.payloads.l2_dlp_attributes.qos_attributes.qos_id = m_egress_qos_profile->get_id(pair_idx);

    la_egress_qos_marking_source_e marking_source{};
    status = m_egress_qos_profile->get_marking_source(marking_source);
    return_on_error(status);
    v.payloads.l2_dlp_attributes.qos_attributes.is_group_qos = (marking_source == la_egress_qos_marking_source_e::QOS_GROUP);

    populate_rcy_data_mirror_command(m_egress_mirror_cmd, is_recycle_ac, v.payloads.l2_dlp_attributes.tx_to_rx_rcy_data);

    if (m_port_type == port_type_e::AC) {
        v.payloads.l2_dlp_attributes.l2_dlp_specific.ac.vlan_after_eve_format = 0;
        v.payloads.l2_dlp_attributes.l2_dlp_specific.ac.eve_types.eve = m_ac_npl_eve_command;
        v.payloads.l2_dlp_attributes.l2_dlp_specific.ac.max_mep_level = m_up_mep_level;
        v.payloads.l2_dlp_attributes.l2_dlp_specific.ac.mep_exists = m_up_mep_enabled ? 1 : 0;
    } else {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if (l2_dlp_entry == nullptr) {
        la_status status = table->insert(k, v, l2_dlp_entry);
        return_on_error(status, HLD, ERROR, "l2_dlp_table[%d].insert failed", pair_idx);
        return LA_STATUS_SUCCESS;
    }

    status = l2_dlp_entry->update(v);
    return_on_error(status, HLD, ERROR, "l2_dlp_table[%d].update failed", pair_idx);
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::do_configure_vxlan_l2_dlp_table(const npl_vxlan_l2_dlp_table_sptr_t& table,
                                                         la_slice_pair_id_t pair_idx,
                                                         npl_vxlan_l2_dlp_table_entry_wptr_t& l2_dlp_entry)
{
    la_status status;
    typename npl_vxlan_l2_dlp_table_t::key_type k;
    typename npl_vxlan_l2_dlp_table_t::value_type v;

    k.l2_dlp_id_key_id = m_port_gid;

    v.payloads.vxlan_tunnel_attributes.sip_index = m_sip_index->id();
    v.payloads.vxlan_tunnel_attributes.dip.ipv4_dip = m_remote_ip_addr.s_addr;
    v.payloads.vxlan_tunnel_attributes.lp_set = 0;
    if (m_filter_group) {
        v.payloads.vxlan_tunnel_attributes.lp_profile = m_filter_group->get_id();
    }
    v.payloads.vxlan_tunnel_attributes.p_counter
        = populate_counter_ptr_slice_pair(m_p_counter[COUNTER_DIRECTION_EGRESS], pair_idx, COUNTER_DIRECTION_EGRESS);
    v.payloads.vxlan_tunnel_attributes.ttl = m_ttl;
    v.payloads.vxlan_tunnel_attributes.ttl_mode = la_2_npl_ttl_inheritance_mode(m_ttl_mode);

    status = update_vxlan_group_policy_encap(v);
    return_on_error(status, HLD, ERROR, "Failed retrieving vxlan group policy encap.");

    if (l2_dlp_entry == nullptr) {
        la_status status = table->insert(k, v, l2_dlp_entry);
        return_on_error(status, HLD, ERROR, "vxlan_l2_dlp_table[%d].insert failed", pair_idx);
        return LA_STATUS_SUCCESS;
    }

    status = l2_dlp_entry->update(v);
    return_on_error(status, HLD, ERROR, "vxlan_l2_dlp_table[%d].update failed", pair_idx);
    return LA_STATUS_SUCCESS;
}

template <class _TableType>
la_status
la_l2_service_port_base::do_teardown_l2_dlp_table(const std::shared_ptr<_TableType>& table,
                                                  typename _TableType::entry_wptr_type& entry)
{
    la_status status;
    auto k = entry->key();
    status = table->erase(k);
    if (status == LA_STATUS_SUCCESS) {
        entry = nullptr;
    }
    return status;
}

la_status
la_l2_service_port_base::teardown_l2_dlp_table(la_slice_pair_id_t pair_idx)
{

    la_status status;

    if (m_port_type != port_type_e::VXLAN) {
        auto& entry = m_slice_pair_data_b[pair_idx].l2_dlp_entry;
        const auto& table(m_device->m_tables.l2_dlp_table[pair_idx]);
        status = do_teardown_l2_dlp_table(table, entry);
    } else {
        if (m_tunnel_mode != la_ip_tunnel_mode_e::DECAP_ONLY) {
            auto& entry = m_slice_pair_data_b[pair_idx].vxlan_l2_dlp_entry;
            const auto& table(m_device->m_tables.vxlan_l2_dlp_table[pair_idx]);
            status = do_teardown_l2_dlp_table(table, entry);
        } else {
            return LA_STATUS_SUCCESS;
        }
    }

    return_on_error(status);

    return status;
}

la_status
la_l2_service_port_base::pwe_set_switch(const la_switch_impl_wptr& sw)
{
    transaction txn;
    la_status status = LA_STATUS_ENOTIMPLEMENTED;

    m_attached_switch = sw;

    if (sw != nullptr) {
        txn.status = configure_pwe_vpls_label_table();
        return_on_error(txn.status);
        txn.on_fail([&]() { teardown_pwe_vpls_label_table(); });

        txn.status = configure_pwe_to_l3_dest_table();
        return_on_error(txn.status);
        txn.on_fail([&]() { teardown_pwe_to_l3_dest_table(); });

        status = configure_mpls_termination_table();
        return_on_error(status);

        return txn.status;
    }
    status = teardown_pwe_vpls_label_table();
    return_on_error(status);
    status = teardown_pwe_to_l3_dest_table();
    return_on_error(status);
    status = configure_mpls_termination_table();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_switch(const la_switch_impl_wptr& sw)
{
    la_status status;

    m_attached_switch = sw;
    if (m_port_type == port_type_e::AC) {
        status = m_ac_port_common.set_switch(m_attached_switch);
    } else if ((m_port_type == port_type_e::PWE) || (m_port_type == port_type_e::PWE_TAGGED)) {
        // Check if this PWE destination is not used by any other PWEs
        la_status status = pwe_sw_dest_in_use(m_l3_destination);
        if (status == LA_STATUS_ENOTFOUND) {
            status = pwe_set_switch(sw);
        } else {
            if (status == LA_STATUS_SUCCESS) {
                log_err(HLD, "PWE destination in this switch %d is already in use", m_attached_switch->get_gid());
                return LA_STATUS_EEXIST;
            } else {
                log_err(HLD, "Invalid Lookup Key");
                return LA_STATUS_EINVAL;
            }
        }
    }

    return status;
}

la_status
la_l2_service_port_base::set_pwe_multicast_recycle_lsp_properties(la_mpls_label recycle_label, la_next_hop* recycle_destination)
{
    start_api_call("recycle_label=", recycle_label, "recycle_destination=", recycle_destination);

    // Check arguments
    if ((recycle_label.label == 0) || (recycle_destination == nullptr)) {
        return LA_STATUS_EINVAL;
    }
    // This API action is only for VPLS pwe, not for VPWS pwe.
    if (m_attached_destination != nullptr) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    auto recycle_nh_sptr = m_device->get_sptr<la_next_hop>(const_cast<la_next_hop*>(recycle_destination));

    if (!of_same_device(recycle_nh_sptr, m_device)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (recycle_label.label == m_recycle_label.label) {
        return LA_STATUS_SUCCESS;
    } else {
        m_recycle_label = recycle_label;
        m_recycle_destination = recycle_nh_sptr;
    }

    return LA_STATUS_SUCCESS;
}

la_l2_service_port_base::~la_l2_service_port_base()
{
}

slice_ifg_vec_t
la_l2_service_port_base::get_ifgs() const
{
    if (m_port_type == port_type_e::PWE || m_port_type == port_type_e::PWE_TAGGED) {
        return get_all_network_ifgs(m_device);
    } else {
        return m_ifg_use_count->get_ifgs();
    }
}

la_status
la_l2_service_port_base::teardown_pwe_port_tag_table()
{
    for (la_slice_id_t slice = 0; slice < m_slice_data_b.size(); slice++) {
        const auto& table(m_device->m_tables.service_mapping_tcam_pwe_tag_table[slice]);
        slice_data_base& data(m_slice_data_b[slice]);

        la_status status = table->erase(data.pwe_port_tag_entry_location);
        return_on_error(status);

        data.pwe_port_tag_entry_location = (size_t)-1;
        data.pwe_port_tag_entry = nullptr;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::update_lp_attributes_payload(npl_mac_lp_attributes_payload_t& payload)
{
    // Assuming  LP attributes are the same on all slices except for counters and ACL.

    if (m_port_type == port_type_e::PWE_TAGGED) {
        return update_lp_attributes_payload_pwe_tagged(payload);
    } else {
        return update_lp_attributes_payload_lp(payload);
    }
}

bool
la_l2_service_port_base::is_counter_set_size_valid(const la_counter_set_impl_wptr& counter,
                                                   la_counter_set::type_e counter_type) const
{
    if (counter == nullptr) {
        return true;
    }

    size_t counter_set_size = counter->get_set_size();

    switch (counter_type) {
    case la_counter_set::type_e::QOS:
        return ((counter_set_size >= 1) && (counter_set_size <= PER_QOS_TC_SET_SIZE));
    case la_counter_set::type_e::PORT:
        if (counter_set_size == 1) {
            return true;
        }

        if (m_port_type == port_type_e::AC) {
            return (counter_set_size == (la_uint_t)la_rate_limiters_packet_type_e::LAST);
        } else {
            return (counter_set_size == PER_L3_PROTOCOL_SET_SIZE);
        }
    default:
        return false;
    }
}

la_status
la_l2_service_port_base::verify_set_counter_parameters(const la_counter_set_impl_wptr& new_counter,
                                                       la_counter_set::type_e counter_type) const
{
    if ((counter_type != la_counter_set::type_e::QOS) && (counter_type != la_counter_set::type_e::PORT)) {
        return LA_STATUS_EINVAL;
    }

    if ((new_counter != nullptr) && (!of_same_device(this, new_counter))) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (!is_counter_set_size_valid(new_counter, counter_type)) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

bool
la_l2_service_port_base::need_aggregate_counter() const
{
    bool is_aggregate = true; // PWE is always multi-slice

    if (m_port_type == port_type_e::AC) {
        const la_system_port* sp = m_ac_ethernet_port->get_system_port();
        if (sp != nullptr) {
            is_aggregate = false;
        }
    }

    return is_aggregate;
}

la_status
la_l2_service_port_base::configure_ingress_counter()
{
    npl_mac_lp_attributes_payload_t payload;
    populate_lp_attributes_payload(payload);

    la_status status = update_lp_attributes_payload(payload);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::configure_egress_counter()
{
    for (auto pair_idx : m_ifg_use_count->get_slice_pairs()) {
        la_status status = configure_l2_dlp_table(pair_idx);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::do_set_counter(const la_counter_set_impl_wptr& new_counter,
                                        la_counter_set::type_e counter_type,
                                        counter_direction_e direction)
{
    la_status status = verify_set_counter_parameters(new_counter, counter_type);
    return_on_error(status);

    auto& curr_counter((counter_type == la_counter_set::type_e::QOS) ? m_q_counter[direction] : m_p_counter[direction]);

    if (curr_counter == new_counter) {
        return LA_STATUS_SUCCESS;
    }

    // Add the port's slices to the new counter
    if (new_counter != nullptr) {
        bool is_aggregate = need_aggregate_counter();
        status = new_counter->add_pq_counter_user(m_device->get_sptr(this), counter_type, direction, is_aggregate);
        return_on_error(status);

        m_device->add_ifg_dependency(this, new_counter);
        m_device->add_object_dependency(new_counter, this);
    }

    // Update the tables with the new counter
    auto prev_counter = curr_counter;
    curr_counter = new_counter; // Needed for table update
    if (direction == COUNTER_DIRECTION_INGRESS) {
        status = configure_ingress_counter();
    } else {
        status = configure_egress_counter();
    }

    return_on_error(status);

    // Remove the port's slices from the previous counter
    if (prev_counter != nullptr) {
        m_device->remove_ifg_dependency(this, prev_counter);
        m_device->remove_object_dependency(prev_counter, this);
        status = prev_counter->remove_pq_counter_user(m_device->get_sptr(this));
        return_on_error(status);
    }

    // Notify counter change to dependent objects
    if (direction == COUNTER_DIRECTION_EGRESS) {
        status = notify_l2_dlp_attrib_change();
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_ingress_counter(la_counter_set::type_e counter_type, la_counter_set* counter)
{
    start_api_call("counter_type=", counter_type, "counter=", counter);

    if ((m_port_type == port_type_e::PWE) && m_attached_destination) {
        return LA_STATUS_EINVAL;
    }

    auto new_counter = m_device->get_sptr<la_counter_set_impl>(counter);
    return do_set_counter(new_counter, counter_type, COUNTER_DIRECTION_INGRESS);
}

la_status
la_l2_service_port_base::get_ingress_counter(la_counter_set::type_e counter_type, la_counter_set*& out_counter) const
{
    if ((counter_type != la_counter_set::type_e::QOS) && (counter_type != la_counter_set::type_e::PORT)) {
        return LA_STATUS_EINVAL;
    }

    auto curr_counter((counter_type == la_counter_set::type_e::QOS) ? m_q_counter[COUNTER_DIRECTION_INGRESS]
                                                                    : m_p_counter[COUNTER_DIRECTION_INGRESS]);

    out_counter = curr_counter.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_egress_counter(la_counter_set::type_e counter_type, la_counter_set* counter)
{
    start_api_call("counter_type=", counter_type, "counter=", counter);

    if ((m_port_type == port_type_e::PWE) && m_attached_destination) {
        return LA_STATUS_EINVAL;
    }

    auto new_counter = m_device->get_sptr<la_counter_set_impl>(counter);
    la_status status = do_set_counter(new_counter, counter_type, COUNTER_DIRECTION_EGRESS);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_egress_counter(la_counter_set::type_e counter_type, la_counter_set*& out_counter) const
{
    if ((counter_type != la_counter_set::type_e::QOS) && (counter_type != la_counter_set::type_e::PORT)) {
        return LA_STATUS_EINVAL;
    }

    auto curr_counter((counter_type == la_counter_set::type_e::QOS) ? m_q_counter[COUNTER_DIRECTION_EGRESS]
                                                                    : m_p_counter[COUNTER_DIRECTION_EGRESS]);

    out_counter = curr_counter.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_meter(const la_meter_set* meter)
{
    start_api_call("meter=", meter);
    la_status status;

    if (m_port_type != port_type_e::AC) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    if ((meter != nullptr) && (!of_same_device(meter, this))) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (meter == m_meter) {
        return LA_STATUS_SUCCESS;
    }

    auto meter_set_impl = const_cast<la_meter_set_impl*>(static_cast<const la_meter_set_impl*>(meter));

    // Attach to the new meter
    if (meter != nullptr) {
        bool is_aggregate = (m_ac_ethernet_port->get_spa_port() != nullptr) ? true : false;
        status = meter_set_impl->attach_user(m_device->get_sptr(this), is_aggregate);
        return_on_error(status);
    }

    // Update the tables with the new meter
    auto prev_meter = m_meter;
    m_meter = m_device->get_sptr(meter_set_impl); // update_lp_attributes_payload needs m_meter to be set with the new meter
    npl_mac_lp_attributes_payload_t payload;
    populate_lp_attributes_payload(payload);
    status = update_lp_attributes_payload(payload);
    if (status != LA_STATUS_SUCCESS) {
        m_meter = nullptr;
        return status;
    }

    // Detach from the current meter
    if (prev_meter != nullptr) {
        status = prev_meter->detach_user(m_device->get_sptr(this));
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_meter(const la_meter_set*& out_meter) const
{
    out_meter = m_meter.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_encap_vni(const la_switch* sw, la_vni_t vni)
{
    start_api_call("sw=", sw, "vni=", vni);

    if (vni >= LA_VXVLAN_MAX_VNI) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (sw == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_switch_impl* sw_impl = const_cast<la_switch_impl*>(static_cast<const la_switch_impl*>(sw));
    la_switch_gid_t sw_gid = sw_impl->get_gid();

    auto it = m_encap_vni_map.find(sw_gid);
    if (it != m_encap_vni_map.end()) {
        if (it->second == vni) {
            return LA_STATUS_EEXIST;
        } else {
            return LA_STATUS_EBUSY;
        }
    }

    la_status status = sw_impl->set_encap_vni(vni);
    return_on_error(status);

    m_encap_vni_map[sw_gid] = vni;

    m_device->add_object_dependency(sw, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::clear_encap_vni(const la_switch* sw)
{
    start_api_call("sw=", sw);

    if (sw == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_switch_impl* sw_impl = const_cast<la_switch_impl*>(static_cast<const la_switch_impl*>(sw));
    la_switch_gid_t sw_gid = sw_impl->get_gid();

    auto it = m_encap_vni_map.find(sw_gid);
    if (it == m_encap_vni_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    la_status status = sw_impl->clear_encap_vni();
    return_on_error(status);

    m_encap_vni_map.erase(sw_gid);
    m_device->remove_object_dependency(sw, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_encap_vni(const la_switch* sw, la_uint32_t& out_vni) const
{
    start_api_getter_call("sw=", sw);

    if (sw == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_switch_impl* sw_impl = const_cast<la_switch_impl*>(static_cast<const la_switch_impl*>(sw));

    return sw_impl->get_encap_vni(out_vni);
}

uint64_t
la_l2_service_port_base::get_overlay_nh_id()
{
    return m_cur_ovl_nh_id;
}

la_status
la_l2_service_port_base::set_ingress_sflow_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    npl_mac_lp_attributes_payload_t payload;
    populate_lp_attributes_payload(payload);

    // Update the service LP attributes table
    payload.layer.two.term.enable_monitor = enabled ? 1 : 0;

    la_status status = update_lp_attributes_payload(payload);
    return_on_error(status);

    // Update cached value
    m_ingress_sflow_enabled = enabled;

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_ingress_sflow_enabled(bool& out_enabled) const
{
    start_api_getter_call();
    out_enabled = m_ingress_sflow_enabled;

    return LA_STATUS_SUCCESS;
}

// Update the L2_DLP attributes required for nh_payload
la_status
la_l2_service_port_base::populate_nh_l2_payload(npl_nh_payload_t& out_nh_payload, la_slice_pair_id_t pair_idx) const
{
    if (m_port_type != port_type_e::AC) {
        return LA_STATUS_EINVAL;
    }

    if (!m_ifg_use_count->is_slice_pair_in_use(pair_idx)) {
        // this l2_ac port does not have sys port on this pair_idx.
        // no configuration required for this pair_idx, return
        return LA_STATUS_SUCCESS;
    }

    // update qos_attributes
    bool demux_count
        = (m_p_counter[COUNTER_DIRECTION_EGRESS] != nullptr) ? m_p_counter[COUNTER_DIRECTION_EGRESS]->get_set_size() > 1 : false;
    out_nh_payload.l2_port = 1;
    out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_dlp_qos_and_attr.demux_count = demux_count ? 1 : 0;
    out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_dlp_qos_and_attr.p_counter
        = populate_counter_ptr_slice_pair(m_p_counter[COUNTER_DIRECTION_EGRESS], pair_idx, COUNTER_DIRECTION_EGRESS);
    out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_dlp_qos_and_attr.q_counter
        = populate_counter_ptr_slice_pair(m_q_counter[COUNTER_DIRECTION_EGRESS], pair_idx, COUNTER_DIRECTION_EGRESS);
    out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_dlp_qos_and_attr.qos_id = m_egress_qos_profile->get_id(pair_idx);

    la_egress_qos_marking_source_e marking_source{};
    la_status status = m_egress_qos_profile->get_marking_source(marking_source);
    return_on_error(status);
    out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_dlp_qos_and_attr.is_group_qos
        = (marking_source == la_egress_qos_marking_source_e::QOS_GROUP);

    // update eve data
    la_vlan_edit_command eve;
    status = get_egress_vlan_edit_command(eve);
    return_on_error(status);

    // base class supports up only 1 vlan definition in nh
    if (eve.num_tags_to_push == 0) {
        out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.nh_ene_macro_code = NPL_NH_ENE_MACRO_ETH;
    } else if (eve.num_tags_to_push == 1) {
        out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.nh_ene_macro_code = NPL_NH_ENE_MACRO_ETH_VLAN;
        out_nh_payload.eve_vid1 = eve.tag0.tci.fields.vid;
        if (eve.tag0.tpid == 0x8100) {
            out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_tpid_prof = 0;
        } else if (eve.tag0.tpid == 0x88a8) {
            out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_tpid_prof = 1;
        } else if (eve.tag0.tpid == 0x9100) {
            out_nh_payload.l3_sa_vlan_or_l2_dlp_attr.l2_dlp_attr.l2_tpid_prof = 2;
        } else {
            return LA_STATUS_ENOTIMPLEMENTED;
        }
    } else {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_egress_sflow_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_l2_service_port_base::get_egress_sflow_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_l2_service_port_base::set_control_word_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    if (m_port_type != port_type_e::PWE) {
        return LA_STATUS_EINVAL;
    }

    if (m_control_word_enable == enabled) {
        return LA_STATUS_SUCCESS;
    }

    transaction txn;
    auto old_enabled = m_control_word_enable;
    m_control_word_enable = enabled;
    txn.on_fail([&]() { m_control_word_enable = old_enabled; });

    txn.status = configure_pwe_encap_table();
    return_on_error(txn.status);
    txn.on_fail([&]() { configure_pwe_encap_table(); });

    if (m_attached_destination == nullptr) {
        txn.status = do_update_cw_fat_pwe_vpls(m_flow_label_enable, enabled);
    }

    txn.status = configure_mpls_termination_table();
    return txn.status;
}

la_status
la_l2_service_port_base::get_control_word_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    if (m_port_type != port_type_e::PWE) {
        return LA_STATUS_EINVAL;
    }

    out_enabled = m_control_word_enable;
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_flow_label_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    if (m_port_type != port_type_e::PWE) {
        return LA_STATUS_EINVAL;
    }

    if (m_flow_label_enable == enabled) {
        return LA_STATUS_SUCCESS;
    }

    transaction txn;
    auto old_enabled = m_flow_label_enable;
    m_flow_label_enable = enabled;
    txn.on_fail([&]() { m_flow_label_enable = old_enabled; });

    txn.status = configure_pwe_encap_table();
    return_on_error(txn.status);
    txn.on_fail([&]() { configure_pwe_encap_table(); });

    if (m_attached_destination == nullptr) {
        txn.status = do_update_cw_fat_pwe_vpls(enabled, m_control_word_enable);
    }

    txn.status = configure_mpls_termination_table();
    return txn.status;
}

la_status
la_l2_service_port_base::get_flow_label_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    if (m_port_type != port_type_e::PWE) {
        return LA_STATUS_EINVAL;
    }

    out_enabled = m_flow_label_enable;
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::notify_l2_dlp_attrib_change() const
{
    attribute_management_details amd;
    amd.op = attribute_management_op::L2_DLP_ATTRIB_CHANGED;
    la_amd_undo_callback_funct_t undo = [](attribute_management_details amd) { return amd; };
    la_status status = m_device->notify_attribute_changed(this, amd, undo);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "l2_dlp attribute change notification failed(status = %s)", la_status2str(status).c_str());
    }
    return status;
}

la_status
la_l2_service_port_base::notify_pwe_l3_destination_attrib_change() const
{
    attribute_management_details amd;
    amd.op = attribute_management_op::PWE_L3_DESTINATION_ATTRIB_CHANGED;
    la_amd_undo_callback_funct_t undo = [](attribute_management_details amd) { return amd; };
    la_status status = m_device->notify_attribute_changed(this, amd, undo);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "Pwe l3 destination attribute change notification failed(status = %s)", la_status2str(status).c_str());
    }
    return status;
}

la_status
la_l2_service_port_base::set_egress_feature_mode(egress_feature_mode_e mode)
{
    start_api_call("mode=", mode);
    if ((mode == egress_feature_mode_e::L2) && (m_port_gid >= la_device_impl::MAX_L2_SERVICE_PORT_PROTECTED_GIDS)) {
        return LA_STATUS_EOUTOFRANGE;
    }

    m_egress_feature_mode = mode;
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_egress_feature_mode(egress_feature_mode_e& out_mode) const
{
    start_api_getter_call();
    out_mode = m_egress_feature_mode;

    return LA_STATUS_SUCCESS;
}

la_l2_service_port::egress_feature_mode_e
la_l2_service_port_base::get_egress_feature_mode() const
{
    return m_egress_feature_mode;
}

la_status
la_l2_service_port_base::update_dependent_attributes(dependency_management_op op)
{
    switch (op.action.attribute_management.op) {
    case (attribute_management_op::ACL_GROUP_CHANGED): {
        la_status status = handle_acl_group_change(op.dependee, op.action.attribute_management.packet_format);
        return status;
    }

    default:
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
la_l2_service_port_base::handle_acl_group_change(const la_object* changed_acl_group, la_acl_packet_format_e packet_format)
{
    if (changed_acl_group == m_ingress_acl_group) {
        auto status = set_acl_group_by_packet_format(la_acl_direction_e::INGRESS, packet_format, m_ingress_acl_group);
        return_on_error(status);

        const auto& acl_group_base
            = m_ingress_acl_group.weak_ptr_static_cast<const la_acl_group_base>().weak_ptr_const_cast<la_acl_group_base>();
        auto slices = m_ifg_use_count->get_slices();
        status = acl_group_base->allocate_rtf_conf_set_id_and_config_mapping(slices);
        return_on_error(status);
    }
    if (changed_acl_group == m_egress_acl_group) {
        auto status = set_acl_group_by_packet_format(la_acl_direction_e::EGRESS, packet_format, m_egress_acl_group);
        return_on_error(status);

        const auto& acl_group_base
            = m_egress_acl_group.weak_ptr_static_cast<const la_acl_group_base>().weak_ptr_const_cast<la_acl_group_base>();
        auto slices = m_ifg_use_count->get_slices();
        status = acl_group_base->allocate_rtf_conf_set_id_and_config_mapping(slices);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_cfm_attrib(la_mep_direction_e mep_dir, la_uint8_t mep_lvl, bool mep_enabled)
{
    transaction txn;
    bool old_down_mep_enabled, old_up_mep_enabled;
    la_uint8_t old_down_mep_level, old_up_mep_level;

    if (mep_lvl > LA_MAX_MEP_LVL) {
        return LA_STATUS_EINVAL;
    }

    switch (mep_dir) {

    case la_mep_direction_e::DOWN:
        old_down_mep_enabled = m_down_mep_enabled;
        old_down_mep_level = m_down_mep_level;
        txn.on_fail([=]() {
            m_down_mep_enabled = old_down_mep_enabled;
            m_down_mep_level = old_down_mep_level;
        });
        m_down_mep_enabled = mep_enabled;
        m_down_mep_level = mep_lvl;

        npl_mac_lp_attributes_payload_t payload;
        populate_lp_attributes_payload(payload);

        txn.status = update_lp_attributes_payload(payload);
        return_on_error(txn.status);
        break;

    case la_mep_direction_e::UP:
        old_up_mep_enabled = m_up_mep_enabled;
        old_up_mep_level = m_up_mep_level;
        txn.on_fail([=]() {
            m_up_mep_enabled = old_up_mep_enabled;
            m_up_mep_level = old_up_mep_level;
        });
        m_up_mep_enabled = mep_enabled;
        m_up_mep_level = mep_lvl;

        for (auto pair_idx : m_ifg_use_count->get_slice_pairs()) {
            txn.status = configure_l2_dlp_table(pair_idx);
            return_on_error(txn.status);
            txn.on_fail([=]() { configure_l2_dlp_table(pair_idx); });
        }
        break;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::set_cfm_enabled(la_mep_direction_e mep_dir, la_uint8_t mep_lvl)
{
    start_api_call("mep_dir=", mep_dir, "mep_lvl=", mep_lvl);

    return (set_cfm_attrib(mep_dir, mep_lvl, true));
}

la_status
la_l2_service_port_base::clear_cfm(la_mep_direction_e mep_dir)
{
    start_api_call("mep_dir=", mep_dir);

    return (set_cfm_attrib(mep_dir, 0, false));
}

la_status
la_l2_service_port_base::get_cfm_mep(la_mep_direction_e mep_dir, la_uint8_t& out_mep_lvl) const
{
    start_api_getter_call("mep_dir=", mep_dir);

    la_status status = LA_STATUS_SUCCESS;

    switch (mep_dir) {

    case la_mep_direction_e::DOWN:
        if (m_down_mep_enabled) {
            out_mep_lvl = m_down_mep_level;
        } else {
            status = LA_STATUS_ENOTFOUND;
        }
        break;

    case la_mep_direction_e::UP:
        if (m_up_mep_enabled) {
            out_mep_lvl = m_up_mep_level;
        } else {
            status = LA_STATUS_ENOTFOUND;
        }
        break;
    }

    return status;
}

la_status
la_l2_service_port_base::verify_matching_mirror_types(const la_mirror_command* mirror_cmd, mirror_type_e type)
{
    switch (mirror_cmd->type()) {
    case silicon_one::la_object::object_type_e::L2_MIRROR_COMMAND: {
        const auto* l2_mirror_cmd = static_cast<const la_l2_mirror_command_base*>(mirror_cmd);
        auto actual_type = l2_mirror_cmd->get_mirror_type();

        if (type == actual_type) {
            return LA_STATUS_SUCCESS;
        }

        break;
    }
    case silicon_one::la_object::object_type_e::ERSPAN_MIRROR_COMMAND: {
        const auto* erspan_mirror_cmd = static_cast<const la_erspan_mirror_command_base*>(mirror_cmd);
        auto actual_type = erspan_mirror_cmd->get_mirror_type();

        if (type == actual_type) {
            return LA_STATUS_SUCCESS;
        }

        break;
    }
    default:
        // not supposed to happen
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_EINVAL;
}

la_status
la_l2_service_port_base::set_group_policy_encap(bool enabled)
{
    start_api_call("enabled=", enabled);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_l2_service_port_base::get_group_policy_encap(bool& out_enabled) const
{
    start_api_getter_call("");

    return LA_STATUS_ENOTIMPLEMENTED;
}

destination_id
la_l2_service_port_base::get_destination_id() const
{
    if (m_port_type == port_type_e::PWE) {
        return destination_id(NPL_DESTINATION_MASK_L2_PWE_DLP | m_pwe_gid);
    }
    return destination_id(NPL_DESTINATION_MASK_L2_DLP | m_port_gid);
}

la_status
la_l2_service_port_base::set_copc_profile(la_control_plane_classifier::l2_service_port_profile_id_t l2_service_port_profile_id)
{
    start_api_call("l2_service_port_profile_id=", l2_service_port_profile_id);

    if (m_port_type != port_type_e::AC) {
        return LA_STATUS_EINVAL;
    }

    if (l2_service_port_profile_id > la_device_impl::MAX_COPC_L2_SERVICE_PORT_PROFILES) {
        return LA_STATUS_EOUTOFRANGE;
    }

    m_copc_profile = l2_service_port_profile_id;

    // Update table
    npl_mac_lp_attributes_payload_t payload;
    populate_lp_attributes_payload(payload);

    la_status attribute_status = update_lp_attributes_payload(payload);
    return_on_error(attribute_status);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_base::get_copc_profile(
    la_control_plane_classifier::l2_service_port_profile_id_t& out_l2_service_port_profile_id) const
{
    out_l2_service_port_profile_id = m_copc_profile;

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
