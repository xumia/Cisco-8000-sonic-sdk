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

#include <climits>

#include "api/npu/la_vrf.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "nplapi/npl_constants.h"
#include "npu/counter_utils.h"
#include "npu/la_acl_delegate.h"
#include "npu/la_counter_set_impl.h"
#include "npu/la_gre_port_impl.h"
#include "npu/la_gue_port_impl.h"
#include "npu/la_ip_over_ip_tunnel_port_impl.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_svi_port_base.h"
#include "npu/la_switch_impl.h"
#include "npu/la_vrf_impl.h"
#include "npu/la_vrf_port_common_akpg.h"
#include "npu/resolution_utils.h"
#include "qos/la_egress_qos_profile_impl.h"
#include "qos/la_ingress_qos_profile_impl.h"
#include "qos/la_meter_set_impl.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

la_vrf_port_common_akpg::la_vrf_port_common_akpg(const la_device_impl_wptr& device, la_l3_port_wptr parent)
    : la_vrf_port_common_base(device, parent), m_slice_data(ASIC_MAX_SLICES_PER_DEVICE_NUM, slice_data())
{
    set_disable_mc_tunnel_decap(1);
}

la_vrf_port_common_akpg::~la_vrf_port_common_akpg()
{
}

la_status
la_vrf_port_common_akpg::initialize(la_l3_port_gid_t gid,
                                    la_mac_addr_t mac_addr,
                                    const la_switch_impl_wcptr& sw,
                                    const la_vrf_impl_wcptr& vrf,
                                    const la_ingress_qos_profile_impl_wptr& ingress_qos_profile_impl,
                                    const la_egress_qos_profile_impl_wptr& egress_qos_profile_impl)
{
    la_status status;
    m_ifg_use_count = make_unique<ifg_use_count>(m_device->get_slice_id_manager());

    m_sw = sw;
    m_vrf = vrf;
    m_mac_addr = mac_addr;
    m_gid = gid;

    m_egress_port_mirror_type = NPL_PORT_MIRROR_TYPE_CONDITIONED;

    m_ingress_qos_profile = ingress_qos_profile_impl;
    m_egress_qos_profile = egress_qos_profile_impl;

    m_l3_lp_attributes.minimal_l3_lp_attributes.per_protocol_count = 0;

    m_l3_lp_attributes.acl_drop_offset.cntr_offset.offset.base_cntr_offset = 0;
    set_disable_ipv4_mc(1);
    set_disable_ipv6_mc(1);
    set_disable_ipv4_uc(1);
    m_protocols.reset();

    m_l3_lp_attributes.q_counter = populate_counter_ptr_slice_pair(nullptr, 0, COUNTER_DIRECTION_INGRESS);
    m_l3_lp_attributes.minimal_l3_lp_attributes.p_counter = populate_counter_ptr_slice_pair(nullptr, 0, COUNTER_DIRECTION_INGRESS);
    m_l3_lp_attributes.m_counter = populate_counter_ptr_slice(nullptr, 0, COUNTER_DIRECTION_INGRESS);
    set_disable_ipv6_uc(1);
    set_disable_mpls(1);
    m_l3_lp_attributes.mirror_cmd = NPL_RX_NULL_MIRROR_CODE;
    m_l3_lp_attributes.minimal_l3_lp_attributes.ttl_mode = la_2_npl_mpls_ttl_inheritance_mode(m_device->get_ttl_inheritance_mode());
    m_l3_lp_attributes.uc_rpf_mode = NPL_RPF_MODE_NONE;
    m_l3_lp_attributes.minimal_l3_lp_attributes.l3_relay_id.id = m_vrf->get_gid();
    m_l3_lp_attributes.minimal_l3_lp_attributes.global_slp_id.id.lsbs.l3_slp_lsbs = get_l3_lp_lsb(m_gid);
    m_l3_lp_attributes.minimal_l3_lp_attributes.global_slp_id.id.msbs.l3_slp_msbs = get_l3_lp_msb(m_gid);
    m_l3_lp_attributes.minimal_l3_lp_attributes.lp_set = 1;

    set_l3_lp_mirror_type(get_initial_l3_lp_mirror_type());

    m_l3_lp_additional_attributes.load_balance_profile = NPL_LB_PROFILE_MPLS;
    m_l3_lp_additional_attributes.enable_monitor = 0;
    m_l3_lp_additional_attributes.slp_based_fwd_and_per_vrf_mpls_fwd.slp_based_forwarding = 0;
    m_l3_lp_additional_attributes.slp_based_fwd_and_per_vrf_mpls_fwd.per_vrf_mpls_fwd = 0;

    m_l3_lp_additional_attributes.qos_id = 0;

    m_l3_lp_attributes.rtf_conf_set_and_stages_or_post_fwd_stage.rtf_conf_set_and_stages.rtf_conf_set.val = RTF_CONF_SET_ID_INVALID;
    m_l3_lp_attributes.rtf_conf_set_and_stages_or_post_fwd_stage.rtf_conf_set_and_stages.ipv4_ipv6_init_rtf_stage
        .ipv4_init_rtf_stage
        = NPL_INIT_RTF_NONE;
    m_l3_lp_attributes.rtf_conf_set_and_stages_or_post_fwd_stage.rtf_conf_set_and_stages.ipv4_ipv6_init_rtf_stage
        .ipv6_init_rtf_stage
        = NPL_INIT_RTF_NONE;

    // SLP based forwarding result
    m_slp_based_forwarding_destination = nullptr;
    m_slp_based_forwarding_mpls_label_present = false;
    m_slp_based_forwarding_mpls_label.label = 0;

    // Add the port's MAC address to the device tables
    la_object::object_type_e type = m_parent->type();
    if (type != la_object::object_type_e::GRE_PORT) {
        status = m_device->m_mac_addr_manager->add(m_mac_addr, NPL_MAC_DA_TYPE_UC);
        return_on_error(status);
    }

    if (m_parent->type() == la_object::object_type_e::L3_AC_PORT) {
        const la_l3_ac_port_impl_wcptr parent = m_parent.weak_ptr_static_cast<la_l3_ac_port_impl>();
        m_is_recycle_ac = silicon_one::is_recycle_ac(parent);
    }
    if (m_is_recycle_ac) {
        la_mac_addr_t recycle_ac_smac;
        recycle_ac_smac.flat = RECYCLE_AC_SMAC;
        status = m_device->m_mac_addr_manager->add(recycle_ac_smac, NPL_MAC_DA_TYPE_UC);
        return_on_error(status);
    }

    // Update fallback vrf
    status = update_fallback_vrf();

    m_device->add_ifg_dependency(m_parent, ingress_qos_profile_impl);
    m_device->add_ifg_dependency(m_parent, egress_qos_profile_impl);

    m_device->add_object_dependency(ingress_qos_profile_impl, m_parent);
    m_device->add_object_dependency(egress_qos_profile_impl, m_parent);

    return LA_STATUS_SUCCESS;
}

npl_port_mirror_type_e
la_vrf_port_common_akpg::get_initial_l3_lp_mirror_type() const
{
    return NPL_PORT_MIRROR_TYPE_CONDITIONED;
}

la_status
la_vrf_port_common_akpg::do_get_protocol_enabled(la_l3_protocol_e protocol, bool& out_enabled) const
{
    bool is_enabled = true;
    la_status status;

    switch (protocol) {
    case la_l3_protocol_e::IPV4_UC:
        is_enabled = !get_disable_ipv4_uc();
        status = LA_STATUS_SUCCESS;
        break;
    case la_l3_protocol_e::MPLS:
        is_enabled = !get_disable_mpls();
        status = LA_STATUS_SUCCESS;
        break;
    case la_l3_protocol_e::IPV6_UC:
        is_enabled = !get_disable_ipv6_uc();
        status = LA_STATUS_SUCCESS;
        break;
    case la_l3_protocol_e::IPV4_MC:
        is_enabled = !get_disable_ipv4_mc();
        status = LA_STATUS_SUCCESS;
        break;
    case la_l3_protocol_e::IPV6_MC:
        is_enabled = !get_disable_ipv6_mc();
        status = LA_STATUS_SUCCESS;
        break;
    default:
        status = LA_STATUS_ENOTIMPLEMENTED;
    }

    out_enabled = is_enabled;
    return status;
}

la_status
la_vrf_port_common_akpg::update_protocol_enabled(la_l3_protocol_e protocol, bool enabled)
{
    la_status status;

    switch (protocol) {
    case la_l3_protocol_e::IPV4_UC:
        set_disable_ipv4_uc(!enabled);
        m_protocols[(size_t)la_l3_protocol_e::IPV4_UC] = enabled;
        break;
    case la_l3_protocol_e::IPV6_UC:
        set_disable_ipv6_uc(!enabled);
        m_protocols[(size_t)la_l3_protocol_e::IPV6_UC] = enabled;
        break;
    case la_l3_protocol_e::MPLS:
        set_disable_mpls(!enabled);
        m_protocols[(size_t)la_l3_protocol_e::MPLS] = enabled;
        break;
    case la_l3_protocol_e::IPV4_MC:
        set_disable_ipv4_mc(!enabled);
        m_protocols[(size_t)la_l3_protocol_e::IPV4_MC] = enabled;
        break;
    case la_l3_protocol_e::IPV6_MC:
        set_disable_ipv6_mc(!enabled);
        m_protocols[(size_t)la_l3_protocol_e::IPV6_MC] = enabled;
        break;
    default:
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::set_l3_lp_attributes_to_param(npl_base_l3_lp_attributes_t& attribs,
                                                       la_l3_protocol_e protocol,
                                                       bool enabled)
{
    switch (protocol) {
    case la_l3_protocol_e::IPV4_UC:
        attribs.minimal_l3_lp_attributes.disable_ipv4_uc = !enabled;
        break;
    case la_l3_protocol_e::IPV6_UC:
        attribs.minimal_l3_lp_attributes.disable_ipv6_uc = !enabled;
        break;
    case la_l3_protocol_e::MPLS:
        attribs.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mpls = !enabled;
        attribs.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mc_tunnel_decap = !enabled;
        break;
    case la_l3_protocol_e::IPV4_MC:
        attribs.minimal_l3_lp_attributes.disable_ipv4_mc = !enabled;
        break;
    case la_l3_protocol_e::IPV6_MC:
        attribs.minimal_l3_lp_attributes.disable_ipv6_mc = !enabled;
        break;
    default:
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    return LA_STATUS_SUCCESS;
}

void
la_vrf_port_common_akpg::set_l3_lp_attributes(npl_base_l3_lp_attributes_t& attribs)
{
    m_l3_lp_attributes.minimal_l3_lp_attributes.disable_ipv4_uc = attribs.minimal_l3_lp_attributes.disable_ipv4_uc;
    m_l3_lp_attributes.minimal_l3_lp_attributes.disable_ipv6_uc = attribs.minimal_l3_lp_attributes.disable_ipv6_uc;
    m_l3_lp_attributes.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mpls
        = attribs.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mpls;
    m_l3_lp_attributes.minimal_l3_lp_attributes.disable_ipv4_mc = attribs.minimal_l3_lp_attributes.disable_ipv4_mc;
    m_l3_lp_attributes.minimal_l3_lp_attributes.disable_ipv6_mc = attribs.minimal_l3_lp_attributes.disable_ipv6_mc;
    m_l3_lp_attributes.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mc_tunnel_decap
        = attribs.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mc_tunnel_decap;
}

la_status
la_vrf_port_common_akpg::set_l3_lp_attributes(npl_base_l3_lp_attributes_t& attribs, la_l3_protocol_e protocol)
{
    switch (protocol) {
    case la_l3_protocol_e::IPV4_UC:
        m_l3_lp_attributes.minimal_l3_lp_attributes.disable_ipv4_uc = attribs.minimal_l3_lp_attributes.disable_ipv4_uc;
        break;
    case la_l3_protocol_e::IPV6_UC:
        m_l3_lp_attributes.minimal_l3_lp_attributes.disable_ipv6_uc = attribs.minimal_l3_lp_attributes.disable_ipv6_uc;
        break;
    case la_l3_protocol_e::MPLS:
        m_l3_lp_attributes.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mpls
            = attribs.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mpls;
        m_l3_lp_attributes.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mc_tunnel_decap
            = attribs.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mc_tunnel_decap;
        break;
    case la_l3_protocol_e::IPV4_MC:
        m_l3_lp_attributes.minimal_l3_lp_attributes.disable_ipv4_mc = attribs.minimal_l3_lp_attributes.disable_ipv4_mc;
        break;
    case la_l3_protocol_e::IPV6_MC:
        m_l3_lp_attributes.minimal_l3_lp_attributes.disable_ipv6_mc = attribs.minimal_l3_lp_attributes.disable_ipv6_mc;
        break;
    default:
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

void
la_vrf_port_common_akpg::set_disable_mpls(npl_base_l3_lp_attributes_t& attribs, uint64_t disable_mpls)
{
    attribs.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mpls = disable_mpls;
}

void
la_vrf_port_common_akpg::set_disable_mpls(uint64_t disable_mpls)
{
    m_l3_lp_attributes.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mpls = disable_mpls;
    m_l3_lp_attributes.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mc_tunnel_decap = disable_mpls;
}

uint64_t
la_vrf_port_common_akpg::get_disable_mpls() const
{
    return m_l3_lp_attributes.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mpls;
}

void
la_vrf_port_common_akpg::set_disable_mc_tunnel_decap(npl_base_l3_lp_attributes_t& attribs, uint64_t disable_mc_tunnel_decap)
{
    attribs.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mc_tunnel_decap = disable_mc_tunnel_decap;
    attribs.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mpls = disable_mc_tunnel_decap;
}

void
la_vrf_port_common_akpg::set_disable_mc_tunnel_decap(uint64_t disable_mc_tunnel_decap)
{
    m_l3_lp_attributes.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mc_tunnel_decap = disable_mc_tunnel_decap;
    m_l3_lp_attributes.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mpls = disable_mc_tunnel_decap;
}

uint64_t
la_vrf_port_common_akpg::get_disable_mc_tunnel_decap() const
{
    return m_l3_lp_attributes.minimal_l3_lp_attributes.disable_mpls_or_mc_tunnel.disable_mc_tunnel_decap;
}

void
la_vrf_port_common_akpg::set_disable_ipv4_mc(npl_base_l3_lp_attributes_t& attribs, uint64_t disable_ipv4_mc)
{
    attribs.minimal_l3_lp_attributes.disable_ipv4_mc = disable_ipv4_mc;
}

void
la_vrf_port_common_akpg::set_disable_ipv4_mc(uint64_t disable_ipv4_mc)
{
    m_l3_lp_attributes.minimal_l3_lp_attributes.disable_ipv4_mc = disable_ipv4_mc;
}

uint64_t
la_vrf_port_common_akpg::get_disable_ipv4_mc() const
{
    return m_l3_lp_attributes.minimal_l3_lp_attributes.disable_ipv4_mc;
}

void
la_vrf_port_common_akpg::set_disable_ipv6_uc(npl_base_l3_lp_attributes_t& attribs, uint64_t disable_ipv6_uc)
{
    attribs.minimal_l3_lp_attributes.disable_ipv6_uc = disable_ipv6_uc;
}

void
la_vrf_port_common_akpg::set_disable_ipv6_uc(uint64_t disable_ipv6_uc)
{
    m_l3_lp_attributes.minimal_l3_lp_attributes.disable_ipv6_uc = disable_ipv6_uc;
}

uint64_t
la_vrf_port_common_akpg::get_disable_ipv6_uc() const
{
    return m_l3_lp_attributes.minimal_l3_lp_attributes.disable_ipv6_uc;
}

void
la_vrf_port_common_akpg::set_l3_lp_mirror_type(npl_port_mirror_type_e l3_lp_mirror_type)
{
    m_l3_lp_attributes.l3_lp_mirror_type = l3_lp_mirror_type;
}

la_status
la_vrf_port_common_akpg::insert_to_em(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                      la_ipv4_addr_t ip_addr,
                                      la_mac_addr_t mac_addr,
                                      bool override_entry)
{
    la_l2_destination_gid_t dest_gid;
    la_status status = get_em_table_dest_gid(mac_addr, dest_gid);
    return_on_error(status);

    typename npl_ipv4_vrf_dip_em_table_t::key_type key;
    typename npl_ipv4_vrf_dip_em_table_t::value_type value;
    typename npl_ipv4_vrf_dip_em_table_t::entry_wptr_type entry;

    uint64_t lpm_result_type;
    status = get_em_table_lpm_result_type(lpm_result_type);
    return_on_error(status);

    populate_em_table_key(ip_addr, key);
    value.payloads.em_lookup_result.result_type
        = static_cast<decltype(value.payloads.em_lookup_result.result_type)>(lpm_result_type);
    npl_em_result_dsp_host_wo_class_t& dsp_host_wo_class(value.payloads.em_lookup_result.result.dsp_host_wo_class);

    dsp_host_wo_class.host_mac_lsb = mac_addr.flat & 0xFFFFFFFFFF;
    dsp_host_wo_class.host_mac_msb = mac_addr.flat >> 41;
    dsp_host_wo_class.dest = dest_gid & 0x0FFF;
    if (((dest_gid & 0xC000) >> 2) == NPL_EM_LOOKUP_RESULT_MASK_DSP) {
        dsp_host_wo_class.dest_type = static_cast<uint64_t>(la_device_impl::lp_map_prefix_type_e::DSP);
        dsp_host_wo_class.extra_dest_bit = (dest_gid >> 12) & 0x1;
    } else if (((dest_gid & 0xC000) >> 2) == NPL_EM_LOOKUP_RESULT_MASK_DSPA) {
        dsp_host_wo_class.dest_type = static_cast<uint64_t>(la_device_impl::lp_map_prefix_type_e::DSPA);
        dsp_host_wo_class.extra_dest_bit = (dest_gid >> 12) & 0x1;
    } else {
        // For L2_DLP, dest_gid[12] is embedded in the lp_map[12]. The lp_map
        // serves two purposes for L2_DLP in the data path: to determine
        // dest[19:14] and the to determine dest[12]. dest[13] is the
        // extra_dest.
        if ((dest_gid >> 12) & 0x1) {
            dsp_host_wo_class.dest_type = static_cast<uint64_t>(la_device_impl::lp_map_prefix_type_e::L2_DLP_1);
        } else {
            dsp_host_wo_class.dest_type = static_cast<uint64_t>(la_device_impl::lp_map_prefix_type_e::L2_DLP_0);
        }
        dsp_host_wo_class.extra_dest_bit = (dest_gid >> 13) & 0x1;
    }

    if (override_entry) {
        status = table->set(key, value, entry);
    } else {
        status = table->insert(key, value, entry);
    }

    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::insert_to_em(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                      la_ipv6_addr_t ip_addr,
                                      la_mac_addr_t mac_addr,
                                      bool override_entry)
{
    la_l2_destination_gid_t dest_gid;
    la_status status = get_em_table_dest_gid(mac_addr, dest_gid);
    return_on_error(status);

    typename npl_ipv6_vrf_dip_em_table_t::key_type key;
    typename npl_ipv6_vrf_dip_em_table_t::value_type value;
    typename npl_ipv6_vrf_dip_em_table_t::entry_wptr_type entry;

    uint64_t lpm_result_type;
    status = get_em_table_lpm_result_type(lpm_result_type);
    return_on_error(status);

    populate_em_table_key(ip_addr, key);
    value.payloads.em_lookup_result.result_type
        = static_cast<decltype(value.payloads.em_lookup_result.result_type)>(lpm_result_type);
    npl_em_result_dsp_host_wo_class_t& dsp_host_wo_class(value.payloads.em_lookup_result.result.dsp_host_wo_class);

    dsp_host_wo_class.host_mac_lsb = mac_addr.flat & 0xFFFFFFFFFF;
    dsp_host_wo_class.host_mac_msb = mac_addr.flat >> 41;
    dsp_host_wo_class.dest = dest_gid & 0x0FFF;
    if (((dest_gid & 0xC000) >> 2) == NPL_EM_LOOKUP_RESULT_MASK_DSP) {
        dsp_host_wo_class.dest_type = static_cast<uint64_t>(la_device_impl::lp_map_prefix_type_e::DSP);
        dsp_host_wo_class.extra_dest_bit = (dest_gid >> 12) & 0x1;
    } else if (((dest_gid & 0xC000) >> 2) == NPL_EM_LOOKUP_RESULT_MASK_DSPA) {
        dsp_host_wo_class.dest_type = static_cast<uint64_t>(la_device_impl::lp_map_prefix_type_e::DSPA);
        dsp_host_wo_class.extra_dest_bit = (dest_gid >> 12) & 0x1;
    } else {
        // For L2_DLP, dest_gid[12] is embedded in the lp_map[12]. The lp_map
        // serves two purposes for L2_DLP in the data path: to determine
        // dest[19:14] and the to determine dest[12]. dest[13] is the
        // extra_dest.
        if ((dest_gid >> 12) & 0x1) {
            dsp_host_wo_class.dest_type = static_cast<uint64_t>(la_device_impl::lp_map_prefix_type_e::L2_DLP_1);
        } else {
            dsp_host_wo_class.dest_type = static_cast<uint64_t>(la_device_impl::lp_map_prefix_type_e::L2_DLP_0);
        }
        dsp_host_wo_class.extra_dest_bit = (dest_gid >> 13) & 0x1;
    }

    if (override_entry) {
        status = table->set(key, value, entry);
    } else {
        status = table->insert(key, value, entry);
    }

    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

template <class _TableType, class _AddrType>
la_status
la_vrf_port_common_akpg::insert_to_em_with_class_id(const std::shared_ptr<_TableType>& table,
                                                    _AddrType ip_addr,
                                                    la_mac_addr_t mac_addr,
                                                    la_class_id_t class_id,
                                                    bool override_entry)
{
    la_l2_destination_gid_t dest_gid;
    la_status status = get_em_table_dest_gid(mac_addr, dest_gid);
    return_on_error(status);

    status = check_class_id_and_dest_gid(class_id, dest_gid);
    return_on_error(status);

    typename _TableType::key_type key;
    typename _TableType::value_type value;
    typename _TableType::entry_wptr_type entry;

    uint64_t lpm_result_type;
    status = get_em_table_lpm_result_type(lpm_result_type);
    return_on_error(status);

    populate_em_table_key(ip_addr, key);
    value.payloads.em_lookup_result.result_type
        = static_cast<decltype(value.payloads.em_lookup_result.result_type)>(lpm_result_type);
    npl_em_result_dsp_host_w_class_t& dsp_host_w_class(value.payloads.em_lookup_result.result.dsp_host_w_class);
    if (((dest_gid & 0xC000) >> 2) == NPL_EM_LOOKUP_RESULT_MASK_DSP) {
        dsp_host_w_class.dest_type_or_has_class.dest_type
            = static_cast<uint64_t>(la_device_impl::lp_map_prefix_type_e::DSP_WITH_CLASS);
        dsp_host_w_class.extra_dest_bit = (dest_gid >> 8) & 0x1;
    } else if (((dest_gid & 0xC000) >> 2) == NPL_EM_LOOKUP_RESULT_MASK_DSPA) {
        dsp_host_w_class.dest_type_or_has_class.dest_type
            = static_cast<uint64_t>(la_device_impl::lp_map_prefix_type_e::DSPA_WITH_CLASS);
        dsp_host_w_class.extra_dest_bit = (dest_gid >> 8) & 0x1;
    } else {
        if ((dest_gid >> 8) & 0x1) {
            dsp_host_w_class.dest_type_or_has_class.dest_type
                = static_cast<uint64_t>(la_device_impl::lp_map_prefix_type_e::L2_DLP_WITH_CLASS_1);
        } else {
            dsp_host_w_class.dest_type_or_has_class.dest_type
                = static_cast<uint64_t>(la_device_impl::lp_map_prefix_type_e::L2_DLP_WITH_CLASS_0);
        }
        dsp_host_w_class.extra_dest_bit = (dest_gid >> 9) & 0x1;
    }
    dsp_host_w_class.class_id = class_id;
    dsp_host_w_class.dest = dest_gid & 0xFF;
    dsp_host_w_class.host_mac_lsb = mac_addr.flat & 0xFFFFFFFFFF;
    dsp_host_w_class.host_mac_msb = mac_addr.flat >> 41;

    if (override_entry) {
        status = table->set(key, value, entry);
    } else {
        status = table->insert(key, value, entry);
    }

    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

template <class _TableType, class _AddrType>
la_status
la_vrf_port_common_akpg::add_ip_host_with_class_id(const std::shared_ptr<_TableType>& table,
                                                   la_port_host<_AddrType>& port_hosts,
                                                   _AddrType ip_addr,
                                                   la_mac_addr_t mac_addr,
                                                   la_class_id_t class_id)
{
    typename subnet_ip_map_t<_AddrType>::iterator it;
    la_status status = get_addr_subnet(port_hosts.m_subnet_ip_map, ip_addr, it);

    if (status == LA_STATUS_ENOTFOUND) {
        port_hosts.add_to_pending_list(ip_addr, mac_addr, class_id);
    } else {
        status = insert_to_em_with_class_id(table, ip_addr, mac_addr, class_id, false /* override_entry */);
        return_on_error(status);

        ip_host_data data;
        data.set_mac_addr(mac_addr);
        data.set_class_id(class_id);

        it->second[ip_addr] = data;
    }

    return LA_STATUS_SUCCESS;
}

template <class _TableType, class _AddrType>
la_status
la_vrf_port_common_akpg::modify_ip_host_with_class_id(const std::shared_ptr<_TableType>& table,
                                                      la_port_host<_AddrType>& port_hosts,
                                                      _AddrType ip_addr,
                                                      la_mac_addr_t mac_addr,
                                                      la_class_id_t class_id)
{
    typename _TableType::key_type key;
    typename _TableType::entry_pointer_type entry;
    typename subnet_ip_map_t<_AddrType>::iterator it;

    la_status status = get_addr_subnet(port_hosts.m_subnet_ip_map, ip_addr, it);
    if (status == LA_STATUS_ENOTFOUND) {
        if (port_hosts.pending_list_has_host(ip_addr)) {
            port_hosts.remove_host_from_pending_list(ip_addr);
            port_hosts.add_to_pending_list(ip_addr, mac_addr, class_id);
        } else {
            return_on_error(status);
        }
    } else {
        // Check if IP is configured.
        populate_em_table_key(ip_addr, key);
        la_status status = table->lookup(key, entry);
        return_on_error(status);

        status = insert_to_em_with_class_id(table, ip_addr, mac_addr, class_id, true /* override_entry */);
        return_on_error(status);

        ip_host_data data;
        data.set_mac_addr(mac_addr);
        data.set_class_id(class_id);

        it->second.erase(ip_addr);
        it->second[ip_addr] = data;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::modify_ip_host(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                        la_ipv4_addr_t ip_addr,
                                        la_mac_addr_t mac_addr)
{
    typename npl_ipv4_vrf_dip_em_table_t::key_type key;
    typename npl_ipv4_vrf_dip_em_table_t::entry_pointer_type entry;
    typename subnet_ip_map_t<la_ipv4_addr_t>::iterator it;

    la_status status = get_addr_subnet(m_subnet_ipv4.m_subnet_ip_map, ip_addr, it);

    if (status == LA_STATUS_ENOTFOUND) {
        if (m_subnet_ipv4.pending_list_has_host(ip_addr)) {
            m_subnet_ipv4.remove_host_from_pending_list(ip_addr);
            m_subnet_ipv4.add_to_pending_list(ip_addr, mac_addr);
        } else {
            return_on_error(status);
        }
    } else {
        // Check if IP is configured.
        populate_em_table_key(ip_addr, key);
        la_status status = table->lookup(key, entry);
        return_on_error(status);

        status = insert_to_em(table, ip_addr, mac_addr, true /* override_entry */);
        return_on_error(status);

        ip_host_data data;
        data.set_mac_addr(mac_addr);

        it->second.erase(ip_addr);
        it->second[ip_addr] = data;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::modify_ip_host(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                        la_ipv6_addr_t ip_addr,
                                        la_mac_addr_t mac_addr)
{
    typename npl_ipv6_vrf_dip_em_table_t::key_type key;
    typename npl_ipv6_vrf_dip_em_table_t::entry_pointer_type entry;
    typename subnet_ip_map_t<la_ipv6_addr_t>::iterator it;

    la_status status = get_addr_subnet(m_subnet_ipv6.m_subnet_ip_map, ip_addr, it);

    if (status == LA_STATUS_ENOTFOUND) {
        if (m_subnet_ipv6.pending_list_has_host(ip_addr)) {
            m_subnet_ipv6.remove_host_from_pending_list(ip_addr);
            m_subnet_ipv6.add_to_pending_list(ip_addr, mac_addr);
        } else {
            return_on_error(status);
        }
    } else {

        // Check if IP is configured.
        populate_em_table_key(ip_addr, key);
        la_status status = table->lookup(key, entry);
        return_on_error(status);

        status = insert_to_em(table, ip_addr, mac_addr, true /* override_entry */);
        return_on_error(status);

        ip_host_data data;
        data.set_mac_addr(mac_addr);

        it->second.erase(ip_addr);
        it->second[ip_addr] = data;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::get_ip_host(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                     const la_port_host<la_ipv4_addr_t>& port_hosts,
                                     la_ipv4_addr_t ip_addr,
                                     la_mac_addr_t& out_mac_addr) const
{
    bool found = false;
    subnet_count_map_key_t key;

    for (auto& subnet : port_hosts.m_subnet_ip_map) {
        key = subnet.first;
        found = is_addr_in_subnet(ip_addr, key);
        if (found) {
            break;
        }
    }

    if (!found) {
        if (port_hosts.pending_list_has_host(ip_addr)) {
            out_mac_addr = port_hosts.get_ip_host_data_from_pending_list(ip_addr).get_mac_addr();

            return LA_STATUS_SUCCESS;
        }

        return LA_STATUS_ENOTFOUND;
    }

    typename npl_ipv4_vrf_dip_em_table_t::value_type value;
    la_status status = populate_em_table_value(table, ip_addr, value);
    return_on_error(status);

    auto dest_type = value.payloads.em_lookup_result.result.dsp_host_w_class.dest_type_or_has_class.dest_type;
    if (dest_type & 0x4) {
        // check if bit 2 of dest_type is set... This bit is same as has_class_id
        out_mac_addr.flat = value.payloads.em_lookup_result.result.dsp_host_w_class.host_mac_lsb;
        out_mac_addr.bytes[5] = value.payloads.em_lookup_result.result.dsp_host_w_class.host_mac_msb << 1;
    } else {
        out_mac_addr.flat = value.payloads.em_lookup_result.result.dsp_host_wo_class.host_mac_lsb;
        out_mac_addr.bytes[5] = value.payloads.em_lookup_result.result.dsp_host_wo_class.host_mac_msb << 1;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::get_ip_host(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                     const la_port_host<la_ipv4_addr_t>& port_hosts,
                                     la_ipv4_addr_t ip_addr,
                                     la_mac_addr_t& out_mac_addr,
                                     la_class_id_t& out_class_id) const
{
    bool found = false;
    subnet_count_map_key_t key;

    for (auto& subnet : port_hosts.m_subnet_ip_map) {
        key = subnet.first;
        found = is_addr_in_subnet(ip_addr, key);
        if (found) {
            break;
        }
    }

    if (!found) {
        if (port_hosts.pending_list_has_host(ip_addr)) {
            out_mac_addr = port_hosts.get_ip_host_data_from_pending_list(ip_addr).get_mac_addr();

            return LA_STATUS_SUCCESS;
        }

        return LA_STATUS_ENOTFOUND;
    }

    typename npl_ipv4_vrf_dip_em_table_t::value_type value;
    la_status status = populate_em_table_value(table, ip_addr, value);
    return_on_error(status);

    out_mac_addr.flat = value.payloads.em_lookup_result.result.dsp_host_w_class.host_mac_lsb;
    out_mac_addr.bytes[5] = value.payloads.em_lookup_result.result.dsp_host_w_class.host_mac_msb << 1;
    out_class_id = value.payloads.em_lookup_result.result.dsp_host_w_class.class_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::get_ip_host(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                     const la_port_host<la_ipv6_addr_t>& port_hosts,
                                     la_ipv6_addr_t ip_addr,
                                     la_mac_addr_t& out_mac_addr) const
{
    bool found = false;
    subnet_count_map_key_t key;

    for (auto& subnet : port_hosts.m_subnet_ip_map) {
        key = subnet.first;
        found = is_addr_in_subnet(ip_addr, key);
        if (found) {
            break;
        }
    }

    if (!found) {
        if (port_hosts.pending_list_has_host(ip_addr)) {
            out_mac_addr = port_hosts.get_ip_host_data_from_pending_list(ip_addr).get_mac_addr();

            return LA_STATUS_SUCCESS;
        }
        return LA_STATUS_ENOTFOUND;
    }

    typename npl_ipv6_vrf_dip_em_table_t::value_type value;
    la_status status = populate_em_table_value(table, ip_addr, value);
    return_on_error(status);
    auto dest_type = value.payloads.em_lookup_result.result.dsp_host_w_class.dest_type_or_has_class.dest_type;
    if (dest_type & 0x4) {
        // check if bit 2 of dest_type is set... This bit is same as has_class_id
        out_mac_addr.flat = value.payloads.em_lookup_result.result.dsp_host_w_class.host_mac_lsb;
        out_mac_addr.bytes[5] = value.payloads.em_lookup_result.result.dsp_host_w_class.host_mac_msb << 1;
    } else {
        out_mac_addr.flat = value.payloads.em_lookup_result.result.dsp_host_wo_class.host_mac_lsb;
        out_mac_addr.bytes[5] = value.payloads.em_lookup_result.result.dsp_host_wo_class.host_mac_msb << 1;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::get_ip_host(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                     const la_port_host<la_ipv6_addr_t>& port_hosts,
                                     la_ipv6_addr_t ip_addr,
                                     la_mac_addr_t& out_mac_addr,
                                     la_class_id_t& out_class_id) const
{
    bool found = false;
    subnet_count_map_key_t key;

    for (auto& subnet : port_hosts.m_subnet_ip_map) {
        key = subnet.first;
        found = is_addr_in_subnet(ip_addr, key);
        if (found) {
            break;
        }
    }

    if (!found) {
        if (port_hosts.pending_list_has_host(ip_addr)) {
            out_mac_addr = port_hosts.get_ip_host_data_from_pending_list(ip_addr).get_mac_addr();

            return LA_STATUS_SUCCESS;
        }

        return LA_STATUS_ENOTFOUND;
    }

    typename npl_ipv6_vrf_dip_em_table_t::value_type value;
    la_status status = populate_em_table_value(table, ip_addr, value);
    return_on_error(status);

    out_mac_addr.flat = value.payloads.em_lookup_result.result.dsp_host_w_class.host_mac_lsb;
    out_mac_addr.bytes[5] = value.payloads.em_lookup_result.result.dsp_host_w_class.host_mac_msb << 1;
    out_class_id = value.payloads.em_lookup_result.result.dsp_host_w_class.class_id;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::get_ip_hosts(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                      const la_port_host<la_ipv4_addr_t>& port_hosts,
                                      la_mac_addr_vec& out_mac_addresses) const
{
    out_mac_addresses.clear();
    for (auto& subnet : port_hosts.m_subnet_ip_map) {
        for (auto& host : subnet.second) {
            typename npl_ipv4_vrf_dip_em_table_t::value_type value;
            la_status status = populate_em_table_value(table, host.first, value);
            return_on_error(status);

            la_mac_addr_t address;
            address.flat = value.payloads.em_lookup_result.result.dsp_host_wo_class.host_mac_lsb;
            address.bytes[5] = value.payloads.em_lookup_result.result.dsp_host_wo_class.host_mac_msb << 1;
            out_mac_addresses.push_back(address);
        }
    }

    for (auto& host : port_hosts.pending_hosts_map) {
        out_mac_addresses.push_back(host.second.get_mac_addr());
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::get_ip_hosts(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                      const la_port_host<la_ipv6_addr_t>& port_hosts,
                                      la_mac_addr_vec& out_mac_addresses) const
{
    out_mac_addresses.clear();
    for (auto& subnet : port_hosts.m_subnet_ip_map) {
        for (auto& host : subnet.second) {
            typename npl_ipv6_vrf_dip_em_table_t::value_type value;
            la_status status = populate_em_table_value(table, host.first, value);
            return_on_error(status);

            la_mac_addr_t address;
            address.flat = value.payloads.em_lookup_result.result.dsp_host_wo_class.host_mac_lsb;
            address.bytes[5] = value.payloads.em_lookup_result.result.dsp_host_wo_class.host_mac_msb << 1;
            out_mac_addresses.push_back(address);
        }
    }

    for (auto& host : port_hosts.pending_hosts_map) {
        out_mac_addresses.push_back(host.second.get_mac_addr());
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::modify_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr)
{
    const auto& table(m_device->m_tables.ipv4_vrf_dip_em_table);

    return modify_ip_host(table, ip_addr, mac_addr);
}

la_status
la_vrf_port_common_akpg::modify_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr)
{
    const auto& table(m_device->m_tables.ipv6_vrf_dip_em_table);

    return modify_ip_host(table, ip_addr, mac_addr);
}

la_status
la_vrf_port_common_akpg::add_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id)
{
    const auto& table(m_device->m_tables.ipv4_vrf_dip_em_table);

    return add_ip_host_with_class_id(table, m_subnet_ipv4, ip_addr, mac_addr, class_id);
}

la_status
la_vrf_port_common_akpg::modify_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id)
{
    const auto& table(m_device->m_tables.ipv4_vrf_dip_em_table);

    return modify_ip_host_with_class_id(table, m_subnet_ipv4, ip_addr, mac_addr, class_id);
}

la_status
la_vrf_port_common_akpg::add_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id)
{
    const auto& table(m_device->m_tables.ipv6_vrf_dip_em_table);

    return add_ip_host_with_class_id(table, m_subnet_ipv6, ip_addr, mac_addr, class_id);
}

la_status
la_vrf_port_common_akpg::modify_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id)
{
    const auto& table(m_device->m_tables.ipv6_vrf_dip_em_table);

    return modify_ip_host_with_class_id(table, m_subnet_ipv6, ip_addr, mac_addr, class_id);
}

la_status
la_vrf_port_common_akpg::configure_txpp_dlp_profile_table(la_slice_pair_id_t slice_pair)
{
    la_object::object_type_e type = m_parent->type();
    if ((type == la_object::object_type_e::GRE_PORT) || (type == la_object::object_type_e::IP_OVER_IP_TUNNEL_PORT)
        || (type == la_object::object_type_e::GUE_PORT)) {
        return LA_STATUS_SUCCESS;
    }

    const auto& table(m_device->m_tables.txpp_em_dlp_profile_mapping_table[slice_pair]);
    npl_txpp_em_dlp_profile_mapping_table_key_t key_l3_dlp_subnet;
    npl_txpp_em_dlp_profile_mapping_table_value_t value;
    npl_txpp_em_dlp_profile_mapping_table_entry_t* entry = nullptr;

    key_l3_dlp_subnet.txpp_em_dlp_profile_mapping_key.dlp_type = NPL_DLP_TYPE_L3;
    key_l3_dlp_subnet.txpp_em_dlp_profile_mapping_key.dlp_id = get_l3_dlp_value_from_gid(m_gid);

    value.action = NPL_TXPP_EM_DLP_PROFILE_MAPPING_TABLE_ACTION_INIT_TX_PROFILE_DATA;

    auto v4_sec_acl_p = m_delegate_acls[(int)la_acl_packet_format_e::IPV4][(int)la_acl_direction_e::EGRESS];
    if (!v4_sec_acl_p.empty()) {
        la_acl_id_t acl_id = la_device_impl::ACL_INVALID_ID;
        v4_sec_acl_p[0]->get_id(slice_pair, acl_id);
        value.payloads.init_tx_profile_data.dlp_profile.overload_union_user_app_data_defined.user_app_dlp_profile.l3_sec.acl_v4_id
            = acl_id;
    }

    auto v6_sec_acl_p = m_delegate_acls[(int)la_acl_packet_format_e::IPV6][(int)la_acl_direction_e::EGRESS];
    if (!v6_sec_acl_p.empty()) {
        la_acl_id_t acl_id = la_device_impl::ACL_INVALID_ID;
        v6_sec_acl_p[0]->get_id(slice_pair, acl_id);
        value.payloads.init_tx_profile_data.dlp_profile.overload_union_user_app_data_defined.user_app_dlp_profile.l3_sec.acl_v6_id
            = acl_id;
    }

    // value.payloads.init_tx_profile_data.dlp_attributes is ignored and left as 0 for now.

    return table->set(key_l3_dlp_subnet, value, entry);
}

la_status
la_vrf_port_common_akpg::update_l3_lp_attributes_per_slice(la_slice_id_t slice,
                                                           npl_base_l3_lp_attributes_t& attribs,
                                                           npl_l3_lp_additional_attributes_t& additional_attribs)
{
    la_status status;
    la_object::object_type_e type = m_parent->type();

    // Counters are defined per slice-pair
    la_slice_pair_id_t pair_idx = slice / 2;

    // TODO: this code is similar to la_l2_service_port_base::populate_payload_counters.
    attribs.q_counter
        = populate_counter_ptr_slice_pair(m_q_counter[COUNTER_DIRECTION_INGRESS], pair_idx, COUNTER_DIRECTION_INGRESS);
    attribs.m_counter = populate_counter_ptr_slice(m_meter, slice, COUNTER_DIRECTION_INGRESS);

    bool is_exist_ingress_qcounter_or_meter = (m_q_counter[COUNTER_DIRECTION_INGRESS] != nullptr) || (m_meter != nullptr);
    if (!m_p_counter[COUNTER_DIRECTION_INGRESS] && is_exist_ingress_qcounter_or_meter) {
        attribs.minimal_l3_lp_attributes.p_counter = NPU_COUNTER_NOP;
    } else {
        attribs.minimal_l3_lp_attributes.p_counter
            = populate_counter_ptr_slice_pair(m_p_counter[COUNTER_DIRECTION_INGRESS], pair_idx, COUNTER_DIRECTION_INGRESS);
        if ((m_parent->type() == la_object::object_type_e::IP_OVER_IP_TUNNEL_PORT)
            || (type == la_object::object_type_e::GUE_PORT)) {
            attribs.minimal_l3_lp_attributes.p_counter
                = populate_counter_ptr_slice(m_p_counter[COUNTER_DIRECTION_INGRESS], slice, COUNTER_DIRECTION_INGRESS);
        }
    }

    additional_attribs.qos_id = m_ingress_qos_profile->get_id(pair_idx);

    // ACL id's are defined per slice-pair. IPv4 goes here.
    {
        la_acl_id_t acl_id = la_device_impl::ACL_INVALID_ID;
        auto acl_p = m_delegate_acls[(int)la_acl_packet_format_e::IPV4][(int)la_acl_direction_e::INGRESS];
        if (!acl_p.empty()) {
            acl_p[0]->get_id(slice / 2, acl_id);
        }
    }

    {
        la_acl_id_t acl_id = la_device_impl::ACL_INVALID_ID;
        auto acl_p = m_delegate_acls[(int)la_acl_packet_format_e::IPV6][(int)la_acl_direction_e::INGRESS];
        if (!acl_p.empty()) {
            acl_p[0]->get_id(slice / 2, acl_id);
        }
    }

    // Port specific code
    switch (type) {
    case la_object::object_type_e::SVI_PORT: {
        auto parent = m_parent.weak_ptr_static_cast<la_svi_port_base>();
        status = parent->update_l3_lp_attributes(slice, attribs, additional_attribs);

    } break;
    case la_object::object_type_e::L3_AC_PORT: {
        auto parent = m_parent.weak_ptr_static_cast<la_l3_ac_port_impl>();
        // TODO - It's a better idea to invoke the below once per slice-pair
        // However this requires some code restructuring
        status = parent->update_l3_lp_attributes(pair_idx, attribs, additional_attribs);

    } break;
    case la_object::object_type_e::IP_OVER_IP_TUNNEL_PORT: {
        auto parent = m_parent.weak_ptr_static_cast<la_ip_over_ip_tunnel_port_impl>();
        status = parent->update_tunnel_term_attributes_per_slice(slice, attribs);

    } break;
    case la_object::object_type_e::GRE_PORT: {
        auto parent = m_parent.weak_ptr_static_cast<la_gre_port_impl>();
        status = parent->update_l3_lp_attributes(slice, attribs, additional_attribs);

    } break;
    case la_object::object_type_e::GUE_PORT: {
        auto parent = m_parent.weak_ptr_static_cast<la_gue_port_impl>();
        status = parent->update_tunnel_term_attributes_per_slice(slice, attribs);

    } break;
    default:
        status = LA_STATUS_EUNKNOWN;
    }

    return status;
}

la_status
la_vrf_port_common_akpg::clear_slp_based_forwarding_destination()
{
    // Invoked from base::destroy(), needs to return success.
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::set_slp_based_forwarding_destination(const la_l3_destination_wptr& destination)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_vrf_port_common_akpg::set_source_based_forwarding(const la_l3_destination* l3_destination,
                                                     bool label_present,
                                                     la_mpls_label label)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_vrf_port_common_akpg::clear_source_based_forwarding()
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_vrf_port_common_akpg::get_source_based_forwarding(const la_l3_destination*& out_l3_destination,
                                                     bool& out_label_present,
                                                     la_mpls_label& out_label) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_vrf_port_common_akpg::set_rcy_sm_vlans(la_vlan_id_t vid1, la_vlan_id_t vid2)
{
    auto slices = m_ifg_use_count->get_slices();
    for (auto slice : slices) {
        la_slice_id_t slice_idx = slice;
        la_status status = configure_l3_dlp_table(slice_idx);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::get_rcy_sm_vlans(la_vlan_id_t& out_vid1, la_vlan_id_t& out_vid2) const
{
    auto svi = m_parent.weak_ptr_static_cast<la_svi_port_base>();
    la_status status = svi->get_rcy_sm_vlans(out_vid1, out_vid2);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::check_class_id_and_dest_gid(la_class_id_t class_id, la_l2_destination_gid_t dest_gid) const
{
    if (((dest_gid & 0xC000) >> 2) == NPL_EM_LOOKUP_RESULT_MASK_L2_DLP) {
        if ((dest_gid & 0x3FFF) > la_device_impl::MAX_L2_HOSTS_WITH_CLASS_IDENTIFIER) {
            return LA_STATUS_EINVAL;
        }
    } else {
        if ((dest_gid & 0x1FFF) > la_device_impl::MAX_HOSTS_WITH_CLASS_IDENTIFIER) {
            return LA_STATUS_EINVAL;
        }
    }

    if (class_id > la_device_impl::MAX_CLASS_IDENTIFIER_FOR_HOSTS) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::populate_dsp_or_dspa_gid(const la_l2_destination_wcptr& l2_dest,
                                                  la_l2_destination_gid_t& out_dest_gid) const
{
    bool is_aggregate;

    la_status status = get_dsp_or_dspa(m_device, l2_dest, out_dest_gid, is_aggregate);
    return_on_error(status);
    out_dest_gid &= 0x1FFF;
    if (is_aggregate) {
        out_dest_gid |= (NPL_EM_LOOKUP_RESULT_MASK_DSPA << 2);
    } else {
        out_dest_gid |= (NPL_EM_LOOKUP_RESULT_MASK_DSP << 2);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::populate_l2_dest_gid(const la_l2_destination_wcptr& l2_dest, la_l2_destination_gid_t& out_dest_gid) const
{
    out_dest_gid = m_device->get_l2_destination_gid(l2_dest);
    out_dest_gid &= 0x3FFF;
    out_dest_gid |= (NPL_EM_LOOKUP_RESULT_MASK_L2_DLP << 2);
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::populate_l2_flood_dest_gid(la_l2_destination_gid_t& out_dest_gid) const
{
    auto svi = m_parent.weak_ptr_static_cast<la_svi_port_base>();
    la_status status = svi->get_inject_up_source_port_gid(out_dest_gid);
    return_on_error(status);
    out_dest_gid &= 0x3FFF;
    out_dest_gid |= (NPL_EM_LOOKUP_RESULT_MASK_L2_DLP << 2);
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::set_lp_attribute_inheritance_mode(la_lp_attribute_inheritance_mode_e mode)
{
    npl_base_l3_lp_attributes_t attribs = m_l3_lp_attributes;
    if (mode == la_lp_attribute_inheritance_mode_e::TUNNEL) {
        attribs.minimal_l3_lp_attributes.lp_set = 1;
    } else {
        attribs.minimal_l3_lp_attributes.lp_set = 0;
    }

    if (attribs.minimal_l3_lp_attributes.lp_set == m_l3_lp_attributes.minimal_l3_lp_attributes.lp_set) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = update_l3_lp_attributes(attribs);
    return_on_error(status);

    m_l3_lp_attributes.minimal_l3_lp_attributes.lp_set = attribs.minimal_l3_lp_attributes.lp_set;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::set_ttl_inheritance_mode(la_mpls_ttl_inheritance_mode_e mode)
{
    npl_base_l3_lp_attributes_t attribs = m_l3_lp_attributes;
    attribs.minimal_l3_lp_attributes.ttl_mode = la_2_npl_mpls_ttl_inheritance_mode(mode);

    la_status status = update_l3_lp_attributes(attribs);
    return_on_error(status);

    m_l3_lp_attributes.minimal_l3_lp_attributes.ttl_mode = attribs.minimal_l3_lp_attributes.ttl_mode;

    return LA_STATUS_SUCCESS;
}

la_mpls_ttl_inheritance_mode_e
la_vrf_port_common_akpg::get_ttl_inheritance_mode() const
{
    la_mpls_ttl_inheritance_mode_e curr_mode
        = npl_2_la_mpls_ttl_inheritance_mode(m_l3_lp_attributes.minimal_l3_lp_attributes.ttl_mode);

    return curr_mode;
}

void
la_vrf_port_common_akpg::set_disable_ipv4_uc(uint64_t disable_ipv4_uc)
{
    m_l3_lp_attributes.minimal_l3_lp_attributes.disable_ipv4_uc = disable_ipv4_uc;
}

void
la_vrf_port_common_akpg::set_disable_ipv4_uc(npl_base_l3_lp_attributes_t& attribs, uint64_t disable_ipv4_uc)
{
    attribs.minimal_l3_lp_attributes.disable_ipv4_uc = disable_ipv4_uc;
}

uint64_t
la_vrf_port_common_akpg::get_disable_ipv4_uc() const
{
    return m_l3_lp_attributes.minimal_l3_lp_attributes.disable_ipv4_uc;
}

void
la_vrf_port_common_akpg::set_disable_ipv6_mc(uint64_t disable_ipv6_mc)
{
    m_l3_lp_attributes.minimal_l3_lp_attributes.disable_ipv6_mc = disable_ipv6_mc;
}

void
la_vrf_port_common_akpg::set_disable_ipv6_mc(npl_base_l3_lp_attributes_t& attribs, uint64_t disable_ipv6_mc)
{
    attribs.minimal_l3_lp_attributes.disable_ipv6_mc = disable_ipv6_mc;
}

uint64_t
la_vrf_port_common_akpg::get_disable_ipv6_mc() const
{
    return m_l3_lp_attributes.minimal_l3_lp_attributes.disable_ipv6_mc;
}

la_status
la_vrf_port_common_akpg::set_vrf(const la_vrf_impl_wcptr& vrf)
{
    npl_base_l3_lp_attributes_t attribs = m_l3_lp_attributes;
    attribs.minimal_l3_lp_attributes.l3_relay_id.id = vrf->get_gid();

    la_status status = update_l3_lp_attributes(attribs);
    return_on_error(status);

    m_l3_lp_attributes.minimal_l3_lp_attributes.l3_relay_id.id = attribs.minimal_l3_lp_attributes.l3_relay_id.id;

    m_vrf = vrf;

    return LA_STATUS_SUCCESS;
}

la_lp_attribute_inheritance_mode_e
la_vrf_port_common_akpg::get_lp_attribute_inheritance_mode() const
{
    la_lp_attribute_inheritance_mode_e curr_mode = (m_l3_lp_attributes.minimal_l3_lp_attributes.lp_set)
                                                       ? la_lp_attribute_inheritance_mode_e::PORT
                                                       : la_lp_attribute_inheritance_mode_e::TUNNEL;

    return curr_mode;
}

la_status
la_vrf_port_common_akpg::configure_egress_counter(const la_counter_set_impl_wptr& counter, la_counter_set::type_e counter_type)
{
    if (counter_type == la_counter_set::type_e::PORT) {
        bool per_protocol_count = (counter != nullptr) ? counter->get_set_size() > 1 : false;
        m_l3_lp_attributes.minimal_l3_lp_attributes.per_protocol_count = per_protocol_count ? 1 : 0;
    }

    la_status status = update_l3_lp_attributes(m_l3_lp_attributes);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::get_em_table_dest_gid(la_mac_addr_t mac_addr, la_l2_destination_gid_t& out_dest_gid) const
{
    la_l2_destination_wcptr l2_dest;
    la_status status = get_l2_destination(m_parent, mac_addr, l2_dest);

    if (m_parent->type() == la_object::object_type_e::SVI_PORT) {
        if (status == LA_STATUS_SUCCESS) {
            auto l2_port = l2_dest.weak_ptr_static_cast<const la_l2_service_port_base>();
            if (l2_port->get_egress_feature_mode() == la_l2_service_port::egress_feature_mode_e::L2) {
                populate_l2_dest_gid(l2_dest, out_dest_gid);
            } else {
                populate_dsp_or_dspa_gid(l2_dest, out_dest_gid);
            }
        } else if (status == LA_STATUS_ENOTFOUND) { // svi flood case
            status = populate_l2_flood_dest_gid(out_dest_gid);
            return_on_error(status);
        } else {
            return_on_error(status);
        }
    } else {
        if (status == LA_STATUS_SUCCESS) {
            populate_dsp_or_dspa_gid(l2_dest, out_dest_gid);
        } else {
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::get_em_table_lpm_result_type(uint64_t& out_lpm_result_type) const
{
    out_lpm_result_type = NPL_IP_UC_EM_RESULT_TYPE_HOST_MAC_AND_L3_DLP;
    return LA_STATUS_SUCCESS;
}

void
la_vrf_port_common_akpg::populate_em_table_key_ipv4_address(la_ipv4_addr_t ip_addr,
                                                            npl_ipv4_vrf_dip_em_table_key_t& out_em_key) const
{
    out_em_key.ipv4_ip_address_address = ip_addr.s_addr;
}

la_status
la_vrf_port_common_akpg::set_ingress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned)
{
    if (mirror_cmd != nullptr && !of_same_device(mirror_cmd, m_device)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    npl_base_l3_lp_attributes_t attribs = m_l3_lp_attributes;
    npl_l3_lp_additional_attributes_t additional_attribs = m_l3_lp_additional_attributes;

    attribs.mirror_cmd = (mirror_cmd == nullptr) ? NPL_RX_NULL_MIRROR_CODE : mirror_cmd->get_gid();
    attribs.l3_lp_mirror_type = is_acl_conditioned ? NPL_PORT_MIRROR_TYPE_CONDITIONED : NPL_PORT_MIRROR_TYPE_UN_CONDITIONED;

    la_status status = update_l3_lp_attributes(attribs, additional_attribs);
    return_on_error(status);

    m_l3_lp_attributes.mirror_cmd = attribs.mirror_cmd;
    m_l3_lp_attributes.l3_lp_mirror_type = attribs.l3_lp_mirror_type;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::get_ingress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const
{
    if (m_l3_lp_attributes.mirror_cmd == NPL_RX_NULL_MIRROR_CODE) {
        out_mirror_cmd = nullptr;
    } else {
        auto mirror_gid = m_l3_lp_attributes.mirror_cmd + la_device_impl::MIRROR_GID_INGRESS_OFFSET;
        out_mirror_cmd = m_device->m_mirror_commands[mirror_gid].weak_ptr_static_cast<la_mirror_command>().get();
    }

    out_is_acl_conditioned = (m_l3_lp_attributes.l3_lp_mirror_type == NPL_PORT_MIRROR_TYPE_CONDITIONED);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::set_mac(const la_mac_addr_t& mac_addr)
{
    // Not allow change mac address on recycle L3 AC port.
    if (m_is_recycle_ac) {
        return LA_STATUS_EINVAL;
    }

    la_status status = m_device->m_mac_addr_manager->remove(m_mac_addr, NPL_MAC_DA_TYPE_UC);
    return_on_error(status);

    status = m_device->m_mac_addr_manager->add(mac_addr, NPL_MAC_DA_TYPE_UC);
    return_on_error(status);

    uint64_t index;
    status = m_device->m_mac_addr_manager->get_index(mac_addr, index);
    return_on_error(status);

    for (auto& slice_data : m_slice_data) {
        if (slice_data.l3_dlp_table_entry != nullptr) {
            auto value = slice_data.l3_dlp_table_entry->value();

            npl_l3_dlp_attributes_t& attrib(value.payloads.l3_dlp_attributes);

            attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vlan_and_sa_lsb_encap.tpid_sa_lsb.sa_lsb
                = mac_address_manager::get_lsbits(mac_addr);
            attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.sa_prefix_index = index;

            status = slice_data.l3_dlp_table_entry->update(value);
            return_on_error(status);
        }
    }

    m_mac_addr = mac_addr;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::add_ifg(la_slice_ifg ifg)
{
    bool ifg_added, slice_added, slice_pair_added;
    m_ifg_use_count->add_ifg_user(ifg, ifg_added, slice_added, slice_pair_added);

    if (!slice_added) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = la_vrf_port_common_base::update_l3_lp_attributes_per_slice(ifg.slice, m_l3_lp_attributes);
    return_on_error(status);

    status = configure_l3_dlp_table(ifg.slice);
    return_on_error(status);

    if (slice_pair_added) {
        la_slice_pair_id_t pair_idx = ifg.slice / 2;

        status = configure_txpp_dlp_profile_table(pair_idx);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::remove_ifg(la_slice_ifg ifg)
{
    bool ifg_removed, slice_removed, slice_pair_removed;
    m_ifg_use_count->remove_ifg_user(ifg, ifg_removed, slice_removed, slice_pair_removed);

    if ((slice_removed) && (m_parent->type() == la_object::object_type_e::IP_OVER_IP_TUNNEL_PORT)) {
        auto parent = m_parent.weak_ptr_static_cast<la_ip_over_ip_tunnel_port_impl>();
        la_status status = parent->teardown_tunnel_termination_table_per_slice(ifg.slice);
        return_on_error(status);
    }
    if ((slice_removed) && (m_parent->type() == la_object::object_type_e::GUE_PORT)) {
        auto parent = m_parent.weak_ptr_static_cast<la_gue_port_impl>();
        la_status status = parent->teardown_tunnel_termination_table_per_slice(ifg.slice);
        return_on_error(status);
    }

    if (slice_removed) {
        la_status status = teardown_l3_dlp_table(ifg.slice);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::do_set_active(bool active, npl_base_l3_lp_attributes_t& attribs)
{
    if (active == false) {
        set_disable_ipv4_uc(attribs, 1);
        set_disable_ipv6_uc(attribs, 1);
        set_disable_mpls(attribs, 1);
        set_disable_ipv4_mc(attribs, 1);
        set_disable_ipv6_mc(attribs, 1);
        set_disable_mc_tunnel_decap(attribs, 1);
    } else {
        set_disable_ipv4_uc(attribs, !m_protocols[(size_t)la_l3_protocol_e::IPV4_UC]);
        set_disable_ipv6_uc(attribs, !m_protocols[(size_t)la_l3_protocol_e::IPV6_UC]);
        set_disable_mpls(attribs, !m_protocols[(size_t)la_l3_protocol_e::MPLS]);
        set_disable_ipv4_mc(attribs, !m_protocols[(size_t)la_l3_protocol_e::IPV4_MC]);
        set_disable_ipv6_mc(attribs, !m_protocols[(size_t)la_l3_protocol_e::IPV6_MC]);
        set_disable_mc_tunnel_decap(attribs, !m_protocols[(size_t)la_l3_protocol_e::MC_TUNNEL_DECAP]);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::set_active(bool active)
{
    if (active == m_is_active) {
        return LA_STATUS_SUCCESS;
    }

    npl_base_l3_lp_attributes_t attribs = m_l3_lp_attributes;

    la_status status = do_set_active(active, attribs);
    return_on_error(status);

    status = update_l3_lp_attributes(attribs);
    return_on_error(status);

    set_l3_lp_attributes(attribs);

    // disable egress mode
    auto slices = m_ifg_use_count->get_slices();

    for (la_slice_id_t slice_idx : slices) {
        slice_data& slice_data(m_slice_data[slice_idx]);
        npl_l3_dlp_table_value_t value(slice_data.l3_dlp_table_entry->value());
        npl_l3_dlp_attributes_t& attrib(value.payloads.l3_dlp_attributes);

        attrib.disabled = !active;
        status = slice_data.l3_dlp_table_entry->update(value);
        return_on_error(status);
    }

    m_is_active = active;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::set_port_egress_mode(bool active)
{
    la_status status;
    auto slices = m_ifg_use_count->get_slices();

    for (la_slice_id_t slice_idx : slices) {
        slice_data& slice_data(m_slice_data[slice_idx]);
        npl_l3_dlp_table_value_t value(slice_data.l3_dlp_table_entry->value());
        npl_l3_dlp_attributes_t& attrib(value.payloads.l3_dlp_attributes);

        attrib.disabled = !active;
        status = slice_data.l3_dlp_table_entry->update(value);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::set_egress_qos_profile(la_egress_qos_profile* egress_qos_profile)
{
    if (egress_qos_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(egress_qos_profile, m_device)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // If nothing to update
    if (m_egress_qos_profile.get() == egress_qos_profile) {
        return LA_STATUS_SUCCESS;
    }

    auto egress_qos_profile_impl = static_cast<la_egress_qos_profile_impl*>(egress_qos_profile);
    auto old_profile = m_egress_qos_profile;

    // Tell the policy about all our IFGs (triggers TCAM programming)
    la_status status = add_current_ifgs(this, egress_qos_profile_impl);
    return_on_error(status);

    m_device->add_ifg_dependency(m_parent, egress_qos_profile_impl);
    m_device->add_object_dependency(egress_qos_profile, m_parent);

    m_egress_qos_profile = m_device->get_sptr(egress_qos_profile_impl);

    // Update device
    auto slices = m_ifg_use_count->get_slices();

    for (auto slice : slices) {
        status = configure_l3_dlp_table(slice);
        return_on_error(status);
    }

    m_device->remove_ifg_dependency(m_parent, old_profile);
    m_device->remove_object_dependency(old_profile, m_parent);

    status = remove_current_ifgs(this, old_profile.get());
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::set_egress_vlan_tag(la_vlan_tag_t tag1, la_vlan_tag_t tag2)
{
    auto slices = m_ifg_use_count->get_slices();

    for (la_slice_id_t slice_idx : slices) {
        slice_data& slice_data(m_slice_data[slice_idx]);
        la_status status = do_set_egress_vlan_tag(tag1, tag2, slice_data.l3_dlp_table_entry);
        return_on_error(status);
    }

    m_tag1 = tag1;
    m_tag2 = tag2;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::configure_l3_dlp_attributes(la_slice_id_t slice_idx)
{
    la_status status;
    la_object::object_type_e type = m_parent->type();

    // Port specific code
    switch (type) {
    case la_object::object_type_e::L3_AC_PORT: {
        status = configure_l3_dlp_table(slice_idx);
    } break;
    case la_object::object_type_e::SVI_PORT: {
        status = configure_l3_dlp_table(slice_idx);
    } break;
    case la_object::object_type_e::GRE_PORT: {
        la_slice_pair_id_t pair_idx = slice_idx / 2;
        auto gre_port = m_parent.weak_ptr_static_cast<la_gre_port_impl>();
        status = gre_port->configure_ip_tunnel_dlp_table(pair_idx);
    } break;
    default:
        status = LA_STATUS_EUNKNOWN;
    }

    return status;
}

la_status
la_vrf_port_common_akpg::configure_l3_dlp_table(la_slice_id_t slice_idx)
{
    if ((m_parent->type() == la_object::object_type_e::IP_OVER_IP_TUNNEL_PORT)
        || (m_parent->type() == la_object::object_type_e::GUE_PORT)) {
        return LA_STATUS_SUCCESS;
    }

    la_slice_pair_id_t pair_idx = slice_idx / 2;

    if (m_parent->type() == la_object::object_type_e::GRE_PORT) {
        auto gre_port = m_parent.weak_ptr_static_cast<la_gre_port_impl>();
        return (gre_port->configure_ip_tunnel_dlp_table(pair_idx));
    }
    uint64_t index;

    const auto& table(m_device->m_tables.l3_dlp_table[slice_idx]);
    npl_l3_dlp_table_key_t key = get_l3_dlp_table_key();
    npl_l3_dlp_table_value_t value;
    npl_l3_dlp_attributes_t& attrib(value.payloads.l3_dlp_attributes);

    attrib.disabled = 0;
    attrib.svi_dhcp_snooping = m_egress_dhcp_snooping;
    la_status status = get_l3_lp_qos_and_attributes(pair_idx, attrib.l3_dlp_qos_and_attributes);
    return_on_error(status);

    bool is_recycle_ac = false;
    if (m_parent->type() == la_object::object_type_e::L3_AC_PORT) {
        const la_l3_ac_port_impl_wcptr parent = m_parent.weak_ptr_static_cast<la_l3_ac_port_impl>();
        is_recycle_ac = silicon_one::is_recycle_ac(parent);
    }

    status = silicon_one::populate_rcy_data(m_device, m_egress_mirror_cmd, is_recycle_ac, attrib.tx_to_rx_rcy_data);
    return_on_error(status);

    if (m_filter_group) {
        attrib.l3_dlp_qos_and_attributes.l3_dlp_info.dlp_attributes.lp_profile = m_filter_group->get_id();
    } else {
        attrib.l3_dlp_qos_and_attributes.l3_dlp_info.dlp_attributes.lp_profile = 0;
    }

    // The encap data is a union - clear all the union fields and then
    // initialize only the svi fields
    memset(&attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap, 0, sizeof(attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap));
    attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vlan_and_sa_lsb_encap.vlan_id = m_tag1.tci.fields.vid;
    attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vlan_and_sa_lsb_encap.tpid_sa_lsb.tpid
        = (is_vlan_tag_eq(m_tag1, LA_VLAN_TAG_UNTAGGED)) ? 0x8100 : m_tag1.tpid;

    la_mac_addr_t smac;
    if (m_is_recycle_ac) {
        la_mac_addr_t recycle_ac_smac;
        recycle_ac_smac.flat = RECYCLE_AC_SMAC;
        smac = recycle_ac_smac;
    } else {
        smac = m_mac_addr;
    }

    status = m_device->m_mac_addr_manager->get_index(smac, index);
    return_on_error(status);

    attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vlan_and_sa_lsb_encap.tpid_sa_lsb.sa_lsb = mac_address_manager::get_lsbits(smac);
    attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.sa_prefix_index = index;

    attrib.nh_ene_macro_code
        = (is_vlan_tag_eq(m_tag1, LA_VLAN_TAG_UNTAGGED))
              ? NPL_NH_ENE_MACRO_ETH
              : (is_vlan_tag_eq(m_tag2, LA_VLAN_TAG_UNTAGGED) ? NPL_NH_ENE_MACRO_ETH_VLAN : NPL_NH_ENE_MACRO_ETH_VLAN_VLAN);
    attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vid2_or_flood_rcy_sm_vlans.flood_rcy_sm_vlans.vid1 = 0;
    attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vid2_or_flood_rcy_sm_vlans.flood_rcy_sm_vlans.vid2 = m_tag2.tci.fields.vid;

    if (m_parent->type() == la_object::object_type_e::SVI_PORT) {
        la_vlan_id_t out_vid1 = LA_VLAN_ID_INVALID, out_vid2 = LA_VLAN_ID_INVALID;
        status = get_rcy_sm_vlans(out_vid1, out_vid2);

        attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vid2_or_flood_rcy_sm_vlans.flood_rcy_sm_vlans.vid1 = out_vid1;
        attrib.l3_dlp_encap_or_te_labels.l3_dlp_encap.vid2_or_flood_rcy_sm_vlans.flood_rcy_sm_vlans.vid2 = out_vid2;
    }

    if (m_slice_data[slice_idx].l3_dlp_table_entry != nullptr) {
        status = m_slice_data[slice_idx].l3_dlp_table_entry->update(value);
    } else {
        status = table->insert(key, value, m_slice_data[slice_idx].l3_dlp_table_entry);
    }

    return_on_error(status);

    attribute_management_details amd;
    amd.op = attribute_management_op::L3_PORT_ATTR_CHANGED;
    amd.l3_port = m_parent.get();
    la_amd_undo_callback_funct_t undo = [this](attribute_management_details amd) { return amd; };
    status = m_device->notify_attribute_changed(m_parent.get(), amd, undo);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::teardown_l3_dlp_table(la_slice_id_t slice_idx)
{
    if ((m_parent->type() == la_object::object_type_e::IP_OVER_IP_TUNNEL_PORT)
        || (m_parent->type() == la_object::object_type_e::GUE_PORT)) {
        return LA_STATUS_SUCCESS;
    }

    const auto& table(m_device->m_tables.l3_dlp_table[slice_idx]);
    npl_l3_dlp_table_key_t key = m_slice_data[slice_idx].l3_dlp_table_entry->key();

    la_status status = table->erase(key);
    return_on_error(status);

    m_slice_data[slice_idx].l3_dlp_table_entry = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::configure_egress_drop_counter_offset(size_t offset)
{
    m_egress_acl_drop_offset = offset;

    // Update device
    auto slices = m_ifg_use_count->get_slices();
    for (auto slice : slices) {
        la_status status = configure_l3_dlp_table(slice);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned)
{
    if (mirror_cmd != nullptr && !of_same_device(mirror_cmd, m_device)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    m_egress_mirror_cmd = m_device->get_sptr(mirror_cmd);
    m_egress_port_mirror_type = is_acl_conditioned ? NPL_PORT_MIRROR_TYPE_CONDITIONED : NPL_PORT_MIRROR_TYPE_UN_CONDITIONED;

    auto slices = m_ifg_use_count->get_slices();
    for (auto slice : slices) {
        la_status status = configure_l3_dlp_table(slice);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::configure_ingress_counter()
{
    for (auto slice_idx : m_ifg_use_count->get_slices()) {
        la_status status = configure_l3_dlp_table(slice_idx);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::set_ecn_remark_enabled(bool enabled)
{
    if (m_enable_ecn_remark == enabled) {
        return LA_STATUS_SUCCESS;
    }

    m_enable_ecn_remark = enabled;

    // Update device
    auto slices = m_ifg_use_count->get_slices();
    for (auto slice : slices) {
        la_status status = configure_l3_dlp_table(slice);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::set_ecn_counting_enabled(bool enabled)
{
    if (m_enable_ecn_counting == enabled) {
        return LA_STATUS_SUCCESS;
    }

    m_enable_ecn_counting = enabled;

    // Update device
    auto slices = m_ifg_use_count->get_slices();
    for (auto slice : slices) {
        la_status status = configure_l3_dlp_table(slice);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::add_ip_host(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                     la_port_host<la_ipv4_addr_t>& port_hosts,
                                     la_ipv4_addr_t ip_addr,
                                     la_mac_addr_t mac_addr,
                                     la_class_id_t class_id)
{
    return add_ip_host_with_class_id(table, port_hosts, ip_addr, mac_addr, class_id);
}

la_status
la_vrf_port_common_akpg::add_ip_host(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                     la_port_host<la_ipv6_addr_t>& port_hosts,
                                     la_ipv6_addr_t ip_addr,
                                     la_mac_addr_t mac_addr,
                                     la_class_id_t class_id)
{
    return add_ip_host_with_class_id(table, port_hosts, ip_addr, mac_addr, class_id);
}

la_status
la_vrf_port_common_akpg::get_mac_termination_table_key(la_switch_gid_t sw_id, npl_mac_termination_em_table_key_t& out_key) const
{
    uint64_t prefix;
    la_status status = m_device->m_mac_addr_manager->get_prefix(m_mac_addr, prefix);
    return_on_error(status);

    out_key.relay_id.id = sw_id;
    out_key.ethernet_header_da_17_0_ = m_mac_addr.flat & ((1ULL << 18) - 1);
    out_key.da_prefix = prefix;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::update_urpf_mode(la_l3_port::urpf_mode_e urpf_mode)
{
    npl_base_l3_lp_attributes_t attribs = m_l3_lp_attributes;
    attribs.uc_rpf_mode = la_2_npl_urpf_mode(urpf_mode);

    la_status status = update_l3_lp_attributes(attribs);
    return_on_error(status);

    m_l3_lp_attributes.uc_rpf_mode = attribs.uc_rpf_mode;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::get_urpf_mode(la_l3_port::urpf_mode_e& out_urpf_mode) const
{
    out_urpf_mode = npl_2_la_urpf_mode(m_l3_lp_attributes.uc_rpf_mode);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_port_common_akpg::set_urpf_mode(la_l3_port::urpf_mode_e urpf_mode)
{
    la_l3_port::urpf_mode_e curr_mode = npl_2_la_urpf_mode(m_l3_lp_attributes.uc_rpf_mode);
    if (curr_mode == urpf_mode) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = update_urpf_mode(urpf_mode);

    return status;
}

la_status
la_vrf_port_common_akpg::set_egress_dhcp_snooping_enabled(bool enabled)
{
    if (m_egress_dhcp_snooping == enabled) {
        return LA_STATUS_SUCCESS;
    }

    m_egress_dhcp_snooping = enabled;

    // Update device
    auto slices = m_ifg_use_count->get_slices();
    for (auto slice : slices) {
        la_status status = configure_l3_dlp_table(slice);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

npl_l3_dlp_table_key_t
la_vrf_port_common_akpg::get_l3_dlp_table_key()
{
    npl_l3_dlp_table_key_t key = {};
    key.l3_dlp_id_lsbs = get_l3_lp_lsb(m_gid);
    key.l3_dlp_id_msbs = get_l3_lp_msb(m_gid);
    return key;
}

la_status
la_vrf_port_common_akpg::set_filter_group(const la_filter_group_impl_wcptr& filter_group)
{
    // Update SLP profile
    npl_l3_lp_additional_attributes_t additional_attributes(m_l3_lp_additional_attributes);

    additional_attributes.lp_profile = filter_group->get_id();

    la_status status = update_l3_lp_attributes(m_l3_lp_attributes, additional_attributes);
    return_on_error(status);

    m_l3_lp_additional_attributes.lp_profile = additional_attributes.lp_profile;

    // Update DLP profile
    m_filter_group = filter_group;
    auto slices = m_ifg_use_count->get_slices();
    for (auto slice : slices) {
        la_status status = configure_l3_dlp_table(slice);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
