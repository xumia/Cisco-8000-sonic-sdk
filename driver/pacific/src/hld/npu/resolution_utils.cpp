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

#include "resolution_utils.h"
#include "api/npu/la_switch.h"
#include "common/bit_vector.h"
#include "common/defines.h"
#include "hld_utils.h"
#include "la_asbr_lsp_impl.h"
#include "la_destination_pe_impl.h"
#include "la_forus_destination_impl.h"
#include "la_ip_tunnel_destination_impl.h"
#include "la_l3_ac_port_impl.h"
#include "la_mpls_label_destination_impl.h"
#include "la_te_tunnel_impl.h"
#include "nplapi/npl_constants.h"
#include "npu/la_ecmp_group_impl.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_ip_multicast_group_base.h"
#include "npu/la_l2_multicast_group_base.h"
#include "npu/la_l2_protection_group_pacific.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_l3_fec_impl.h"
#include "npu/la_l3_protection_group_impl.h"
#include "npu/la_mpls_multicast_group_impl.h"
#include "npu/la_mpls_nhlfe_impl.h"
#include "npu/la_mpls_vpn_encap_impl.h"
#include "npu/la_next_hop_base.h"
#include "npu/la_prefix_object_base.h"
#include "npu/la_protection_monitor_impl.h"
#include "npu/la_svi_port_base.h"
#include "npu/la_vxlan_next_hop_base.h"
#include "system/la_device_impl.h"
#include "system/la_l2_punt_destination_impl.h"
#include "system/la_npu_host_destination_impl.h"
#include "system/la_npu_host_port_base.h"
#include "system/la_punt_inject_port_base.h"
#include "system/la_spa_port_base.h"
#include "system/la_system_port_base.h"
#include "tm/la_voq_set_impl.h"

namespace silicon_one
{

// TODO: this code segment is temporary till we remove all raw pointers functions
template <class T>
static weak_ptr_unsafe<T>
la_object_raw_to_weak_ptr(T* ptr)
{
    if (!ptr)
        return nullptr;
    return (static_cast<const la_device_impl*>(ptr->get_device()))->get_sptr<T>(ptr);
}
// TODO: end of code segment to remove

static la_status
get_l2_destination_raw(const la_l3_port* l3_port, la_mac_addr_t mac_addr, const la_l2_destination*& out_l2_destination)
{
    la_object::object_type_e l3_port_type = l3_port->type();

    switch (l3_port_type) {
    case la_object::object_type_e::SVI_PORT: {
        la_l2_destination* l2_dest = nullptr;
        const la_svi_port_base* svi = static_cast<const la_svi_port_base*>(l3_port);
        const la_switch* sw = nullptr;

        la_status status = svi->get_switch(sw);
        return_on_error(status);

        la_mac_age_info_t entry_info;
        status = sw->get_mac_entry(mac_addr, l2_dest, entry_info);
        return_on_error(status);

        out_l2_destination = l2_dest;

        return LA_STATUS_SUCCESS;
    }

    break;
    case la_object::object_type_e::L3_AC_PORT: {
        const la_l3_ac_port_impl* ac_port = static_cast<const la_l3_ac_port_impl*>(l3_port);
        const la_ethernet_port* ep = ac_port->get_ethernet_port();

        out_l2_destination = ep;

        return LA_STATUS_SUCCESS;
    }

    break;

    default:
        return LA_STATUS_EUNKNOWN;
    }
}

la_status
get_l2_destination(const la_l3_port_wcptr& l3_port, la_mac_addr_t mac_addr, la_l2_destination_wcptr& out_l2_destination)
{
    const la_l2_destination* out_l2_destination_raw = out_l2_destination.get();
    la_status status = get_l2_destination_raw(l3_port.get(), mac_addr, out_l2_destination_raw);
    return_on_error(status);
    out_l2_destination = la_object_raw_to_weak_ptr(out_l2_destination_raw);
    return status;
}

la_status
get_dsp_or_dspa(const la_device_impl_wptr& device,
                const la_l2_destination_wcptr& l2_dest,
                la_l2_destination_gid_t& out_gid,
                bool& out_is_aggregate)
{
    la_object::object_type_e l2_dest_type = l2_dest->type();
    la_l2_destination_gid_t dest_gid;

    switch (l2_dest_type) {

    case la_object::object_type_e::L2_SERVICE_PORT: {
        auto srvp = l2_dest.weak_ptr_static_cast<const la_l2_service_port_base>();

        la_l2_service_port_base::port_type_e port_type = srvp->get_port_type();
        if (port_type != la_l2_service_port::port_type_e::AC) {
            return LA_STATUS_ENOTIMPLEMENTED;
        }

        const la_ethernet_port_base_wcptr ep = srvp->get_ethernet_port();
        out_is_aggregate = ep->is_aggregate();
        dest_gid = device->get_l2_destination_gid(ep);
    } break;

    case la_object::object_type_e::ETHERNET_PORT: {
        auto ep = l2_dest.weak_ptr_static_cast<const la_ethernet_port_base>();
        out_is_aggregate = ep->is_aggregate();
        dest_gid = device->get_l2_destination_gid(ep);
    } break;

    default:

        return LA_STATUS_ENOTIMPLEMENTED;
    }

    out_gid = dest_gid;
    return LA_STATUS_SUCCESS;
}

bool
is_l3_lpm_destination(lpm_destination_id lpm_dest)
{
    // Check if the prefix of the lpm_dest.val == L3_DLP_SUBNET_PREFIX. All prefixes except L3_DLP_SUBNET represent an
    // l3_destination object
    if ((lpm_dest.val >> (NPL_LPM_COMPRESSED_DESTINATION_LEN - NPL_LPM_COMPRESSED_DESTINATION_L3_DLP_SUBNET_PREFIX_LEN))
        == NPL_LPM_COMPRESSED_DESTINATION_L3_DLP_SUBNET_PREFIX) {
        return false;
    }

    return true;
}

const la_system_port_base_wcptr get_actual_dsp(const la_system_port_wcptr& dsp) // PACKET-DMA-WA
{
    if (dsp == nullptr) {
        return nullptr;
    }

    auto idsp = dsp.weak_ptr_static_cast<const la_system_port_base>();
    if (idsp->get_port_type() != la_system_port_base::port_type_e::PCI) {
        return idsp;
    }

    return idsp->get_punt_recycle_port();
}

la_slice_id_t
get_actual_dsp_slice(const la_system_port_wcptr& dsp)
{
    if (dsp == nullptr) {
        return -1;
    }

    auto adsp = get_actual_dsp(dsp);
    return adsp->get_slice();
}

destination_id
get_destination_id(const la_object* dest_object, resolution_step_e prev_step)
{
    la_object::object_type_e dest_type = dest_object->type();

    switch (dest_type) {
    // L2 destinations

    case la_object::object_type_e::L2_MULTICAST_GROUP: {
        const la_l2_multicast_group_base* mcgi = static_cast<const la_l2_multicast_group_base*>(dest_object);
        la_multicast_group_gid_t gid = mcgi->get_gid();

        return destination_id(NPL_DESTINATION_MASK_MC | gid);
    }

    case la_object::object_type_e::L2_SERVICE_PORT: {
        const la_l2_service_port_base* l2_service_port_base = static_cast<const la_l2_service_port_base*>(dest_object);
        return l2_service_port_base->get_destination_id();
    }

    case la_object::object_type_e::SYSTEM_PORT: {
        auto la_dev = static_cast<const la_device_impl*>(dest_object->get_device());
        auto sp = la_dev->get_sptr<const la_system_port_base>(dest_object);
        // TODO - this should call la_system_port_base->get_destination_id, that should
        // return the la_system_port_base->get_destination_id(prev_step)
        auto actual_dsp = get_actual_dsp(sp);
        auto sp_gid = actual_dsp->get_gid();
        return destination_id(NPL_DESTINATION_MASK_DSP | sp_gid);
    }

    case la_object::object_type_e::ETHERNET_PORT: {
        const la_ethernet_port_base* ep = static_cast<const la_ethernet_port_base*>(dest_object);
        const la_system_port_base* sp = static_cast<const la_system_port_base*>(ep->get_system_port());

        if (sp != nullptr) {
            return get_destination_id(sp, prev_step);
        } else {
            const la_spa_port_base* spa = static_cast<const la_spa_port_base*>(ep->get_spa_port());
            if (spa != nullptr) {
                // TODO - this should call la_spa_port_base->get_destination_id, that should
                // return the la_spa_port_base->get_destination_id(prev_step)
                la_spa_port_gid_t spa_gid = spa->get_gid();

                return destination_id(NPL_DESTINATION_MASK_DSPA | spa_gid);
            }
        }

        return DESTINATION_ID_INVALID;
    }

    case la_object::object_type_e::L2_PROTECTION_GROUP: {
        const la_l2_protection_group_base* l2_protection_group = static_cast<const la_l2_protection_group_base*>(dest_object);
        la_l2_port_gid_t l2_protection_group_gid = l2_protection_group->get_gid(); // TODO - this should call
        // la_l2_protection_impl->get_destination_id(prev_step), that
        // should return the id per step

        return destination_id(NPL_DESTINATION_MASK_L2_DLP | l2_protection_group_gid);
    }

    case la_object::object_type_e::VOQ_SET: {
        const la_voq_set_impl* voq_set = static_cast<const la_voq_set_impl*>(dest_object);
        la_voq_gid_t voq_gid = voq_set->get_base_voq_id();
        return destination_id(NPL_DESTINATION_MASK_BVN | voq_gid);
    }

    // L3 destinations

    case la_object::object_type_e::FORUS_DESTINATION: {
        const la_forus_destination_impl* forus_dest = static_cast<const la_forus_destination_impl*>(dest_object);
        auto bincode = forus_dest->get_bincode();
        return destination_id(NPL_DESTINATION_MASK_LPTS | (1 << 0) | (bincode << 1));
    }

    case la_object::object_type_e::L3_AC_PORT: {
        const la_l3_ac_port_impl* port = static_cast<const la_l3_ac_port_impl*>(dest_object);
        if (!port->is_lp_queueing_enabled()) {
            return DESTINATION_ID_INVALID;
        }
        const la_ethernet_port_base* ep = static_cast<const la_ethernet_port_base*>(port->get_ethernet_port());
        if (ep->is_aggregate()) {
            return get_destination_id(ep, RESOLUTION_STEP_STAGE3_LB);
        } else {
            la_voq_set* vs = port->get_voq_set();
            if (vs == nullptr) {
                return DESTINATION_ID_INVALID;
            }
            return get_destination_id(port->get_voq_set(), RESOLUTION_STEP_STAGE3_LB);
        }
    }

    case la_object::object_type_e::IP_MULTICAST_GROUP: {
        const la_ip_multicast_group_base* mcgi = static_cast<const la_ip_multicast_group_base*>(dest_object);
        la_multicast_group_gid_t gid = mcgi->get_gid();

        return destination_id(NPL_DESTINATION_MASK_MC | gid);
    }

    case la_object::object_type_e::MPLS_MULTICAST_GROUP: {
        const la_mpls_multicast_group_impl* mcgm = static_cast<const la_mpls_multicast_group_impl*>(dest_object);
        la_multicast_group_gid_t gid = mcgm->get_gid();

        return destination_id(NPL_DESTINATION_MASK_MC | gid);
    }

    case la_object::object_type_e::L3_PROTECTION_GROUP: {
        const la_l3_protection_group_impl* l3_protection_group = static_cast<const la_l3_protection_group_impl*>(dest_object);
        return l3_protection_group->get_destination_id(prev_step);
    }

    case la_object::object_type_e::FEC: {
        const la_l3_fec_impl* fec = static_cast<const la_l3_fec_impl*>(dest_object);

        return fec->get_destination_id(prev_step);
    }

    case la_object::object_type_e::ECMP_GROUP: {
        const la_ecmp_group_impl* ecmp_group = static_cast<const la_ecmp_group_impl*>(dest_object);

        return ecmp_group->get_destination_id(prev_step);
    }

    case la_object::object_type_e::TE_TUNNEL: {
        const la_te_tunnel_impl* te_tunnel = static_cast<const la_te_tunnel_impl*>(dest_object);
        return te_tunnel->get_destination_id(prev_step);
    }

    case la_object::object_type_e::NEXT_HOP: {
        const la_next_hop_base* next_hop = static_cast<const la_next_hop_base*>(dest_object);

        return next_hop->get_destination_id(prev_step);
    }

    case la_object::object_type_e::VXLAN_NEXT_HOP: {
        const la_vxlan_next_hop_base* vxlan_next_hop = static_cast<const la_vxlan_next_hop_base*>(dest_object);

        return vxlan_next_hop->get_destination_id(prev_step);
    }

    case la_object::object_type_e::MPLS_NHLFE: {
        const la_mpls_nhlfe_impl* nhlfe = static_cast<const la_mpls_nhlfe_impl*>(dest_object);

        return nhlfe->get_destination_id(prev_step);
    }

    case la_object::object_type_e::PREFIX_OBJECT: {
        const la_prefix_object_base* pfx = static_cast<const la_prefix_object_base*>(dest_object);
        return pfx->get_destination_id(prev_step);
    }

    case la_object::object_type_e::DESTINATION_PE: {
        const la_destination_pe_impl* dpe = static_cast<const la_destination_pe_impl*>(dest_object);
        return dpe->get_destination_id(prev_step);
    }

    case la_object::object_type_e::IP_TUNNEL_DESTINATION: {
        const la_ip_tunnel_destination_impl* ip_tunnel = static_cast<const la_ip_tunnel_destination_impl*>(dest_object);
        return ip_tunnel->get_destination_id(prev_step);
    }

    case la_object::object_type_e::ASBR_LSP: {
        const la_asbr_lsp_impl* asbr_lsp = static_cast<const la_asbr_lsp_impl*>(dest_object);
        return asbr_lsp->get_destination_id(prev_step);
    }

    case la_object::object_type_e::L2_PUNT_DESTINATION: {
        const la_l2_punt_destination_impl* l2_punt_dest = static_cast<const la_l2_punt_destination_impl*>(dest_object);
        return l2_punt_dest->get_destination_id(prev_step);
    }

    case la_object::object_type_e::NPU_HOST_DESTINATION: {
        const auto npu_host_destination = static_cast<const la_npu_host_destination_impl*>(dest_object);

        const la_npu_host_port_base* npu_host_port = npu_host_destination->get_npu_host_port();
        if (npu_host_port == nullptr) {
            return DESTINATION_ID_INVALID;
        }

        const la_system_port* sp = npu_host_port->get_system_port();
        return get_destination_id(sp, prev_step);
    }

    case la_object::object_type_e::MPLS_VPN_ENCAP: {
        const auto vpn_encap = static_cast<const la_mpls_vpn_encap_impl*>(dest_object);
        return vpn_encap->get_destination_id(prev_step);
    }

    default:
        return DESTINATION_ID_INVALID;
    }
}

destination_id
get_destination_id(const la_object_wcptr& dest_object, resolution_step_e prev_step)
{
    return get_destination_id(dest_object.get(), prev_step);
}

la_status
get_l3_port(const la_l3_destination* dest_object, la_l3_port*& out_l3_port)
{

    la_object::object_type_e dest_type = dest_object->type();
    la_status status;

    switch (dest_type) {
    case la_object::object_type_e::NEXT_HOP: {
        const la_next_hop_base* next_hop = static_cast<const la_next_hop_base*>(dest_object);

        return next_hop->get_router_port(out_l3_port);
    }

    case la_object::object_type_e::VXLAN_NEXT_HOP: {
        const la_vxlan_next_hop_base* vxlan_next_hop = static_cast<const la_vxlan_next_hop_base*>(dest_object);

        return vxlan_next_hop->get_router_port(out_l3_port);
    }

    case la_object::object_type_e::FEC: {
        const la_l3_fec_impl* fec = static_cast<const la_l3_fec_impl*>(dest_object);
        la_l3_destination* dest = fec->get_destination();
        return get_l3_port(dest, out_l3_port);
    }

    // Except NEXT_HOP and FEC->NEXT_HOP other destination types like FEC->ECMP
    // FEC->PREFIX_NEXT_HOP etc. are not currently implemented.
    default:
        return LA_STATUS_ENOTIMPLEMENTED;
    }
}

la_status
get_l3_port(const la_l3_destination_wcptr& dest_object, la_l3_port_wptr& out_l3_port)
{
    la_l3_port* out_l3_port_raw = out_l3_port.get();
    la_status status = get_l3_port(dest_object.get(), out_l3_port_raw);
    return_on_error(status);
    out_l3_port = la_object_raw_to_weak_ptr(out_l3_port_raw);
    return status;
}

lpm_destination_id
get_lpm_destination_id(const la_object_wcptr& dest_object, resolution_step_e prev_step)
{
    la_object::object_type_e dest_type = dest_object->type();

    switch (dest_type) {
    case la_object::object_type_e::FEC: {
        const auto& fec = dest_object.weak_ptr_static_cast<const la_l3_fec_impl>();

        return fec->get_lpm_destination_id(prev_step);
    }

    case la_object::object_type_e::FORUS_DESTINATION: {
        const auto& forus = dest_object.weak_ptr_static_cast<const la_forus_destination_impl>();

        return forus->get_lpm_destination_id(prev_step);
    }

    case la_object::object_type_e::ECMP_GROUP: {
        const auto& ecmp_group = dest_object.weak_ptr_static_cast<const la_ecmp_group_impl>();

        return ecmp_group->get_lpm_destination_id(prev_step);
    }

    case la_object::object_type_e::NEXT_HOP: {
        const auto& next_hop = dest_object.weak_ptr_static_cast<const la_next_hop_base>();
        return next_hop->get_lpm_destination_id(prev_step);
    }

    case la_object::object_type_e::VXLAN_NEXT_HOP: {
        const auto& vxlan_next_hop = dest_object.weak_ptr_static_cast<const la_vxlan_next_hop_base>();
        return vxlan_next_hop->get_lpm_destination_id(prev_step);
    }

    case la_object::object_type_e::DESTINATION_PE: {
        const auto& dpe = dest_object.weak_ptr_static_cast<const la_destination_pe_impl>();
        return dpe->get_lpm_destination_id(prev_step);
    }

    case la_object::object_type_e::PREFIX_OBJECT: {
        const auto& pfx = dest_object.weak_ptr_static_cast<const la_prefix_object_base>();
        return pfx->get_lpm_destination_id(prev_step);
    }

    case la_object::object_type_e::MPLS_VPN_ENCAP: {
        const auto& vpn_encap = dest_object.weak_ptr_static_cast<const la_mpls_vpn_encap_impl>();
        return vpn_encap->get_lpm_destination_id(prev_step);
    }

    case la_object::object_type_e::IP_TUNNEL_DESTINATION: {
        const auto& ip_tunnel = dest_object.weak_ptr_static_cast<const la_ip_tunnel_destination_impl>();
        return ip_tunnel->get_lpm_destination_id(prev_step);
    }

    case la_object::object_type_e::MPLS_LABEL_DESTINATION: {
        return LPM_DESTINATION_ID_INVALID;
    }

    case la_object::object_type_e::L2_SERVICE_PORT: {
        const auto& l2_port = dest_object.weak_ptr_static_cast<const la_l2_service_port_base>();
        return l2_port->get_lpm_destination_id(prev_step);
    }

    default:
        return LPM_DESTINATION_ID_INVALID;
    }
}

static la_status
instantiate_resolution_object_core(const la_object* obj, resolution_step_e prev_step)
{
    la_object::object_type_e obj_type = obj->type();

    switch (obj_type) {
    case la_object::object_type_e::ECMP_GROUP: {
        la_ecmp_group_impl* ecmp_group = const_cast<la_ecmp_group_impl*>(static_cast<const la_ecmp_group_impl*>(obj));
        la_status status = ecmp_group->instantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::FORUS_DESTINATION: {
        return LA_STATUS_SUCCESS; // forus destination do not have any specific resolution related objects to be instantiated. WE
                                  // still need to handle this here to avoid making special cases for these destinations
    }

    case la_object::object_type_e::MPLS_MULTICAST_GROUP: {
        return LA_STATUS_SUCCESS; // forus destination do not have any specific resolution related objects to be instantiated. WE
                                  // still need to handle this here to avoid making special cases for these destinations
    }

    case la_object::object_type_e::FEC: {
        return LA_STATUS_SUCCESS; // TODO - this should call the fec instantiate that should immediately succeed.
    }

    case la_object::object_type_e::NEXT_HOP: {
        la_next_hop_base* next_hop = const_cast<la_next_hop_base*>(static_cast<const la_next_hop_base*>(obj));
        la_status status = next_hop->instantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::VXLAN_NEXT_HOP: {
        la_vxlan_next_hop_base* vxlan_next_hop
            = const_cast<la_vxlan_next_hop_base*>(static_cast<const la_vxlan_next_hop_base*>(obj));
        la_status status = vxlan_next_hop->instantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::MPLS_NHLFE: {
        la_mpls_nhlfe_impl* nhlfe = const_cast<la_mpls_nhlfe_impl*>(static_cast<const la_mpls_nhlfe_impl*>(obj));
        la_status status = nhlfe->instantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::MPLS_LABEL_DESTINATION: {
        la_mpls_label_destination_impl* label_dest
            = const_cast<la_mpls_label_destination_impl*>(static_cast<const la_mpls_label_destination_impl*>(obj));
        la_status status = label_dest->instantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::PREFIX_OBJECT: {
        la_prefix_object_base* pfx = const_cast<la_prefix_object_base*>(static_cast<const la_prefix_object_base*>(obj));
        la_status status = pfx->instantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::DESTINATION_PE: {
        la_destination_pe_impl* dpe = const_cast<la_destination_pe_impl*>(static_cast<const la_destination_pe_impl*>(obj));
        la_status status = dpe->instantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::IP_TUNNEL_DESTINATION: {
        la_ip_tunnel_destination_impl* ip_tunnel
            = const_cast<la_ip_tunnel_destination_impl*>(static_cast<const la_ip_tunnel_destination_impl*>(obj));
        la_status status = ip_tunnel->instantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::ASBR_LSP: {
        la_asbr_lsp_impl* asbr_lsp = const_cast<la_asbr_lsp_impl*>(static_cast<const la_asbr_lsp_impl*>(obj));
        la_status status = asbr_lsp->instantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::TE_TUNNEL: {
        la_te_tunnel_impl* te_tunnel = const_cast<la_te_tunnel_impl*>(static_cast<const la_te_tunnel_impl*>(obj));
        la_status status = te_tunnel->instantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::PROTECTION_MONITOR: {
        la_protection_monitor_impl* protection_monitor
            = const_cast<la_protection_monitor_impl*>(static_cast<const la_protection_monitor_impl*>(obj));
        la_status status = protection_monitor->instantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::L3_PROTECTION_GROUP: {
        la_l3_protection_group_impl* l3_protection_group
            = const_cast<la_l3_protection_group_impl*>(static_cast<const la_l3_protection_group_impl*>(obj));
        la_status status = l3_protection_group->instantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::MPLS_VPN_ENCAP: {
        return LA_STATUS_SUCCESS;
    }

    case la_object::object_type_e::L2_SERVICE_PORT: {
        return LA_STATUS_SUCCESS;
    }

    case la_object::object_type_e::MULTICAST_PROTECTION_GROUP: {
        return LA_STATUS_SUCCESS; // Multicast protection group is a entirely egress construct, so no instantiation required
    }

    default: {
        return LA_STATUS_ENOTIMPLEMENTED;
    }
    }
}

la_status
instantiate_resolution_object(const la_object* obj, resolution_step_e prev_step)
{
    la_status status = instantiate_resolution_object_core(obj, prev_step);

    return (status == LA_STATUS_ERESOURCE) ? LA_STATUS_ESIZE : status;
}

la_status
instantiate_resolution_object(const la_object_wcptr& obj, resolution_step_e prev_step)
{
    return instantiate_resolution_object(obj.get(), prev_step);
}

static la_status
instantiate_resolution_object_core(const la_object* obj, resolution_step_e prev_step, const la_object* dep_obj)
{
    la_object::object_type_e obj_type = obj->type();

    switch (obj_type) {
    case la_object::object_type_e::ECMP_GROUP: {
        la_ecmp_group_impl* ecmp_group = const_cast<la_ecmp_group_impl*>(static_cast<const la_ecmp_group_impl*>(obj));
        la_status status = ecmp_group->instantiate(prev_step, dep_obj);
        return status;
    }

    default: {
        return instantiate_resolution_object(obj, prev_step);
    }
    }
}

la_status
instantiate_resolution_object(const la_object_wcptr& obj, resolution_step_e prev_step, const la_object_wcptr& dep_obj)
{
    la_status status = instantiate_resolution_object_core(obj.get(), prev_step, dep_obj.get());

    return (status == LA_STATUS_ERESOURCE) ? LA_STATUS_ESIZE : status;
}

la_status
instantiate_resolution_object(const la_object_wcptr& obj, resolution_step_e prev_step, const la_object* prev_obj)
{
    la_status status = instantiate_resolution_object_core(obj.get(), prev_step, prev_obj);

    return (status == LA_STATUS_ERESOURCE) ? LA_STATUS_ESIZE : status;
}

la_status
uninstantiate_resolution_object(const la_object* obj, resolution_step_e prev_step)
{
    la_object::object_type_e obj_type = obj->type();

    switch (obj_type) {
    case la_object::object_type_e::ECMP_GROUP: {
        la_ecmp_group_impl* ecmp_group = const_cast<la_ecmp_group_impl*>(static_cast<const la_ecmp_group_impl*>(obj));
        la_status status = ecmp_group->uninstantiate(prev_step);
        return status;
    }
    case la_object::object_type_e::MPLS_NHLFE: {
        la_mpls_nhlfe_impl* nhlfe = const_cast<la_mpls_nhlfe_impl*>(static_cast<const la_mpls_nhlfe_impl*>(obj));
        la_status status = nhlfe->uninstantiate(prev_step);
        return status;
    }
    case la_object::object_type_e::NEXT_HOP: {
        la_next_hop_base* next_hop = const_cast<la_next_hop_base*>(static_cast<const la_next_hop_base*>(obj));
        la_status status = next_hop->uninstantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::VXLAN_NEXT_HOP: {
        la_vxlan_next_hop_base* vxlan_next_hop
            = const_cast<la_vxlan_next_hop_base*>(static_cast<const la_vxlan_next_hop_base*>(obj));
        la_status status = vxlan_next_hop->uninstantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::MPLS_LABEL_DESTINATION: {
        la_mpls_label_destination_impl* label_dest
            = const_cast<la_mpls_label_destination_impl*>(static_cast<const la_mpls_label_destination_impl*>(obj));
        la_status status = label_dest->uninstantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::PREFIX_OBJECT: {
        la_prefix_object_base* pfx = const_cast<la_prefix_object_base*>(static_cast<const la_prefix_object_base*>(obj));
        la_status status = pfx->uninstantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::DESTINATION_PE: {
        la_destination_pe_impl* dpe = const_cast<la_destination_pe_impl*>(static_cast<const la_destination_pe_impl*>(obj));
        la_status status = dpe->uninstantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::IP_TUNNEL_DESTINATION: {
        la_ip_tunnel_destination_impl* ip_tunnel
            = const_cast<la_ip_tunnel_destination_impl*>(static_cast<const la_ip_tunnel_destination_impl*>(obj));
        la_status status = ip_tunnel->uninstantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::ASBR_LSP: {
        la_asbr_lsp_impl* asbr_lsp = const_cast<la_asbr_lsp_impl*>(static_cast<const la_asbr_lsp_impl*>(obj));
        la_status status = asbr_lsp->uninstantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::TE_TUNNEL: {
        la_te_tunnel_impl* te_tunnel = const_cast<la_te_tunnel_impl*>(static_cast<const la_te_tunnel_impl*>(obj));
        la_status status = te_tunnel->uninstantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::PROTECTION_MONITOR: {
        la_protection_monitor_impl* protection_monitor
            = const_cast<la_protection_monitor_impl*>(static_cast<const la_protection_monitor_impl*>(obj));
        la_status status = protection_monitor->uninstantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::L3_PROTECTION_GROUP: {
        la_l3_protection_group_impl* l3_protection_group
            = const_cast<la_l3_protection_group_impl*>(static_cast<const la_l3_protection_group_impl*>(obj));
        la_status status = l3_protection_group->uninstantiate(prev_step);
        return status;
    }

    case la_object::object_type_e::FORUS_DESTINATION: {
        return LA_STATUS_SUCCESS;
    }

    case la_object::object_type_e::MPLS_MULTICAST_GROUP: {
        return LA_STATUS_SUCCESS;
    }

    case la_object::object_type_e::FEC: {
        return LA_STATUS_SUCCESS; // TODO - this should call the fec uninstantiate that should immediately succeed.
    }

    case la_object::object_type_e::MPLS_VPN_ENCAP: {
        return LA_STATUS_SUCCESS;
    }

    case la_object::object_type_e::L2_SERVICE_PORT: {
        return LA_STATUS_SUCCESS;
    }

    case la_object::object_type_e::MULTICAST_PROTECTION_GROUP: {
        return LA_STATUS_SUCCESS;
    }

    default: {
        return LA_STATUS_ENOTIMPLEMENTED;
    }
    }
}

la_status
uninstantiate_resolution_object(const la_object_wcptr& obj, resolution_step_e prev_step)
{
    return uninstantiate_resolution_object(obj.get(), prev_step);
}

destination_type_e
get_destination_type(destination_id dest_id)
{
    if (does_destination_match_prefix(dest_id.val, NPL_DESTINATION_L2_DLP_PREFIX, NPL_DESTINATION_L2_DLP_PREFIX_LEN)) {
        return DESTINATION_TYPE_L2;
    } else if (does_destination_match_prefix(dest_id.val, NPL_DESTINATION_ECMP_PREFIX, NPL_DESTINATION_ECMP_PREFIX_LEN)) {
        return DESTINATION_TYPE_L3;
    } else if (does_destination_match_prefix(
                   dest_id.val, NPL_DESTINATION_STAGE2_ECMP_PREFIX, NPL_DESTINATION_STAGE2_ECMP_PREFIX_LEN)) {
        return DESTINATION_TYPE_L3;
    } else if (does_destination_match_prefix(
                   dest_id.val, NPL_DESTINATION_L3_DLP_SUBNET_PREFIX, NPL_DESTINATION_L3_DLP_SUBNET_PREFIX_LEN)) {
        return DESTINATION_TYPE_L3;
    } else if (does_destination_match_prefix(dest_id.val, NPL_DESTINATION_CE_PTR_PREFIX, NPL_DESTINATION_CE_PTR_PREFIX_LEN)) {
        return DESTINATION_TYPE_L3;
    } else if (does_destination_match_prefix(dest_id.val, NPL_DESTINATION_FEC_PREFIX, NPL_DESTINATION_FEC_PREFIX_LEN)) {
        return DESTINATION_TYPE_L3;
    } else if (does_destination_match_prefix(
                   dest_id.val, NPL_DESTINATION_STAGE2_P_NH_PREFIX, NPL_DESTINATION_STAGE2_P_NH_PREFIX_LEN)) {
        return DESTINATION_TYPE_L3;
    }

    return DESTINATION_TYPE_UNKNOWN;
}

lpm_destination_id
l3_destination_gid_2_lpm_destination_id(la_l3_destination_gid_t dest_id)
{
    lpm_destination_id retval(LA_L3_DESTINATION_GID_INVALID);

    if (does_destination_match_prefix(dest_id, NPL_DESTINATION_ECMP_PREFIX, NPL_DESTINATION_ECMP_PREFIX_LEN)) {
        retval.val = (dest_id & ~NPL_DESTINATION_MASK_ECMP) | NPL_LPM_COMPRESSED_DESTINATION_ECMP_MASK;
    } else if (does_destination_match_prefix(dest_id, NPL_DESTINATION_STAGE2_ECMP_PREFIX, NPL_DESTINATION_STAGE2_ECMP_PREFIX_LEN)) {
        retval.val = (dest_id & ~NPL_DESTINATION_MASK_STAGE2_ECMP) | NPL_LPM_COMPRESSED_DESTINATION_STAGE2_ECMP_MASK;
    } else if (does_destination_match_prefix(
                   dest_id, NPL_DESTINATION_L3_DLP_SUBNET_PREFIX, NPL_DESTINATION_L3_DLP_SUBNET_PREFIX_LEN)) {
        retval.val = (dest_id & ~NPL_DESTINATION_MASK_L3_DLP_SUBNET) | NPL_LPM_COMPRESSED_DESTINATION_L3_DLP_SUBNET_MASK;
    } else if (does_destination_match_prefix(dest_id, NPL_DESTINATION_CE_PTR_PREFIX, NPL_DESTINATION_CE_PTR_PREFIX_LEN)) {
        retval.val = (dest_id & ~NPL_DESTINATION_MASK_CE_PTR) | NPL_LPM_COMPRESSED_DESTINATION_CE_PTR_MASK;
    } else if (does_destination_match_prefix(dest_id, NPL_DESTINATION_FEC_PREFIX, NPL_DESTINATION_FEC_PREFIX_LEN)) {
        retval.val = (dest_id & ~NPL_DESTINATION_MASK_FEC) | NPL_LPM_COMPRESSED_DESTINATION_FEC_MASK;
    }

    return retval;
}

bool
does_destination_match_prefix(uint64_t destination, uint64_t prefix, uint64_t prefix_len)
{
    if ((destination >> (NUM_OF_BITS_IN_DESTINATION - prefix_len)) == prefix) {
        return true;
    }

    return false;
}

static bool
is_aggregate_port_raw(const la_l3_port* port)
{
    if (port == nullptr) {
        return false;
    }

    la_object::object_type_e port_type = port->type();
    // SVI is always multi-slice
    if (port_type != la_object::object_type_e::L3_AC_PORT) {
        return true;
    }

    const la_l3_ac_port_impl* acp = static_cast<const la_l3_ac_port_impl*>(port);
    const la_ethernet_port* ep = acp->get_ethernet_port();
    const la_system_port* sp = ep->get_system_port();
    // Counters for SPA ports are aggregated
    if (sp != nullptr) {
        return false;
    }

    return true;
}

bool
is_aggregate_port(const la_l3_port_wcptr& port)
{
    return is_aggregate_port_raw(port.get());
}

bool
is_aggregate_nh(const la_next_hop* next_hop)
{
    la_l3_port* l3_port = nullptr;
    const la_next_hop_base* next_hop_impl = static_cast<const la_next_hop_base*>(next_hop);

    la_status status = next_hop_impl->get_router_port(l3_port);
    if (status != LA_STATUS_SUCCESS) {
        return false;
    }

    return (is_aggregate_port_raw(l3_port));
}

bool
is_aggregate_nh(const la_next_hop_wcptr& next_hop)
{
    return is_aggregate_nh(next_hop.get());
}

#define HW_LOAD_BALANCE_VECTOR_BITS 380
#define SOFT_LOAD_BALANCE_VECTOR_BITS 292
#define SOFT_LB_KEY_WIDTH 16
#define HW_LOAD_BALANCE_HARD_VECTOR_MSB 315
#define HW_LOAD_BALANCE_INITIAL_VECTOR_BITS 16
#define LOAD_BALANCE_DIVISOR_BITS 17
#define LOAD_BALANCE_DIVISOR_MSB 16
#define LOAD_BALANCE_RESULT_BITS 16
#define LOAD_BALANCE_RESULT_MSB 15

static void
hw_load_balancing_populate_bit_vector(const la_lb_vector_t& lb_vector, bit_vector384_t& bit_vector)
{
    size_t msb = 0, lsb = 0;
    uint64_t value = 0;

    //
    // fieldSelect [379:316]
    // hardVector  [315:0]
    //

    msb = HW_LOAD_BALANCE_HARD_VECTOR_MSB;
    if (lb_vector.type == LA_LB_VECTOR_IPV4_TCP_UDP) {
        lsb = msb - 16 + 1;
        value = lb_vector.ipv4.src_port;
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 16 + 1;
        value = lb_vector.ipv4.dest_port;
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 8 + 1;
        value = lb_vector.ipv4.protocol;
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv4.sip;
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv4.dip;
        bit_vector.set_bits(msb, lsb, value);

        // The following bit set relies on the configuration of:
        // Reg: m_pacific_tree->slice[0-5]->npu->rxpp_fwd->rxpp_fwd->res_lb_profile_fs_insturctions_reg[1]
        // Field: res_lb_key_fs0_instruction
        // The configuration is made in 'la_device_impl::init_load_balancing_keys()'
        // --> dst: 'bit_vector' fs0 (bit_vector[347:316]), src/value: packet portion as defined in profile 1, fs0_instruction
        msb = HW_LOAD_BALANCE_VECTOR_BITS - 33;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv4.sip;
        bit_vector.set_bits(msb, lsb, value);
        // taking second dip into lb_vector
        msb = HW_LOAD_BALANCE_VECTOR_BITS - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv4.dip;
        bit_vector.set_bits(msb, lsb, value);
    } else if (lb_vector.type == LA_LB_VECTOR_IPV4_NON_TCP_UDP) {
        lsb = msb - 32 + 1;
        value = lb_vector.ipv4.sip;
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv4.dip;
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 8 + 1;
        value = lb_vector.ipv4.protocol;
        bit_vector.set_bits(msb, lsb, value);

        // The following bit set relies on the configuration of:
        // Reg: m_pacific_tree->slice[0-5]->npu->rxpp_fwd->rxpp_fwd->res_lb_profile_fs_insturctions_reg[1]
        // Field: res_lb_key_fs0_instruction
        // The configuration is made in 'la_device_impl::init_load_balancing_keys()'
        // --> dst: 'bit_vector' fs0 (bit_vector[347:316]), src/value: packet portion as defined in profile 1, fs0_instruction
        msb = HW_LOAD_BALANCE_VECTOR_BITS - 33;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv4.sip;
        bit_vector.set_bits(msb, lsb, value);
        // taking second dip into lb_vector
        msb = HW_LOAD_BALANCE_VECTOR_BITS - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv4.dip;
        bit_vector.set_bits(msb, lsb, value);
    } else if (lb_vector.type == LA_LB_VECTOR_IPV6_TCP_UDP) {
        lsb = msb - 16 + 1;
        value = lb_vector.ipv6.src_port;
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 16 + 1;
        value = lb_vector.ipv6.dest_port;
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 8 + 1;
        value = lb_vector.ipv6.next_header;
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv6.sip[3];
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv6.sip[2];
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv6.sip[1];
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv6.sip[0];
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv6.dip[3];
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv6.dip[2];
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv6.dip[1];
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv6.dip[0];
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 20 + 1;
        value = lb_vector.ipv6.flow_label;
        bit_vector.set_bits(msb, lsb, value);

        // The following bit set relies on the configuration of:
        // Reg: m_pacific_tree->slice[0-5]->npu->rxpp_fwd->rxpp_fwd->res_lb_profile_fs_insturctions_reg[2]
        // Field: res_lb_key_fs0_instruction
        // The configuration is made in 'la_device_impl::init_load_balancing_keys()'
        // --> dst: 'bit_vector' fs0 (bit_vector[347:316]), src/value: packet portion as defined in profile 2, fs0_instruction
        msb = HW_LOAD_BALANCE_VECTOR_BITS - 33;
        lsb = msb - 32 + 1;
        value = (lb_vector.ipv6.dip[2] << 8) | (lb_vector.ipv6.dip[1] >> 24); // ipv6.dip[87:56] = (dip[2][23:0],dip[1][31:24])
        bit_vector.set_bits(msb, lsb, value);
    } else if (lb_vector.type == LA_LB_VECTOR_IPV6_NON_TCP_UDP) {
        lsb = msb - 32 + 1;
        value = lb_vector.ipv6.sip[3];
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv6.sip[2];
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv6.sip[1];
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv6.sip[0];
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv6.dip[3];
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv6.dip[2];
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv6.dip[1];
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv6.dip[0];
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 8 + 1;
        value = lb_vector.ipv6.next_header;
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 20 + 1;
        value = lb_vector.ipv6.flow_label;
        bit_vector.set_bits(msb, lsb, value);

        // The following bit set relies on the configuration of:
        // Reg: m_pacific_tree->slice[0-5]->npu->rxpp_fwd->rxpp_fwd->res_lb_profile_fs_insturctions_reg[2]
        // Field: res_lb_key_fs0_instruction
        // The configuration is made in 'la_device_impl::init_load_balancing_keys()'
        // --> dst: 'bit_vector' fs0 (bit_vector[347:316]), src/value: packet portion as defined in profile 2, fs0_instruction
        msb = HW_LOAD_BALANCE_VECTOR_BITS - 33;
        lsb = msb - 32 + 1;
        value = (lb_vector.ipv6.dip[2] << 8) | (lb_vector.ipv6.dip[1] >> 24); // ipv6.dip[87:56] = (dip[2][23:0],dip[1][31:24])
        bit_vector.set_bits(msb, lsb, value);
    } else if (lb_vector.type == LA_LB_VECTOR_ETHERNET_VLAN_TAG) {
        lsb = msb - 12 + 1;
        value = lb_vector.ethernet.vlan_id;
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 48 + 1;
        value = lb_vector.ethernet.da.flat;
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 48 + 1;
        value = lb_vector.ethernet.sa.flat;
        bit_vector.set_bits(msb, lsb, value);
    } else if (lb_vector.type == LA_LB_VECTOR_ETHERNET_NON_VLAN_TAG) {
        lsb = msb - 48 + 1;
        value = lb_vector.ethernet.da.flat;
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 48 + 1;
        value = lb_vector.ethernet.sa.flat;
        bit_vector.set_bits(msb, lsb, value);
    } else if (lb_vector.type == LA_LB_VECTOR_MPLS) {
        uint8_t labels = 0;
        uint32_t label_value;
        while (labels < lb_vector.mpls.num_valid_labels) {
            lsb = msb - 20 + 1;
            label_value = lb_vector.mpls.label[labels];
            value = label_value;
            bit_vector.set_bits(msb, lsb, value);
            msb = lsb - 1;
            labels++;
        }
    } else if (lb_vector.type == LA_LB_VECTOR_MPLS_IPV4) {
        lsb = msb - 8 + 1;
        value = lb_vector.ipv4.protocol;
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv4.sip;
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 32 + 1;
        value = lb_vector.ipv4.dip;
        bit_vector.set_bits(msb, lsb, value);
    } else if (lb_vector.type == LA_LB_VECTOR_MPLS_IPV6) {
        lsb = msb - 64 + 1;
        value = *(uint64_t*)&(lb_vector.ipv6.sip[0]);
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 64 + 1;
        value = *(uint64_t*)&(lb_vector.ipv6.sip[2]);
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 64 + 1;
        value = *(uint64_t*)&(lb_vector.ipv6.dip[0]);
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 64 + 1;
        value = *(uint64_t*)&(lb_vector.ipv6.dip[2]);
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 8 + 1;
        value = lb_vector.ipv6.next_header;
        bit_vector.set_bits(msb, lsb, value);

        msb = lsb - 1;
        lsb = msb - 20 + 1;
        value = lb_vector.ipv6.flow_label;
        bit_vector.set_bits(msb, lsb, value);
    } else if (lb_vector.type == LA_LB_VECTOR_MPLS_ENTROPY_LI) {
        lsb = msb - 20 + 1;
        value = lb_vector.mpls_entropy_li;
        bit_vector.set_bits(msb, lsb, value);
    } else {
        // ALL ZEROS
    }
}

static void
set_src_to_dst_vector_in_reverse(bit_vector384_t& dst_bit_vector,
                                 uint16_t dst_msb,
                                 bit_vector64_t& src_bit_vector,
                                 uint16_t src_offset,
                                 uint16_t src_sz)
{
    for (uint16_t i = 0; i < src_sz; i++) {
        dst_bit_vector.set_bit(dst_msb - i, src_bit_vector.bit(src_offset + i));
    }
}

static void
populate_soft_lb_vector_ipv4(const la_lb_vector_t& lb_vector, bit_vector384_t& bit_vector)
{
    size_t msb = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    if (lb_vector.type == LA_LB_VECTOR_IPV4_TCP_UDP) {
        src_port = lb_vector.ipv4.src_port;
        dst_port = lb_vector.ipv4.dest_port;
    }

    // Bit vectors
    bit_vector64_t sip_vector(lb_vector.ipv4.sip, 32);
    bit_vector64_t dip_vector(lb_vector.ipv4.dip, 32);
    bit_vector64_t dport_vector(dst_port, 16);
    bit_vector64_t sport_vector(src_port, 16);
    bit_vector64_t proto_vector(lb_vector.ipv4.protocol, 8);

    // Set lower 16 bits of DIP
    msb = SOFT_LOAD_BALANCE_VECTOR_BITS - 1;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, dip_vector, 0, 16);

    // Set bit 56 of soft vector remaining
    msb -= (64 + 55);
    bit_vector.set_bit(msb, 1);

    // Set Destination Port
    msb -= 1;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, dport_vector, 0, 16);

    // Set Source Port
    msb -= 16;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, sport_vector, 0, 16);

    // Set higher 16 bits of DIP
    msb -= 16;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, dip_vector, 16, 16);

    // Set SIP
    msb -= 16;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, sip_vector, 0, 32);

    // Set Protocol
    msb -= 32;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, proto_vector, 0, 8);
}

static void
populate_soft_lb_vector_ipv6(const la_lb_vector_t& lb_vector, bit_vector384_t& bit_vector)
{
    size_t msb = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    if (lb_vector.type == LA_LB_VECTOR_IPV6_TCP_UDP) {
        src_port = lb_vector.ipv6.src_port;
        dst_port = lb_vector.ipv6.dest_port;
    }

    // Bit vectors
    bit_vector64_t dip_vector_0(lb_vector.ipv6.dip[0], 32); // DIP[31:0]
    bit_vector64_t dip_vector_1(lb_vector.ipv6.dip[1], 32); // DIP[63:32]
    bit_vector64_t dip_vector_2(lb_vector.ipv6.dip[2], 32); // DIP[95:64]
    bit_vector64_t dip_vector_3(lb_vector.ipv6.dip[3], 32); // DIP[127:96]
    bit_vector64_t sip_vector_0(lb_vector.ipv6.sip[0], 32); // SIP[31:0]
    bit_vector64_t sip_vector_1(lb_vector.ipv6.sip[1], 32); // SIP[63:32]
    bit_vector64_t sip_vector_2(lb_vector.ipv6.sip[2], 32); // SIP[95:64]
    bit_vector64_t proto_vector(lb_vector.ipv6.next_header, 8);
    bit_vector64_t flow_vector(lb_vector.ipv6.flow_label, 20);
    bit_vector64_t dport_vector(dst_port, 16);
    bit_vector64_t sport_vector(src_port, 16);

    // Set DIP [31:0]
    msb = SOFT_LOAD_BALANCE_VECTOR_BITS - 1;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, dip_vector_0, 0, 32);

    // Set DIP [63:32]
    msb -= 32;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, dip_vector_1, 0, 32);

    // Set DIP [102:64]
    msb -= 32;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, dip_vector_2, 0, 32);
    msb -= 32;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, dip_vector_3, 0, 7);

    // Set SIP [47:32]
    msb -= 7;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, sip_vector_1, 0, 16);

    // Set bit 56 of soft vector remaining
    msb -= 16;
    bit_vector.set_bit(msb, 1);

    // Set SIP [31:0]
    msb -= 1;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, sip_vector_0, 0, 32);

    // Set SIP [95:48]
    msb -= 32;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, sip_vector_1, 16, 16);
    msb -= 16;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, sip_vector_2, 0, 32);

    // Set next header
    msb -= 32;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, proto_vector, 0, 8);

    // Set Flow label
    msb -= 8;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, flow_vector, 0, 20);

    // Set Destination Port
    msb -= 20;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, dport_vector, 0, 16);

    // Set Source Port
    msb -= 16;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, sport_vector, 0, 16);
}

static void
populate_soft_lb_vector_eth_non_vlan(const la_lb_vector_t& lb_vector, bit_vector384_t& bit_vector)
{
    size_t msb = 0;
    bit_vector64_t dmac_vector(lb_vector.ethernet.da.flat, 48);
    bit_vector64_t smac_vector(lb_vector.ethernet.sa.flat, 48);
    bit_vector64_t etype_vector(lb_vector.ethernet.ether_type, 16);

    // Set bit 56 of soft vector remaining
    msb = SOFT_LOAD_BALANCE_VECTOR_BITS - 1 - 64 - 55;
    bit_vector.set_bit(msb, 1);

    // Set SA/DA [167:56]
    msb -= 1;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, etype_vector, 0, 16);
    msb -= 16;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, smac_vector, 0, 48);
    msb -= 48;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, dmac_vector, 0, 48);
}

static void
populate_soft_lb_vector_eth_vlan(const la_lb_vector_t& lb_vector, bit_vector384_t& bit_vector)
{
    size_t msb = 0;
    bit_vector64_t dmac_vector(lb_vector.ethernet.da.flat, 48);
    bit_vector64_t smac_vector(lb_vector.ethernet.sa.flat, 48);
    bit_vector64_t vlan_vector(lb_vector.ethernet.vlan_id, 16);
    bit_vector64_t etype_vector(lb_vector.ethernet.ether_type, 16);

    // Set bit 56 of soft vector remaining
    msb = SOFT_LOAD_BALANCE_VECTOR_BITS - 1 - 64 - 55;
    bit_vector.set_bit(msb, 1);

    // Set Vlan [67:56]
    msb -= 1;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, vlan_vector, 0, 12);

    // Set SA/DA [179:68]
    msb -= 12;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, etype_vector, 0, 16);
    msb -= 16;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, smac_vector, 0, 48);
    msb -= 48;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, dmac_vector, 0, 48);
}

static void
populate_soft_lb_vector_eth_mpls_cw(const la_lb_vector_t& lb_vector, bit_vector384_t& bit_vector)
{
    size_t msb = 0;
    bit_vector64_t dmac_vector(lb_vector.ethernet.da.flat, 48);
    bit_vector64_t smac_vector(lb_vector.ethernet.sa.flat, 48);

    // Set bit 56 of soft vector remaining
    msb = SOFT_LOAD_BALANCE_VECTOR_BITS - 1 - 64 - 55;
    bit_vector.set_bit(msb, 1);

    // Set SA/DA [167:56]
    msb -= 1;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, smac_vector, 16, 32);
    msb -= 32;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, dmac_vector, 0, 48);
}

static void
populate_soft_lb_vector_gtp(const la_lb_vector_t& lb_vector, bit_vector384_t& bit_vector)
{
    size_t msb = 0;
    bit_vector64_t gtp_teid_vector(lb_vector.gtp_tunnel_id, 32);

    // Set lower 16 bits of Tunnel ID
    msb = SOFT_LOAD_BALANCE_VECTOR_BITS - 1;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, gtp_teid_vector, 0, 16);

    // Set bit 56 of soft vector remaining
    msb -= (64 + 55);
    bit_vector.set_bit(msb, 1);

    // Set higher 16 bits of Tunnel ID
    msb -= 1;
    set_src_to_dst_vector_in_reverse(bit_vector, msb, gtp_teid_vector, 16, 16);
}

static void
soft_load_balancing_populate_bit_vector(const la_lb_vector_t& lb_vector, bit_vector384_t& bit_vector)
{
    if ((lb_vector.type == LA_LB_VECTOR_IPV4_TCP_UDP) || (lb_vector.type == LA_LB_VECTOR_IPV4_NON_TCP_UDP)) {

        populate_soft_lb_vector_ipv4(lb_vector, bit_vector);

    } else if ((lb_vector.type == LA_LB_VECTOR_IPV6_TCP_UDP) || (lb_vector.type == LA_LB_VECTOR_IPV6_NON_TCP_UDP)) {

        populate_soft_lb_vector_ipv6(lb_vector, bit_vector);

    } else if (lb_vector.type == LA_LB_VECTOR_ETHERNET_NON_VLAN_TAG) {

        populate_soft_lb_vector_eth_non_vlan(lb_vector, bit_vector);

    } else if (lb_vector.type == LA_LB_VECTOR_ETHERNET_VLAN_TAG) {

        populate_soft_lb_vector_eth_vlan(lb_vector, bit_vector);

    } else if (lb_vector.type == LA_LB_VECTOR_MPLS_CW_ETHERNET) {

        populate_soft_lb_vector_eth_mpls_cw(lb_vector, bit_vector);

    } else if (lb_vector.type == LA_LB_VECTOR_GTP) {

        populate_soft_lb_vector_gtp(lb_vector, bit_vector);
    }
}

static uint16_t
load_balancing_hash(uint16_t initial_value, uint32_t divisor, const la_lb_vector_t& lb_vector, bool is_soft)
{
    size_t load_balance_vector_width = is_soft ? SOFT_LOAD_BALANCE_VECTOR_BITS : HW_LOAD_BALANCE_VECTOR_BITS;

    bit_vector384_t lb_vector_bits(0, load_balance_vector_width);

    if (is_soft) {
        soft_load_balancing_populate_bit_vector(lb_vector, lb_vector_bits);
    } else {
        hw_load_balancing_populate_bit_vector(lb_vector, lb_vector_bits);
    }

    uint64_t value = divisor;
    bit_vector64_t bv_divisor(0, LOAD_BALANCE_DIVISOR_BITS);
    bv_divisor.set_bits(LOAD_BALANCE_DIVISOR_MSB, 0, value);

    value = (divisor & 0xFFFF);
    bit_vector64_t bv_taps(0, LOAD_BALANCE_RESULT_BITS);
    bv_taps.set_bits(LOAD_BALANCE_RESULT_MSB, 0, value);

    // Result starts with initial vector
    value = initial_value;
    bit_vector64_t bv_hash_result(0, LOAD_BALANCE_RESULT_BITS);
    bv_hash_result.set_bits(LOAD_BALANCE_RESULT_MSB, 0, value);

    bit_vector64_t bv_relevant_bits(0, LOAD_BALANCE_RESULT_BITS);
    // Value bits are inserted one by one, and XORed with result's relevant bits according to taps.
    // On each cycle result is shifted right by 1, and the MSB is set by XORing next value bit and relevant result bits.
    for (size_t i = 0; i < load_balance_vector_width; i++) {
        bv_relevant_bits = bv_hash_result;
        bv_relevant_bits &= bv_taps;
        bool next_bit = lb_vector_bits.bit(i);

        // Calculation of next bit
        for (size_t j = 0; j < LOAD_BALANCE_RESULT_BITS; j++) {
            next_bit ^= bv_relevant_bits.bit(j);
        }

        // Shifting right by 1, setting MSB to be calculated next bit.
        value = bv_hash_result.get_value();
        value = ((value >> 1) & 0x7FFF); // clear the MSB which will be replaced with next_bit
        value |= ((next_bit & 0x1) << LOAD_BALANCE_RESULT_MSB);
        bv_hash_result.set_bits(LOAD_BALANCE_RESULT_MSB, 0, value);
    }

    return bv_hash_result.get_value();
}

static void
get_shifted_crc_divisors(uint16_t shift_amount, std::vector<uint64_t>& out_crc_divisors)
{
    std::vector<uint64_t> crc_divisors{NPL_LB_CRC_DIVISOR_0, /*  lb_key[0]  DSPA */
                                       NPL_LB_CRC_DIVISOR_1,
                                       NPL_LB_CRC_DIVISOR_2,
                                       NPL_LB_CRC_DIVISOR_3,
                                       NPL_LB_CRC_DIVISOR_4,
                                       NPL_LB_CRC_DIVISOR_5};

    std::rotate(crc_divisors.begin(), crc_divisors.begin() + crc_divisors.size() - shift_amount, crc_divisors.end());

    out_crc_divisors = crc_divisors;
}

static int16_t
calculate_lb_hash_for_step(const la_lb_pak_fields_vec& lb_vector, resolution_step_e step, uint16_t seed, uint16_t shift_amount)
{
    uint16_t hw_lb_key;
    uint16_t soft_lb_key;
    la_lb_vector_t hw_lb_vector = {};
    la_lb_vector_t soft_lb_vector = {};
    int num_vec = 0;
    const int MIN_NUM_KEYS = 1;

    //
    // Barrel Shifted (16 bits) of 96b load balance hash vector
    //
    // Original Form: [5][4][3][2][1][0]
    // After Barrel Shifted: [4][3][2][1][0][5]
    //
    // lb_key[0] => [5]
    // lb_key[1] => [0]
    // lb_key[2] => [1]
    // lb_key[3] => [2]
    //

    // Extract lb vectors. Only two lb_vectors are supported today. The first one is for hardwired lb
    // calculation and the second one for software lb calculation
    for (auto tmp_vec : lb_vector) {
        switch (num_vec) {
        case 0:
            hw_lb_vector = tmp_vec;
            break;
        case 1:
            soft_lb_vector = tmp_vec;
            break;
        default:
            break;
        }

        ++num_vec;
    }

    std::vector<uint64_t> crc_divisors;
    get_shifted_crc_divisors(shift_amount, crc_divisors);

    switch (step) {
    case RESOLUTION_STEP_NATIVE_LB: {
        // LB_KEY 3
        hw_lb_key = load_balancing_hash(seed, crc_divisors[3], hw_lb_vector, false /* is_soft */);
        hw_lb_key += NPL_LB_KEY_CONST_ADD;

        if (num_vec > MIN_NUM_KEYS) {
            soft_lb_key = load_balancing_hash(seed, NPL_LB_CRC_DIVISOR_3, soft_lb_vector, true /* is_soft */);
            return hw_lb_key ^ soft_lb_key;
        } else {
            return hw_lb_key;
        }
    }
    case RESOLUTION_STEP_STAGE2_LB: {
        // LB_KEY 2
        hw_lb_key = load_balancing_hash(seed, crc_divisors[2], hw_lb_vector, false /* is_soft */);
        hw_lb_key += NPL_LB_KEY_CONST_ADD;

        if (num_vec > MIN_NUM_KEYS) {
            soft_lb_key = load_balancing_hash(seed, NPL_LB_CRC_DIVISOR_2, soft_lb_vector, true /* is_soft */);
            return hw_lb_key ^ soft_lb_key;
        } else {
            return hw_lb_key;
        }
    }
    case RESOLUTION_STEP_STAGE3_LB: {
        // LB_KEY 1
        hw_lb_key = load_balancing_hash(seed, crc_divisors[1], hw_lb_vector, false /* is_soft */);
        hw_lb_key += NPL_LB_KEY_CONST_ADD;

        if (num_vec > MIN_NUM_KEYS) {
            soft_lb_key = load_balancing_hash(seed, NPL_LB_CRC_DIVISOR_1, soft_lb_vector, true /* is_soft */);
            return hw_lb_key ^ soft_lb_key;
        } else {
            return hw_lb_key;
        }
    }
    case RESOLUTION_STEP_PORT_DSPA: {
        // LB_KEY 0
        hw_lb_key = load_balancing_hash(seed, crc_divisors[0], hw_lb_vector, false /* is_soft */);
        hw_lb_key += NPL_LB_KEY_CONST_ADD;

        if (num_vec > MIN_NUM_KEYS) {
            soft_lb_key = load_balancing_hash(seed, NPL_LB_CRC_DIVISOR_0, soft_lb_vector, true /* is_soft */);
            return hw_lb_key ^ soft_lb_key;
        } else {
            return hw_lb_key;
        }
    }

    default: {
        return 0;
    }
    }
}

la_status
do_lb_resolution(const la_lb_pak_fields_vec& lb_vector,
                 size_t group_size,
                 npl_lb_consistency_mode_e consistency_mode,
                 resolution_step_e step,
                 uint16_t seed,
                 uint16_t shift_amount,
                 size_t& out_member_id)
{
    uint16_t lb_key = calculate_lb_hash_for_step(lb_vector, step, seed, shift_amount);
    if (consistency_mode == NPL_LB_CONSISTENCY_MODE_CONSISTENCE_ENABLED) {
        //
        // Consistency mode should use EM with hash value as member_id along
        // with group id, so that it provides consistent path for the flow
        //
        out_member_id = lb_key;
    } else {
        out_member_id = (((lb_key * group_size) & 0x1FF0000) >> 16);
    }
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
