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

#ifndef __LA_OBJECT_H__
#define __LA_OBJECT_H__

#include "api/types/la_common_types.h"
#include "api/types/la_system_types.h"

#include <memory>

/// @file
/// @brief Leaba Object API-s.
///
/// Defines API-s for managing the #silicon_one::la_object base class.

/// @addtogroup OBJECT
/// @{

namespace silicon_one
{

/// Leaba API object base class.
///
/// All API objects derive from this class.
/// Each created object is associated with the owner device, and API objects may interact with
/// each other if and only if they're created from the same device.
class la_object
{
public:
    /// @brief API object type.
    ///
    /// Enumerates API object types inheriting from la_object.
    enum class object_type_e {
        AC_PROFILE = 0,               ///< #silicon_one::la_ac_profile
        ACL,                          ///< #silicon_one::la_acl
        ACL_SCALED,                   ///< #silicon_one::la_acl_scaled
        ACL_KEY_PROFILE,              ///< #silicon_one::la_acl_key_profile
        ACL_COMMAND_PROFILE,          ///< #silicon_one::la_acl_command_profile
        ACL_GROUP,                    ///< #silicon_one::la_acl_group
        ASBR_LSP,                     ///< #silicon_one::la_asbr_lsp
        BFD_SESSION,                  ///< #silicon_one::la_bfd_session
        COUNTER_SET,                  ///< #silicon_one::la_counter_set
        DESTINATION_PE,               ///< #silicon_one::la_destination_pe
        DEVICE,                       ///< #silicon_one::la_device
        ECMP_GROUP,                   ///< #silicon_one::la_ecmp_group
        EGRESS_QOS_PROFILE,           ///< #silicon_one::la_egress_qos_profile
        ERSPAN_MIRROR_COMMAND,        ///< #silicon_one::la_erspan_mirror_command
        ETHERNET_PORT,                ///< #silicon_one::la_ethernet_port
        FABRIC_MULTICAST_GROUP,       ///< #silicon_one::la_fabric_multicast_group
        FABRIC_PORT,                  ///< #silicon_one::la_fabric_port
        FABRIC_PORT_SCHEDULER,        ///< #silicon_one::la_fabric_port_scheduler
        FEC,                          ///< #silicon_one::la_l3_fec
        FILTER_GROUP,                 ///< #silicon_one::la_filter_group
        FLOW_CACHE_HANDLER,           ///< #silicon_one::la_flow_cache_handler
        FORUS_DESTINATION,            ///< #silicon_one::la_forus_destination
        GRE_PORT,                     ///< #silicon_one::la_gre_port
        GUE_PORT,                     ///< #silicon_one::la_gue_port
        HBM_HANDLER,                  ///< #silicon_one::la_hbm_handler
        PTP_HANDLER,                  ///< #silicon_one::la_ptp_handler
        IFG_SCHEDULER,                ///< #silicon_one::la_ifg_scheduler
        INGRESS_QOS_PROFILE,          ///< #silicon_one::la_ingress_qos_profile
        INTERFACE_SCHEDULER,          ///< #silicon_one::la_interface_scheduler
        IP_MULTICAST_GROUP,           ///< #silicon_one::la_ip_multicast_group
        IP_OVER_IP_TUNNEL_PORT,       ///< #silicon_one::la_ip_over_ip_tunnel_port
        IP_TUNNEL_DESTINATION,        ///< #silicon_one::la_ip_tunnel_destination
        LOGICAL_PORT_SCHEDULER,       ///< #silicon_one::la_logical_port_scheduler
        LPTS,                         ///< #silicon_one::la_lpts
        COPC,                         ///< #silicon_one::la_control_plane_classifier
        L2_MIRROR_COMMAND,            ///< #silicon_one::la_l2_mirror_command
        L2_MULTICAST_GROUP,           ///< #silicon_one::la_l2_multicast_group
        L2_PROTECTION_GROUP,          ///< #silicon_one::la_l2_protection_group
        L3_PROTECTION_GROUP,          ///< #silicon_one::la_l3_protection_group
        L2_PUNT_DESTINATION,          ///< #silicon_one::la_l2_punt_destination
        L2_SERVICE_PORT,              ///< #silicon_one::la_l2_service_port
        L3_AC_PORT,                   ///< #silicon_one::la_l3_ac_port
        LSR,                          ///< #silicon_one::la_lsr
        MAC_PORT,                     ///< #silicon_one::la_mac_port
        METER_ACTION_PROFILE,         ///< #silicon_one::la_meter_action_profile
        METER_MARKDOWN_PROFILE,       ///< #silicon_one::la_meter_markdown_profile
        METER_PROFILE,                ///< #silicon_one::la_meter_profile
        METER_SET,                    ///< #silicon_one::la_meter_set
        MPLS_LABEL_DESTINATION,       ///< #silicon_one::la_mpls_label_destination
        MPLS_NHLFE,                   ///< #silicon_one::la_mpls_nhlfe
        MPLS_VPN_DECAP,               ///< #silicon_one::la_mpls_vpn_decap
        MPLS_VPN_ENCAP,               ///< #silicon_one::la_mpls_vpn_encap
        MLDP_VPN_DECAP,               ///< #silicon_one::la_mldp_vpn_decap
        MPLS_MULTICAST_GROUP,         ///< #silicon_one::la_mpls_multicast_group
        MULTICAST_PROTECTION_GROUP,   ///< #silicon_one::la_multicast_protection_group
        MULTICAST_PROTECTION_MONITOR, ///< #silicon_one::la_multicast_protection_monitor
        NEXT_HOP,                     ///< #silicon_one::la_next_hop
        NPU_HOST_DESTINATION,         ///< #silicon_one::la_npu_host_destination
        NPU_HOST_PORT,                ///< #silicon_one::la_npu_host_port
        OG_LPTS_APPLICATION,          ///< #silicon_one::la_og_lpts_application
        OUTPUT_QUEUE_SCHEDULER,       ///< #silicon_one::la_output_queue_scheduler
        PCI_PORT,                     ///< #silicon_one::la_pci_port
        PCL,                          ///< #silicon_one::la_pcl
        PREFIX_OBJECT,                ///< #silicon_one::la_prefix_object
        PROTECTION_MONITOR,           ///< #silicon_one::la_protection_monitor
        PUNT_INJECT_PORT,             ///< #silicon_one::la_punt_inject_port
        RATE_LIMITER_SET,             ///< #silicon_one::la_rate_limiter_set
        RECYCLE_PORT,                 ///< #silicon_one::la_recycle_port
        REMOTE_PORT,                  ///< #silicon_one::la_remote_port
        REMOTE_DEVICE,                ///< #silicon_one::la_remote_device
        RX_CGM_SQ_PROFILE,            ///< #silicon_one::la_rx_cgm_sq_profile
        SPA_PORT,                     ///< #silicon_one::la_spa_port
        STACK_PORT,                   ///< #silicon_one::la_stack_port
        SVI_PORT,                     ///< #silicon_one::la_svi_port
        SWITCH,                       ///< #silicon_one::la_switch
        SYSTEM_PORT,                  ///< #silicon_one::la_system_port
        SYSTEM_PORT_SCHEDULER,        ///< #silicon_one::la_system_port_scheduler
        TE_TUNNEL,                    ///< #silicon_one::la_te_tunnel
        TC_PROFILE,                   ///< #silicon_one::la_tc_profile
        VOQ_CGM_PROFILE,              ///< #silicon_one::la_voq_cgm_profile
        VOQ_SET,                      ///< #silicon_one::la_voq_set
        VRF,                          ///< #silicon_one::la_vrf
        VXLAN_NEXT_HOP,               ///< #silicon_one::la_vxlan_next_hop
        VOQ_CGM_EVICTED_PROFILE,      ///< #silicon_one::la_voq_cgm_evicted_profile
        SECURITY_GROUP_CELL,          ///< #silicon_one::la_security_group_cell
        PBTS_MAP_PROFILE,             ///< #silicon_one::la_pbts_map_profile
        PBTS_GROUP,                   ///< #silicon_one::la_pbts_group
        VRF_REDIRECT_DESTINATION,     ///< #silicon_one::la_vrf_redirect_destination
        RTF_CONF_SET
    };

    /// @brief Get object's type.
    ///
    /// It is safe to downcast an object to the returned type.
    /// For example, if #type() returns object_type_e::SWITCH, the object can safely be
    /// downcast to #silicon_one::la_switch*.
    ///
    /// @return     #object_type_e for this object.
    virtual object_type_e type() const = 0;

    /// @brief Get device that owns this object.
    ///
    /// Device returned is the same one used for creating this object.
    /// Leaba API objects are allowed to interact only if they're both from the same device.
    ///
    /// @return     #silicon_one::la_device* that created this object.
    virtual const la_device* get_device() const = 0;

    /// @brief Get object ID.
    ///
    /// Unique number representing this object in the owner device.
    ///
    /// @return Object's ID.
    virtual la_object_id_t oid() const = 0;

    virtual std::string to_string() const = 0;

protected:
    // The code below should be:
    //     virtual ~la_object() = default;
    //
    // GCC 4.7 has some trouble dealing with base class destructor = default (see
    // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53613).
    // Therefore, la_object's destructor is implemented in place.
    virtual ~la_object()
    {
    }

    friend class la_object_deleter;
};
}

/// @}

#endif
