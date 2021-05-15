// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

/// @file
/// @brief Point-to-Point PWE service example
///
/// @example p2p_pwe1.cpp
///
/// Creates a Point-to-Point PWE service.
///
/// Traffic is serviced between PWE port 1 (raw PWE; local label 12, remote label 17) and PWE port 2 (tagged; local label 25, remote
/// label 28; using VLAN 8).
///
/// @dot
/// digraph p2p_pwe1 {
///     rankdir=LR;
///     node[shape = record, style="bold, rounded", fontname = "Helvetica:bold", fontsize = 10];
///     edge [tailport="e", headport="w", arrowhead="none"];
///     tunnel1 [label = "Tunnel 1 | Encap: 700"];
///     tunnel2 [label = "Tunnel 2 | Encap: 800"];
///     pwe1 [label = "PWE 1 (raw) | Local: 12 | Remote: 17"];
///     pwe2 [label = "PWE 2 (tagged) | Local: 25 | Remote : 28"];
///     tunnel1->pwe1;
///     pwe1->pwe2;
///     pwe2->tunnel2 [label = "VLAN 8"];
/// }
/// @enddot

#include "example_system.h"

#include "api/npu/la_ethernet_port.h"
#include "api/npu/la_l2_service_port.h"
#include "api/npu/la_l3_ac_port.h"
#include "api/npu/la_mpls_tunnel.h"
#include "api/npu/la_next_hop.h"
#include "api/npu/la_tunnel.h"
#include "api/npu/la_vrf.h"
#include "api/types/la_common_types.h"
#include "api/types/la_tunnel_types.h"

using namespace silicon_one;

const la_l3_destination_gid_t MPLS_TUNNEL1_GID = 0x123;
const la_mpls_label MPLS_TUNNEL1_LABEL = {600};

const la_l3_destination_gid_t MPLS_TUNNEL2_GID = 0x124;
const la_mpls_label MPLS_TUNNEL2_LABEL = {800};

la_ethernet_port *ep1, *ep2;
la_l2_service_port *pwe1, *pwe2;

const la_mpls_label PWE_LOCAL_LABEL_1 = {27};
const la_mpls_label PWE_REMOTE_LABEL_1 = {18};

const la_mpls_label PWE_LOCAL_LABEL_2 = {21};
const la_mpls_label PWE_REMOTE_LABEL_2 = {19};

la_mpls_tunnel* tunnel1;
la_mpls_tunnel* tunnel2;

void
create_tunnels(example_system_t* es)
{
    // Create the VRF and L3 ports.
    la_vrf* vrf = nullptr;
    la_l3_ac_port* l3ap0 = nullptr;
    la_l3_ac_port* l3ap1 = nullptr;
    la_mac_addr_t mac_addr = {.flat = 0};

    es->xdevice->create_vrf(es->vrf_next_gid++, vrf);
    es->xdevice->create_l3_ac_port(es->l3_port_next_gid++,
                                   es->l2_ethernet_ports[0],
                                   EXAMPLE_SYSTEM_AC_PROFILE_VID1,
                                   EXAMPLE_SYSTEM_AC_PROFILE_VID2,
                                   mac_addr,
                                   vrf,
                                   es->default_ingress_qos_profile,
                                   es->default_egress_qos_profile,
                                   la_egress_qos_marking_source_e::QOS_TAG,
                                   l3ap0);

    es->xdevice->create_l3_ac_port(es->l3_port_next_gid++,
                                   es->l2_ethernet_ports[1],
                                   EXAMPLE_SYSTEM_AC_PROFILE_VID1,
                                   EXAMPLE_SYSTEM_AC_PROFILE_VID2,
                                   mac_addr,
                                   vrf,
                                   es->default_ingress_qos_profile,
                                   es->default_egress_qos_profile,
                                   la_egress_qos_marking_source_e::QOS_TAG,
                                   l3ap1);

    // Create tunnel 1
    la_mac_addr_t tunnel1_da = la_mac_addr_from_string("00:00:5E:00:53:E2");
    la_next_hop* tunnel1_nh = nullptr;
    es->xdevice->create_next_hop(es->next_hop_next_gid++, tunnel1_da, l3ap0, tunnel1_nh);

    la_mpls_ttl_settings ttl1 = {.mode = la_mpls_ttl_inheritance_mode_e::UNIFORM, .ttl = 128};

    es->xdevice->create_mpls_tunnel(MPLS_TUNNEL1_GID,
                                    la_mpls_tunnel_type_e::PWE,
                                    MPLS_TUNNEL1_LABEL,
                                    tunnel1_nh,
                                    ttl1,
                                    es->default_egress_qos_profile,
                                    la_egress_qos_marking_source_e::QOS_TAG,
                                    tunnel1);

    // Create tunnel 2
    la_mac_addr_t tunnel2_da = la_mac_addr_from_string("00:00:5E:00:53:E3");
    la_next_hop* tunnel2_nh = nullptr;
    es->xdevice->create_next_hop(es->next_hop_next_gid++, tunnel2_da, l3ap1, tunnel2_nh);

    la_mpls_ttl_settings ttl2 = {.mode = la_mpls_ttl_inheritance_mode_e::UNIFORM, .ttl = 128};

    es->xdevice->create_mpls_tunnel(MPLS_TUNNEL2_GID,
                                    la_mpls_tunnel_type_e::PWE,
                                    MPLS_TUNNEL2_LABEL,
                                    tunnel1_nh,
                                    ttl2,
                                    es->default_egress_qos_profile,
                                    la_egress_qos_marking_source_e::QOS_TAG,
                                    tunnel2);
}

void
create_pwe_ports(example_system_t* es)
{
    // Create AC profile
    es->xdevice->create_pwe_l2_service_port(es->l2_port_next_gid++,
                                            PWE_LOCAL_LABEL_1,
                                            PWE_REMOTE_LABEL_1,
                                            es->l2_port_next_gid,
                                            tunnel1,
                                            es->default_ingress_qos_profile,
                                            es->default_egress_qos_profile,
                                            la_egress_qos_marking_source_e::QOS_TAG,
                                            pwe1);

    es->xdevice->create_pwe_tagged_l2_service_port(es->l2_port_next_gid++,
                                                   PWE_LOCAL_LABEL_2,
                                                   PWE_REMOTE_LABEL_2,
                                                   tunnel2,
                                                   8 /* outer VID */,
                                                   es->default_ingress_qos_profile,
                                                   es->default_egress_qos_profile,
                                                   la_egress_qos_marking_source_e::QOS_TAG,
                                                   pwe2);
}

void
connect_pwes(example_system_t* es)
{
    pwe1->set_destination(pwe2);
    pwe2->set_destination(pwe1);
}

int
main()
{
    example_system_t es;

    example_system_init(&es);

    ep1 = ep2 = nullptr;
    pwe1 = pwe2 = nullptr;
    tunnel1 = tunnel2 = nullptr;

    create_tunnels(&es);
    create_pwe_ports(&es);
    connect_pwes(&es);

    return 0;
}
