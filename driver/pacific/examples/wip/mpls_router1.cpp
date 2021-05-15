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
/// @brief MPLS Router example
///
/// @example mpls_router1.cpp
///
/// Creates Simple Router and MPLS "router" and populate them with few forwarding rules.
/// The default router has two ports. The MPLS has three ports.
///
/// Port 1 is "shared" by both routers - it can receive MPLS packets which will forward according to the MPLS ILM.
/// Non MPLS, IPv4 packets will be forwarded according to the IPv4 FIB.
///
/// @dot
/// digraph mpls_router1{
///     node[shape = box, style="bold, rounded", fontname = "Helvetica:bold", fontsize = 10];
///     edge [tailport="s", headport="n"];
///     vrf0[label = "IPv4 Router"];
///     mpls[label = "MPLS Router"];
///     rp0 [label = "L3 Eth port 0"];
///     rp1 [label = "L3 Eth port 1"];
///     rp2 [label = "L3 Eth port 2"];
///     rp3 [label = "L3 Eth port 3"];
///     sp0 [label = "SP 0"];
///     sp1 [label = "SP 1"];
///     sp2 [label = "SP 2"];
///     sp3 [label = "SP 3"];
///     { rank=same; rp0; rp1; rp2; rp3};
///     vrf0-> {rp0 rp1};
///     mpls-> {rp1 rp2 rp3};
///     rp0->sp0;
///     rp1->sp1;
///     rp2->sp2;
///     rp3->sp3;
/// }
/// @enddot
///
/// ### Routing Table: #
/// | Prefix             | Next Hop IP       | Next Hop MAC      | L3 Eth port |
/// | :-----------       | :---              | :---              | :---:       |
/// | 192.168. 11.  0/24 | Directly attached |                   | 0           |
/// | 192.168. 12.  0/24 | Directly attached |                   | 1           |
/// | 192.168.111.  0/24 | 192.168.11.100    | 00:00:5E:00:53:F1 | 0           |
/// |   0.  0.  0.  0/0  | 192.168.12.100    | 00:00:5E:00:53:F2 | 1           |
///
/// ### MPLS Incoming Label Map: #
/// | Incoming label    | MPLS Action                                       | Next Hop MAC      | L3 Eth port   |
/// | :-----------      | :---                                              | :---              | :---:         |
/// | 101               | SWAP to 201                                       | 00:00:5E:00:53:E1 | 1             |
/// | 102               | SWAP to 202, push to tunnel 1                     | 00:00:5E:00:53:E2 | 2             |
/// | 103               | POP (Penultimate hop popping), Uniform TTL        | 00:00:5E:00:53:E3 | 3             |
///
/// Tunnel 1 encapsulates the MPLS traffic with an additional MLPS label.
/// Encapsulated traffic is encapsulated using the label 700.
/// Received traffic with label 600 is decapsulated by the tunnel/router.

#include "example_system.h"

#include "api/npu/la_ethernet_port.h"
#include "api/npu/la_l3_ac_port.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_lsr.h"
#include "api/npu/la_mpls.h"
#include "api/npu/la_mpls_nhlfe.h"
#include "api/npu/la_mpls_tunnel.h"
#include "api/npu/la_next_hop.h"
#include "api/npu/la_switch.h"
#include "api/npu/la_tunnel.h"
#include "api/npu/la_vrf.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_tunnel_types.h"

using namespace silicon_one;

enum { NUM_OF_ROUTER_PORTS = 4 };

const la_l3_destination_gid_t MPLS_TUNNEL_GID = 0x123;
const la_mpls_label MPLS_TUNNEL_LABEL = {600};

void
add_router_port(example_system_t* es,
                la_vrf* vrf,
                la_l3_ac_port*& rport,
                const char* mac_addr_str,
                bool ipv4_en,
                bool mpls_en,
                const char* ipv4_str)
{
    la_mac_addr_t mac_addr = la_mac_addr_from_string(mac_addr_str);
    es->xdevice->create_l3_ac_port(es->l3_port_next_gid++,
                                   es->l2_ethernet_ports[0],
                                   EXAMPLE_SYSTEM_AC_PROFILE_VID1,
                                   EXAMPLE_SYSTEM_AC_PROFILE_VID2,
                                   mac_addr,
                                   vrf,
                                   es->default_ingress_qos_profile,
                                   es->default_egress_qos_profile,
                                   la_egress_qos_marking_source_e::QOS_TAG,
                                   rport);

    // set L3 port parameters
    rport->set_protocol_enabled(la_l3_protocol_e::IPV4_UC, ipv4_en);
    rport->set_protocol_enabled(la_l3_protocol_e::IPV4_MC, ipv4_en);
    rport->set_protocol_enabled(la_l3_protocol_e::IPV6_UC, false);
    rport->set_protocol_enabled(la_l3_protocol_e::IPV6_MC, false);
    rport->set_protocol_enabled(la_l3_protocol_e::MPLS, mpls_en);

    // Add IPv4 route
    if (ipv4_en) {
        la_ipv4_prefix_t ip_and_prefix = la_ipv4_prefix_from_string(ipv4_str);
        vrf->add_ipv4_route(ip_and_prefix, LA_L3_DESTINATION_CPU, 0 /* user-data */, false /* latency_sensitive */);
    }
}

void
create(example_system_t* es,
       la_vrf*& vrf0,
       la_l3_ac_port*& rp0,
       la_l3_ac_port*& rp1,
       la_l3_ac_port*& rp2,
       la_l3_ac_port*& rp3,
       la_mpls_tunnel*& tunnel)
{
    la_vlan_id_t vlan_id = 5;

    // Phase 1: Create the Router and the ports
    // Create Router
    es->xdevice->create_vrf(es->vrf_next_gid++, vrf0);

    // Clear MPLS ILM
    // la_mpls_clear_all_entries(es->device);

    // L3 Eth port 0, from Ethernet Port 0 (IPv4 only)
    add_router_port(es, vrf0, rp0, "00:00:5E:00:53:01", true, false, "192.168.11.1/24");

    // set port (special) parameters
    la_vlan_tag_t vlan_out_tag = {.tpid = 0x8100, .tci = {.fields = {.pcp = 0, .dei = 0, .vid = vlan_id}}};
    rp0->set_egress_vlan_tag(vlan_out_tag, LA_VLAN_TAG_UNTAGGED);

    // L3 Eth port 1, from Ethernet Port 1 (IPv4 and MPLS)
    add_router_port(es, vrf0, rp1, "00:00:5E:00:53:02", true, true, "192.168.12.1/24");

    // L3 Eth port 2, from Ethernet Port 2
    // MPLS only, with no VRF attachment or IP address
    add_router_port(es, vrf0, rp2, "00:00:5E:00:53:03", false, true, "");

    // L3 Eth port 3, from Ethernet Port 3
    // MPLS only, with no VRF attachment or IP address
    add_router_port(es, vrf0, rp3, "00:00:5E:00:53:04", false, true, "");

    // Create MPLS tunnel
    la_mac_addr_t tunnel_da = la_mac_addr_from_string("00:00:5E:00:53:E2");
    la_next_hop* tunnel_nh = nullptr;
    es->xdevice->create_next_hop(es->next_hop_next_gid++, tunnel_da, rp2, tunnel_nh);

    la_mpls_ttl_settings ttl = {.mode = la_mpls_ttl_inheritance_mode_e::UNIFORM, .ttl = 128};

    es->xdevice->create_mpls_tunnel(MPLS_TUNNEL_GID,
                                    la_mpls_tunnel_type_e::PLAIN,
                                    MPLS_TUNNEL_LABEL,
                                    tunnel_nh,
                                    ttl,
                                    es->default_egress_qos_profile,
                                    la_egress_qos_marking_source_e::QOS_TAG,
                                    tunnel);
}

void
update_fib(example_system_t* es, la_vrf& vrf0, la_l3_ac_port* rp0, la_l3_ac_port* rp1, la_l3_ac_port* rp2, la_l3_ac_port* rp3)
{
    // Add routes
    la_mac_addr_t mac_addr_arp1 = la_mac_addr_from_string("00:00:5E:00:53:F1"); // MAC of 192.168.11.100
    la_next_hop* nh1 = nullptr;
    es->xdevice->create_next_hop(es->next_hop_next_gid++, mac_addr_arp1, rp0, nh1);
    la_ipv4_prefix_t prefix1 = la_ipv4_prefix_from_string("192.168.111.0/24");
    vrf0.add_ipv4_route(prefix1, nh1, 0 /* user-data */, false /* latency_sensitive */);

    la_mac_addr_t mac_addr_arp2 = la_mac_addr_from_string("00:00:5E:00:53:F2"); // MAC of 192.168.12.100
    la_next_hop* nh2 = nullptr;
    es->xdevice->create_next_hop(es->next_hop_next_gid++, mac_addr_arp2, rp1, nh2);
    la_ipv4_prefix_t prefix2 = la_ipv4_prefix_from_string("0.0.0.0/0");
    vrf0.add_ipv4_route(prefix2, nh2, 0 /* user-data */, false /* latency_sensitive */);
}

void
update_ilm(example_system_t* es,
           la_vrf& vrf0,
           la_l3_ac_port* rp0,
           la_l3_ac_port* rp1,
           la_l3_ac_port* rp2,
           la_l3_ac_port* rp3,
           la_mpls_tunnel* mpls_tunnel)
{
    la_mpls_nhlfe* mpls_nhlfe1 = nullptr;
    la_mpls_nhlfe* mpls_nhlfe2 = nullptr;
    la_mpls_nhlfe* mpls_nhlfe3 = nullptr;

    la_lsr* lsr;
    es->xdevice->get_lsr(lsr);

    // Add MPLS NHLFE
    // NHLFE1: SWAP to label 201, send on RP1 (no TTL definition)
    la_mac_addr_t mac_addr_dest1 = la_mac_addr_from_string("00:00:5E:00:53:E1");
    la_next_hop* nh1 = nullptr;
    la_mpls_label label1 = {201};
    es->xdevice->create_next_hop(es->next_hop_next_gid++, mac_addr_dest1, rp1, nh1);
    es->xdevice->create_mpls_swap_nhlfe(nh1, label1, mpls_nhlfe1);
    la_mpls_label label1_1 = {101};
    lsr->add_route(label1_1, mpls_nhlfe1, 0 /*user data*/);

    // NHLFE2: SWAP to label 202, then push to tunnel.
    // TTL PIPE and start from 64, send on RP2
    la_mac_addr_t mac_addr_dest2 = la_mac_addr_from_string("00:00:5E:00:53:E2");
    la_next_hop* nh2 = nullptr;
    la_mpls_label label2 = {202};
    es->xdevice->create_next_hop(es->next_hop_next_gid++, mac_addr_dest2, rp2, nh2);
    es->xdevice->create_mpls_swap_nhlfe(nh2, label2, mpls_nhlfe2);
    la_mpls_label label2_1 = {102};
    lsr->add_route(label2_1, mpls_nhlfe2, 0 /*user data*/);

    // NHLFE3: POP label for Penultimate Pop Hopping
    la_mac_addr_t mac_addr_dest3 = la_mac_addr_from_string("00:00:5E:00:53:E3");
    la_next_hop* nh3 = nullptr;
    es->xdevice->create_next_hop(es->next_hop_next_gid++, mac_addr_dest3, rp3, nh3);
    es->xdevice->create_mpls_php_nhlfe(
        nh3, la_mpls_ttl_inheritance_mode_e::UNIFORM, la_mpls_qos_inheritance_mode_e::UNIFORM, mpls_nhlfe3);
    la_mpls_label label3_1 = {103};
    lsr->add_route(label3_1, mpls_nhlfe3, 0 /*user data*/);
}

int
main()
{
    example_system_t es;
    example_system_init(&es);

    la_vrf* vrf0 = nullptr;

    la_l3_ac_port* rp0 = nullptr;
    la_l3_ac_port* rp1 = nullptr;
    la_l3_ac_port* rp2 = nullptr;
    la_l3_ac_port* rp3 = nullptr;

    la_mpls_tunnel* mpls_tunnel = nullptr;

    create(&es, vrf0, rp0, rp1, rp2, rp3, mpls_tunnel);

    // Update FIB when there is association between Next Hop IP and MAC address
    update_fib(&es, *vrf0, rp0, rp1, rp2, rp3);

    // Update ILM when there is association between Next Hop IP and MAC address
    update_ilm(&es, *vrf0, rp0, rp1, rp2, rp3, mpls_tunnel);

    return 0;
}
