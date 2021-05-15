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
/// @brief Router with ECMP groups example
///
/// @example ecmp1.cpp
///
/// Creates a router with three L3 ethernet ports, and two ECMP groups.
///
/// @dot
/// digraph ecmp1 {
///     node[shape = box, style="bold, rounded", fontname = "Helvetica:bold", fontsize = 10];
///     edge [tailport="s", headport="n"];
///     vrf0[label = "Router"];
///     rp1 [label = "L3 AC port 1"];
///     rp2 [label = "L3 AC port 2"];
///     rp3 [label = "L3 AC port 3"];
///     np1 [label = "NP 1"];
///     np2 [label = "NP 2"];
///     np3 [label = "NP 3"];
///     {rank=same; rp1; rp2; rp2};
///     {rank=same; np1; np2; np3};
///     vrf0->{rp1 rp2 rp3};
///     rp1->np1;
///     rp2->np2;
///     rp3->np3;
/// }
/// @enddot
///
/// ### Routing Table: #
/// | Prefix             | Next Hop          | Destination                  |
/// | :-----------       | :---              | :---:                        |
/// | 192.168. 12.100/32 | Directly attached | L3 AC 0/00:00:5E:00:53:F1    |
/// | 192.168. 11.  0/24 | Directly attached | CPU                          |
/// | 192.168. 12.  0/24 | Directly attached | CPU                          |
/// | 192.168.111.  0/24 | ------            | ECMP group 1                 |
/// |   0.  0.  0.  0/0  | ------            | ECMP group 2                 |
///
/// ### ECMP groups: #
/// | Group              | L3 destinations                                  | Load balancing        |
/// | :-----------       | :---                                             | :---:                 |
/// | ecmp_group1        | Eth0/00:00:5E:00:53:F1, Eth1/00:00:5E:00:53:F2   | Consistent, Hash A    |
/// | ecmp_group2        | Eth0/00:00:5E:00:53:F1, Eth2/00:00:5E:00:53:F3   | Dynamic, Hash B       |

#include "example_system.h"

#include "api/npu/la_ecmp_group.h"
#include "api/npu/la_ethernet_port.h"
#include "api/npu/la_l3_ac_port.h"
#include "api/npu/la_next_hop.h"
#include "api/npu/la_vrf.h"
#include "api/types/la_ip_types.h"

using namespace silicon_one;

la_l3_ac_port* l3ap0 = nullptr;
la_l3_ac_port* l3ap1 = nullptr;
la_l3_ac_port* l3ap2 = nullptr;

la_l3_ac_port*
create_l3_ac_port(example_system_t* es, la_vrf* vrf, la_ethernet_port* ep, la_mac_addr_t mac)
{
    la_l3_ac_port* port;
    es->xdevice->create_l3_ac_port(es->l3_port_next_gid++,
                                   ep,
                                   EXAMPLE_SYSTEM_AC_PROFILE_VID1,
                                   EXAMPLE_SYSTEM_AC_PROFILE_VID2,
                                   mac,
                                   vrf,
                                   es->default_ingress_qos_profile,
                                   es->default_egress_qos_profile,
                                   la_egress_qos_marking_source_e::QOS_TAG,
                                   port);

    return port;
}

void
create_router(example_system_t* es, la_vrf*& vrf1)
{
    // Create router
    es->xdevice->create_vrf(es->vrf_next_gid++, vrf1);

    // Create L3 Ethernet port 0
    la_mac_addr_t mac_addr = {.flat = 0};
    l3ap0 = create_l3_ac_port(es, vrf1, es->l2_ethernet_ports[0], mac_addr);

    // set port parameters
    la_vlan_tag_t vlan_out_tag = {.tpid = 0x8100, .tci = {.fields = {.pcp = 0, .dei = 0, .vid = 5}}};
    l3ap0->set_egress_vlan_tag(vlan_out_tag, LA_VLAN_TAG_UNTAGGED);

    // Create L3 Ethernet port 1
    l3ap1 = create_l3_ac_port(es, vrf1, es->l2_ethernet_ports[1], mac_addr);

    // Create L3 Ethernet port 2
    l3ap2 = create_l3_ac_port(es, vrf1, es->l2_ethernet_ports[2], mac_addr);

    la_ipv4_prefix_t ip_and_prefix1 = la_ipv4_prefix_from_string("192.168.11.0/24");
    vrf1->add_ipv4_route(ip_and_prefix1, LA_L3_DESTINATION_CPU, 0 /* user-data */, false /* latency_sensitive */);

    la_ipv4_prefix_t ip_and_prefix2 = la_ipv4_prefix_from_string("192.168.12.0/24");
    vrf1->add_ipv4_route(ip_and_prefix2, LA_L3_DESTINATION_CPU, 0 /* user-data */, false /* latency_sensitive */);
}

void
create_next_hops(example_system_t* es, la_next_hop*& nh1, la_next_hop*& nh2, la_next_hop*& nh3)
{
    la_mac_addr_t mac_addr_arp1 = la_mac_addr_from_string("00:00:5E:00:53:F1");
    es->xdevice->create_next_hop(es->next_hop_next_gid++, mac_addr_arp1, l3ap0, nh1);

    la_mac_addr_t mac_addr_arp2 = la_mac_addr_from_string("00:00:5E:00:53:F2");
    es->xdevice->create_next_hop(es->next_hop_next_gid++, mac_addr_arp2, l3ap1, nh2);

    la_mac_addr_t mac_addr_arp3 = la_mac_addr_from_string("00:00:5E:00:53:F3");
    es->xdevice->create_next_hop(es->next_hop_next_gid++, mac_addr_arp3, l3ap2, nh3);
}

void
create_ecmp_groups(example_system_t* es,
                   la_ecmp_group* ecmp_group1,
                   la_ecmp_group* ecmp_group2,
                   la_next_hop* nh1,
                   la_next_hop* nh2,
                   la_next_hop* nh3)
{
    es->xdevice->create_ecmp_group(ecmp_group1);
    ecmp_group1->add_member(nh1);
    ecmp_group1->add_member(nh2);
    ecmp_group1->set_lb_mode(la_lb_mode_e::CONSISTENT);
    ecmp_group1->set_lb_hash(la_lb_hash_e::A);

    es->xdevice->create_ecmp_group(ecmp_group2);
    ecmp_group2->add_member(nh1);
    ecmp_group2->add_member(nh3);
    ecmp_group2->set_lb_mode(la_lb_mode_e::DYNAMIC);
    ecmp_group2->set_lb_hash(la_lb_hash_e::B);
}

void
update_fib(example_system_t* es,
           la_vrf& vrf1,
           la_ecmp_group* ecmp_group1,
           la_ecmp_group* ecmp_group2,
           la_next_hop* nh1,
           la_next_hop* nh2,
           la_next_hop* nh3)
{
    // Add routes
    la_ipv4_prefix_t prefix3 = la_ipv4_prefix_from_string("192.168.12.100/32");
    vrf1.add_ipv4_route(prefix3, nh1, 0 /* user-data */, false /* latency_sensitive */);

    la_ipv4_prefix_t prefix1 = la_ipv4_prefix_from_string("192.168.111.0/24");
    vrf1.add_ipv4_route(prefix1, ecmp_group1, 0 /* user-data */, false /* latency_sensitive */);

    la_ipv4_prefix_t prefix2 = la_ipv4_prefix_from_string("0.0.0.0/0");
    vrf1.add_ipv4_route(prefix2, ecmp_group2, 0 /* user-data */, false /* latency_sensitive */);
}

int
main()
{
    example_system_t es;

    la_vrf* vrf1 = nullptr;
    la_ecmp_group* ecmp_group1 = nullptr;
    la_ecmp_group* ecmp_group2 = nullptr;
    la_next_hop* nh1 = nullptr;
    la_next_hop* nh2 = nullptr;
    la_next_hop* nh3 = nullptr;

    example_system_init(&es);

    // Create and set the basic FIB
    create_router(&es, vrf1);

    // Create next hops and ECMP groups
    create_next_hops(&es, nh1, nh2, nh3);
    create_ecmp_groups(&es, ecmp_group1, ecmp_group2, nh1, nh2, nh3);

    // Update FIB when there is association between Next Hop IP and MAC address
    update_fib(&es, *vrf1, ecmp_group1, ecmp_group2, nh1, nh2, nh3);

    return 0;
}
