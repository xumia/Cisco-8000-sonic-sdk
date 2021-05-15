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
/// @brief Switch-Router example
///
/// @example switch_router1.cpp
/// Creates a virtual simple switch with two ports and a router with three L3 ports.
///
/// ## Layer 2 ##
/// - Switch port 1 is a single-device, single SP port. The port default VLAN is 5.
/// - Switch port 2 is a single-device, single SP port. It has no default VLAN.
/// - This example uses the simple bridging model, where all VLAN 5 traffic is associated with one switch.
///
/// ## Layer 3 ##
/// - Router port 1 is a "simple" Ethernet port from a single SP port.
/// - Router port 2 is a "simple" Ethernet port from a single SP port.
/// - Router port 3 connected to the Switch.
///
/// @dot
/// digraph switch_router1{
///     node[shape = box, style="bold, rounded", fontname = "Helvetica:bold", fontsize = 10];
///     edge [tailport="s", headport="n"];
///     vrf0[label = "Router"];
///     rp0 [label = "L3 AC port 0"];
///     rp1 [label = "L3 AC port 1"];
///     rp2 [label = "SVI port"];
///     sw  [label = "Switch\nVLAN 5"];
///     ep0 [label = "Eth 0"];
///     ep1 [label = "Eth 1"];
///     sp0 [label = "SP 0"];
///     sp1 [label = "SP 1"];
///     sp2 [label = "SP 2"];
///     sp3 [label = "SP 3"];
///     { rank=same; rp0; rp1; rp2};
///     { rank=same; ep0; ep1};
///     { rank=same; sp0; sp1; sp2; sp3};
///     vrf0-> {rp0 rp1 rp2};
///     rp0->sp0;
///     rp1->sp1;
///     rp2->sw->{ep0 ep1};
///     ep0->sp2;
///     ep1->sp3;
/// }
/// @enddot
///
/// ### Routing Table: #
/// | Prefix             | Next Hop IP       | Next Hop MAC      | Router port |
/// | :-----------       | :---              | :---              | :---:       |
/// | 192.168. 12.100/32 | Directly attached | 00:00:5E:00:53:F2 | L3 AC 1     |
/// | 192.168. 11.  0/24 | Directly attached |                   | L3 AC 0     |
/// | 192.168. 12.  0/24 | Directly attached |                   | L3 AC 1     |
/// | 192.168. 13.  0/24 | Directly attached |                   | SVI         |
/// | 192.168.111.  0/24 | 192.168.11.100    | 00:00:5E:00:53:F1 | L3 AC 0     |
/// |   0.  0.  0.  0/0  | 192.168.13.100    | 00:00:5E:00:53:F3 | SVI         |

#include "example_system.h"

#include "api/npu/la_ethernet_port.h"
#include "api/npu/la_l3_ac_port.h"
#include "api/npu/la_next_hop.h"
#include "api/npu/la_svi_port.h"
#include "api/npu/la_switch.h"
#include "api/npu/la_vrf.h"
#include "api/system/la_device.h"
#include "api/types/la_ip_types.h"

using namespace silicon_one;

la_l3_ac_port* l3ap0 = nullptr;
la_l3_ac_port* l3ap1 = nullptr;

void
create_switch(example_system* es, la_switch_gid_t switch_id, la_vlan_id_t vlan_id)
{
    // Set port VLAN on one of the ethernet ports
    es->l2_ethernet_ports[0]->set_port_vlan(vlan_id);

    // Create switch
    la_switch* sw = nullptr;
    es->xdevice->create_switch(switch_id, sw);
}

void
create(example_system* es, la_vrf*& vrf1, la_svi_port*& svi1)
{
    la_switch_gid_t switch_id = es->switch_next_gid++;
    la_mac_addr_t mac_addr = {.flat = 0};
    la_vlan_id_t vlan_id = 5;

    // Phase 1: Create the ethernet ports and switches that we want to connect to the router
    create_switch(es, switch_id, vlan_id);

    // Phase 2: Create the Router and the ports
    // Create Router
    es->xdevice->create_vrf(es->vrf_next_gid++, vrf1);

    // L3 AC port 0
    es->xdevice->create_l3_ac_port(es->l3_port_next_gid++,
                                   es->l2_ethernet_ports[0],
                                   EXAMPLE_SYSTEM_AC_PROFILE_VID1,
                                   EXAMPLE_SYSTEM_AC_PROFILE_VID2,
                                   mac_addr,
                                   vrf1,
                                   es->default_ingress_qos_profile,
                                   es->default_egress_qos_profile,
                                   la_egress_qos_marking_source_e::QOS_TAG,
                                   l3ap0);

    // L3 AC port 1
    es->xdevice->create_l3_ac_port(es->l3_port_next_gid++,
                                   es->l2_ethernet_ports[1],
                                   EXAMPLE_SYSTEM_AC_PROFILE_VID1,
                                   EXAMPLE_SYSTEM_AC_PROFILE_VID2,
                                   mac_addr,
                                   vrf1,
                                   es->default_ingress_qos_profile,
                                   es->default_egress_qos_profile,
                                   la_egress_qos_marking_source_e::QOS_TAG,
                                   l3ap1);

    // set port parameters
    la_vlan_tag_t vlan_out_tag = {.tpid = 0x8100, .tci = {.fields = {.pcp = 0, .dei = 0, .vid = vlan_id}}};
    l3ap0->set_egress_vlan_tag(vlan_out_tag, LA_VLAN_TAG_UNTAGGED);

    la_ipv4_prefix_t ip_and_prefix1 = la_ipv4_prefix_from_string("192.168.11.0/24");
    vrf1->add_ipv4_route(ip_and_prefix1, LA_L3_DESTINATION_CPU, 0 /* user-data */, false /* latency_sensitive */);

    la_ipv4_prefix_t ip_and_prefix2 = la_ipv4_prefix_from_string("192.168.12.0/24");
    vrf1->add_ipv4_route(ip_and_prefix2, LA_L3_DESTINATION_CPU, 0 /* user-data */, false /* latency_sensitive */);

    // SVI port, from Switch
    la_switch* sw1 = es->xdevice->get_switch_by_id(switch_id);
    la_mac_addr_t mac_addr3 = la_mac_addr_from_string("00:00:5E:00:53:03");
    es->xdevice->create_svi_port(es->l3_port_next_gid++,
                                 sw1,
                                 vrf1,
                                 mac_addr3,
                                 es->default_ingress_qos_profile,
                                 es->default_egress_qos_profile,
                                 la_egress_qos_marking_source_e::QOS_TAG,
                                 svi1);

    la_ipv4_prefix_t ip_and_prefix3 = la_ipv4_prefix_from_string("192.168.13.0/24");
    vrf1->add_ipv4_route(ip_and_prefix3, LA_L3_DESTINATION_CPU, 0 /* user-data */, false /* latency_sensitive */);
}

void
update_fib(example_system* es, la_vrf& vrf1, la_svi_port* svi1)
{
    // Add routes
    la_mac_addr_t mac_addr_arp1 = la_mac_addr_from_string("00:00:5E:00:53:F1"); // MAC of 192.168.11.100
    la_next_hop* nh1 = nullptr;
    es->xdevice->create_next_hop(es->next_hop_next_gid++, mac_addr_arp1, l3ap0, nh1);
    la_ipv4_prefix_t prefix1 = la_ipv4_prefix_from_string("192.168.111.0/24");
    vrf1.add_ipv4_route(prefix1, nh1, 0 /* user-data */, false /* latency sensitive */);
    la_mac_addr_t mac_addr_arp2 = la_mac_addr_from_string("00:00:5E:00:53:F3"); // MAC of 192.168.13.100
    la_next_hop* nh2 = nullptr;
    es->xdevice->create_next_hop(es->next_hop_next_gid++, mac_addr_arp2, svi1, nh2);
    la_ipv4_prefix_t prefix2 = la_ipv4_prefix_from_string("0.0.0.0/0");
    vrf1.add_ipv4_route(prefix2, nh2, 0 /* user-data */, false /* latency_sensitive */);
    // Add directly attached host
    la_mac_addr_t mac_addr_arp3 = la_mac_addr_from_string("00:00:5E:00:53:F2"); // MAC of 192.168.12.100
    la_next_hop* nh3 = nullptr;
    es->xdevice->create_next_hop(es->next_hop_next_gid++, mac_addr_arp3, l3ap1, nh3);
    la_ipv4_prefix_t prefix3 = la_ipv4_prefix_from_string("192.168.12.100/32");
    vrf1.add_ipv4_route(prefix3, nh3, 0 /* user-data */, false /* latency_sensitive */);
}

int
main()
{
    example_system es;

    example_system_init(&es);

    la_vrf* vrf1 = nullptr;
    la_svi_port* svi1 = nullptr;

    // Create and set the basic FIB
    create(&es, vrf1, svi1);

    // Update FIB when there is association between Next Hop IP and MAC address
    update_fib(&es, *vrf1, svi1);

    return 0;
}
