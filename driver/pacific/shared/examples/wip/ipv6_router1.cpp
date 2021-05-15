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
/// @brief IPv6 router with three L3 ports example
///
/// @example ipv6_router1.cpp
/// Creates an IPv6 router with three L3 ports.
///
/// ## Layer 3 #
/// Ports 0-2 are "simple" Ethernet port from a single SP port.
///
/// In this example each port has different global unique network prefix and the link local address is the same.
/// In this example all ports are IPv6 only.
///
/// ### Port information: #
/// | Port                | 1                     | 2                     | 3                     |
/// | :-----------        | :---                  | :---                  | :---                  |
/// | MAC                 | 00:00:5E:00:53:01     | 00:00:5E:00:53:02     | 00:00:5E:00:53:03     |
/// | Link-local address  | FE80::1/64            | FE80::1/64            | FE80::1/64            |
/// | Global address      | 2001:DB8:CAFE:1::1/64 | 2001:DB8:CAFE:2::1/64 | 2001:DB8:CAFE:3::1/64 |
///
/// @dot
/// digraph ipv6_router1{
///     node[shape = box, style="bold, rounded", fontname = "Helvetica:bold", fontsize = 10];
///     edge [tailport="s", headport="n", splines=""];
///     vrf0[label = "Router"];
///     rp0 [label = "L3 AC port 0"];
///     rp1 [label = "L3 AC port 1"];
///     rp2 [label = "L3 AC port 2"];
///     sp0 [label = "SP 0"];
///     sp1 [label = "SP 1"];
///     sp2 [label = "SP 2"];
///     vrf0-> {rp0 rp1 rp2};
///     rp0->sp0;
///     rp1->sp1;
///     rp2->sp2;
/// }
/// @enddot

#include "example_system.h"

#include "api/npu/la_ethernet_port.h"
#include "api/npu/la_l2_destination.h"
#include "api/npu/la_l3_ac_port.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_next_hop.h"
#include "api/npu/la_switch.h"
#include "api/npu/la_vrf.h"
#include "api/system/la_device.h"
#include "api/types/la_ip_types.h"

using namespace silicon_one;

void
add_router_port(example_system_t* es,
                la_vrf* vrf,
                la_l3_ac_port*& rport,
                const char* mac_addr_str,
                const char* ipv6_global_str,
                la_ethernet_port* ep)
{
    la_mac_addr_t mac_addr = la_mac_addr_from_string(mac_addr_str);
    es->xdevice->create_l3_ac_port(es->l3_port_next_gid++,
                                   ep,
                                   EXAMPLE_SYSTEM_AC_PROFILE_VID1,
                                   EXAMPLE_SYSTEM_AC_PROFILE_VID2,
                                   mac_addr,
                                   vrf,
                                   es->default_ingress_qos_profile,
                                   es->default_egress_qos_profile,
                                   la_egress_qos_marking_source_e::QOS_TAG,
                                   rport);

    // set L3 port parameters
    rport->set_protocol_enabled(la_l3_protocol_e::IPV4_UC, false);
    rport->set_protocol_enabled(la_l3_protocol_e::IPV4_MC, false);
    rport->set_protocol_enabled(la_l3_protocol_e::MPLS, false);

    // Add global unique address
    la_ipv6_prefix_t ip_prefix_global = la_ipv6_prefix_from_string(ipv6_global_str);
    vrf->add_ipv6_route(ip_prefix_global, LA_L3_DESTINATION_CPU, 0 /* user-data */, false /* latency_sensitive */);

    // Add Link-local trap
    rport->set_event_enabled(LA_EVENT_L3_LOCAL_SUBNET, true);
}

void
create(example_system_t* es, la_vrf*& vrf0, la_l3_ac_port*& rp0, la_l3_ac_port*& rp1, la_l3_ac_port*& rp2)
{
    la_vrf_gid_t router_id = 1;

    // Phase 0: General settings
    // Enable trap for every packet with IPv6 extension header of Hop-by-hop option
    es->xdevice->set_ipv6_ext_header_trap_enabled(LA_IPV6_EXT_HDR_HOP_BY_HOP, true);

    // Phase 1: Create the Router and the ports
    // Create Router
    es->xdevice->create_vrf(router_id, vrf0);

    // L3 AC port 0, from Ethernet Port 0 (IPv6 only)
    add_router_port(es, vrf0, rp0, "00:00:5E:00:53:01", "2001:DB8:CAFE:1::1/64", es->l2_ethernet_ports[0]);

    // L3 AC port 1, from Ethernet Port 1 (IPv6 only)
    add_router_port(es, vrf0, rp1, "00:00:5E:00:53:02", "2001:DB8:CAFE:2::1/64", es->l2_ethernet_ports[1]);

    // L3 AC port 2, from Ethernet Port 2 (IPv6 only)
    add_router_port(es, vrf0, rp2, "00:00:5E:00:53:03", "2001:DB8:CAFE:3::1/64", es->l2_ethernet_ports[2]);
}

void
configure_events(example_system_t* es)
{
    es->xdevice->set_trap_configuration(LA_EVENT_L3_LOCAL_SUBNET,
                                        0 /* priority */,
                                        nullptr /* counters */,
                                        es->punt_destination,
                                        false /* skip_inject_up_packets */,
                                        false /* skip_p2p_packets */,
                                        true /* overwrite_phb */,
                                        0 /* tc */);
}

void
activate(example_system_t* es, la_vrf& vrf0, la_l3_ac_port* rp0, la_l3_ac_port* rp1, la_l3_ac_port* rp2)
{
    // Add routes
    la_mac_addr_t mac_addr_nd1 = la_mac_addr_from_string("00:00:5E:00:53:31"); // MAC of 2001:DB8:CAFE:3::100
    la_ipv6_prefix_t prefix1 = la_ipv6_prefix_from_string("2001:DB8:CAFE:10::/64");
    la_next_hop* nh1 = nullptr;
    es->xdevice->create_next_hop(1 /* next hop GID */, mac_addr_nd1, rp2, nh1);
    vrf0.add_ipv6_route(prefix1, nh1, 0 /* user-data */, false, /* latency_sensitive */);

    la_mac_addr_t mac_addr_nd2 = la_mac_addr_from_string("00:00:5E:00:53:11"); // MAC of 2001:DB8:CAFE:1::100
    la_ipv6_prefix_t prefix2 = la_ipv6_prefix_from_string("2001:DB8::/32");
    la_next_hop* nh2 = nullptr;
    es->xdevice->create_next_hop(2 /* next hop GID */, mac_addr_nd2, rp0, nh2);
    vrf0.add_ipv6_route(prefix2, nh2, 0 /* user-data */, false /* latency_sensitive */);
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

    create(&es, vrf0, rp0, rp1, rp2);
    configure_events(&es);
    activate(&es, *vrf0, rp0, rp1, rp2);

    return 0;
}
