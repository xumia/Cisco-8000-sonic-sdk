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
/// @brief Events example
///
/// @example events1.cpp
///
/// Creates a virtual switch with two ports.
/// ARP packets going through the switch are trapped.
/// DHCPv4 packets going through the switch are snooped.
///
/// @dot
/// digraph switch1{
///     node[shape = box, style="bold, rounded", fontname = "Helvetica:bold", fontsize = 10];
///     edge [tailport="s", headport="n"];
///     sw  [label = "Switch\n VLAN 5"];
///     ep1 [label = "Eth 1\n Port VLAN 5"];
///     ep2 [label = "Eth 2"];
///     np1 [label = "NP 1"];
///     np2 [label = "NP 2"];
///     { rank=same; np1; np2};
///     sw->{ep1 ep2};
///     ep1->np1;
///     ep2->np2;
/// }
/// @enddot

#include "example_system.h"

#include "api/npu/la_ethernet_port.h"
#include "api/npu/la_l2_destination.h"
#include "api/npu/la_switch.h"
#include "api/system/la_l2_mirror_command.h"
#include "api/system/la_l2_punt_destination.h"
#include "api/types/la_common_types.h"

using namespace silicon_one;

const la_vlan_id_t vlan_id = 5;

void
create_switch(example_system_t* es, la_switch*& sw)
{
    // Create switch

    es->xdevice->create_switch(es->switch_next_gid++, sw);

    // Configure ports
    // TBD
}

void
create_punt_inject(example_system_t* es, la_punt_inject_port*& pi_port, la_l2_punt_destination*& p_dest)
{
    // Create punt/inject port
    la_mac_addr_t mac_addr1 = la_mac_addr_from_string("00:00:5E:00:53:F1");
    es->xdevice->create_punt_inject_port(es->system_ports[0], mac_addr1, pi_port);

    // Create punt destination
    la_mac_addr_t mac_addr2 = la_mac_addr_from_string("00:00:5E:00:53:F2");
    es->xdevice->create_l2_punt_destination(pi_port, mac_addr2, p_dest);
}

void
create_mirror_command(example_system_t* es,
                      la_punt_inject_port* pi_port,
                      la_mirror_gid_t mirror_gid,
                      la_l2_mirror_command*& mirror_cmd)
{
    // Create mirror command
    la_mac_addr_t mac_addr3 = la_mac_addr_from_string("00:00:5E:00:53:F3");
    la_vlan_tag_tci_t vlan_tag;
    vlan_tag.fields.vid = vlan_id;
    es->xdevice->create_l2_mirror_command(mirror_gid, pi_port, mac_addr3, vlan_tag, mirror_cmd);
}

void
configure_traps(example_system_t* es, la_switch* sw, la_punt_destination* p_dest)
{
    sw->set_event_enabled(LA_EVENT_ETHERNET_ARP, true);

    es->xdevice->set_trap_configuration(LA_EVENT_ETHERNET_ARP,
                                        5 /* priority */,
                                        nullptr /* counter set */,
                                        p_dest,
                                        false /* skip_inject_up_packets */,
                                        false /* skip_p2p_packets */,
                                        true /* overwrite_phb */,
                                        0 /* tc */);
}

void
configure_snoops(example_system_t* es, la_switch* sw, la_l2_mirror_command* mirror_cmd)
{
    sw->set_event_enabled(LA_EVENT_ETHERNET_DHCPV4_SERVER, true);

    es->xdevice->set_snoop_configuration(LA_EVENT_ETHERNET_DHCPV4_SERVER, 5 /* priority */, mirror_cmd);
}

int
main()
{
    example_system_t es;
    example_system_init(&es);

    la_switch* sw = nullptr;
    create_switch(&es, sw);

    la_punt_inject_port* pi_port = nullptr;
    la_l2_punt_destination* p_dest = nullptr;
    la_l2_mirror_command* mirror_cmd = nullptr;

    la_mirror_gid_t mirror_gid = 10;

    create_punt_inject(&es, pi_port, p_dest);

    create_mirror_command(&es, pi_port, mirror_gid, mirror_cmd);

    configure_traps(&es, sw, p_dest);
    configure_snoops(&es, sw, mirror_cmd);

    return 0;
}
