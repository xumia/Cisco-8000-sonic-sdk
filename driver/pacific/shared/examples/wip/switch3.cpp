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
/// @brief Switch with broadcast, multicast and flood configuration example
///
/// @example switch3.cpp
///
/// Creates virtual switch with three ports, 1 AC and 2 NP.
/// The purpose of this example is to showcase how flooding is configured.
///
/// - Flood packets are sent to ports 2 and 3.
/// @dot
/// digraph switch3{
///     node[shape = box, style="bold, rounded", fontname = "Helvetica:bold", fontsize = 10];
///     edge [tailport="s", headport="n"];
///     sw  [label = "Switch"];
///     ap1 [label = "AC port 1"];
///     ep1 [label = "Eth 1"];
///     ep2 [label = "Eth 2"];
///     ep3 [label = "Eth 3"];
///     np1 [label = "NP 1"];
///     np2 [label = "NP 2"];
///     np3 [label = "NP 3"];
///     { rank=same; np1; np2, np3};
///     { rank=same; ep1; ep2, ep3};
///     sw->{ap1, ep2, ep3};
///     ap1->ep1 [label = "Outer VID=5\nInner VID=3"];
///     ep1->np1;
///     ep2->np2;
///     ep3->np3;
/// }
/// @enddot

#include "example_system.h"

#include "api/npu/la_ac_profile.h"
#include "api/npu/la_ethernet_port.h"
#include "api/npu/la_l2_destination.h"
#include "api/npu/la_l2_multicast_group.h"
#include "api/npu/la_l2_service_port.h"
#include "api/npu/la_switch.h"
#include "api/system/la_device.h"
#include "api/types/la_common_types.h"

using namespace silicon_one;

void
create_ethernet_ports(example_system_t* es, la_ethernet_port*& ep1, la_ethernet_port*& ep2, la_ethernet_port*& ep3)
{
    // Create ethernet ports.
    // ep1 is an AC ethernet port, composed only of physical port 1
    es->xdevice->create_ethernet_port(es->system_ports[0], la_ethernet_port::port_type_e::AC, ep1);

    // ep2 is a simple ethernet port, composed only of physical port 2
    es->xdevice->create_ethernet_port(es->system_ports[1], la_ethernet_port::port_type_e::SIMPLE, ep2);

    // ep3 is a simple ethernet port, composed only of physical port 3
    es->xdevice->create_ethernet_port(es->system_ports[2], la_ethernet_port::port_type_e::SIMPLE, ep3);
}

void
configure_ac_profile(la_device* xdevice, la_ethernet_port* ep1)
{
    // Create AC profile
    la_ac_profile* ac_profile = nullptr;
    xdevice->create_ac_profile(ac_profile);

    ac_profile->set_key_selector_per_format(LA_PACKET_VLAN_FORMAT_802Q, la_ac_profile::key_selector_e::PORT_VLAN);
    ac_profile->set_key_selector_per_format(LA_PACKET_VLAN_FORMAT_802QinQ, la_ac_profile::key_selector_e::PORT_VLAN_VLAN);

    ep1->set_ac_profile(ac_profile);
}

void
create_sw1(example_system_t* es, la_switch* sw, la_l2_service_port*& ap1, la_ethernet_port* ep1)
{
    // Create switch
    la_switch_gid_t switch_id = es->switch_next_gid++;
    es->xdevice->create_switch(switch_id, sw);

    // Create AC switch port
    es->xdevice->create_ac_l2_service_port(es->l2_port_next_gid++,
                                           ep1,
                                           5 /* outer VID */,
                                           3 /* inner VID */,
                                           es->default_ingress_qos_profile,
                                           es->default_egress_qos_profile,
                                           la_egress_qos_marking_source_e::QOS_TAG,
                                           ap1);

    ap1->attach_to_switch(sw);
}

void
configure_flooding(example_system_t* es, la_switch* sw, la_l2_service_port* ap1, la_ethernet_port* ep2, la_ethernet_port* ep3)
{
    la_l2_multicast_group* flood_group = nullptr;

    // Set the switch's flood group to {ep2, ep3}
    es->xdevice->create_l2_multicast_group(es->multicast_next_gid++, la_replication_paradigm_e::INGRESS, flood_group);
    flood_group->add(ep2);
    flood_group->add(ep3);

    sw->set_flood_destination(flood_group);
}

int
main()
{
    example_system_t es;

    example_system_init(&es);

    la_ethernet_port* ep1 = nullptr;
    la_ethernet_port* ep2 = nullptr;
    la_ethernet_port* ep3 = nullptr;
    la_l2_service_port* ap1 = nullptr;
    la_switch* sw = nullptr;

    create_ethernet_ports(&es, ep1, ep2, ep3);
    configure_ac_profile(es.xdevice, ep1);

    create_sw1(&es, sw, ap1, ep1);
    configure_flooding(&es, sw, ap1, ep2, ep3);

    return 0;
}
