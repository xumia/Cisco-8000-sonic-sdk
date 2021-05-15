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
/// @brief Two switches with two ports each example
///
/// @example switch2.cpp
///
/// Creates two virtual switchs with two ports each.
///
/// - Ethernet port 1 is a single-device, single SP port.
///               Packets with a single VLAN tag, VLAN = 8, map to switch #1.
///               Packets with two VLAN tags, Outer = 5, Inner = 3, map to switch #2.
///
/// - Ethernet port 2 is a single-device, single SP port.
///               Packets with a no VLAN tag map to switch #1.
///               Packets with two VLAN tags, Outer = 5, Inner = 8, map to switch #2.
/// @dot
/// digraph switch2{
///     splines=polyline;
///     concentrate="true";
///     edge [tailport="s", headport="n"];
///     node[shape = box, style="bold, rounded", fontname = "Helvetica:bold", fontsize = 10];
///     sw1 [label = "Switch 1", color="blue"];
///     sw2 [label = "Switch 2", color="green"];
///     ep1 [label = "Eth 1"];
///     ep2 [label = "Eth 2"];
///     sp1 [label = "SP 1"];
///     sp2 [label = "SP 2"];
///     { rank=same; sp1; sp2};
///     sw1->ep1 [label="VLAN=8", color="blue", fontcolor="blue"];
///     sw1->ep2 [label="no VLAN", color="blue", fontcolor="blue"];
///     sw2->ep1 [label="Outer VLAN=5\nInner VLAN=3", color="green", fontcolor="green"];
///     sw2->ep2 [label="Outer VLAN=5\nInner VLAN=8", color="green", fontcolor="green"];
///     ep1->sp1;
///     ep2->sp2;
/// }
/// @enddot

#include "example_system.h"

#include "api/npu/la_ac_profile.h"
#include "api/npu/la_ethernet_port.h"
#include "api/npu/la_l2_service_port.h"
#include "api/npu/la_switch.h"
#include "api/system/la_device.h"
#include "api/types/la_common_types.h"

using namespace silicon_one;

void
create_ethernet_ports(example_system_t* es, la_ethernet_port*& ep1, la_ethernet_port*& ep2)
{
    // Create ethernet ports.
    // ep1 is an AC ethernet port, composed only of physical port 1
    es->xdevice->create_ethernet_port(es->system_ports[0], la_ethernet_port::port_type_e::AC, ep1);

    // ep2 is an AC ethernet port, composed only of physical port 2
    es->xdevice->create_ethernet_port(es->system_ports[1], la_ethernet_port::port_type_e::AC, ep2);
}

void
configure_ac_profile(la_device* xdevice, la_ethernet_port* ep1, la_ethernet_port* ep2)
{
    // Create AC profile
    la_ac_profile* ac_profile = nullptr;
    xdevice->create_ac_profile(ac_profile);

    ac_profile->set_key_selector_per_format(LA_PACKET_VLAN_FORMAT_802Q, la_ac_profile::key_selector_e::PORT_VLAN);
    ac_profile->set_key_selector_per_format(LA_PACKET_VLAN_FORMAT_802QinQ, la_ac_profile::key_selector_e::PORT_VLAN_VLAN);

    ep1->set_ac_profile(ac_profile);
    ep2->set_ac_profile(ac_profile);
}

void
create_sw1(example_system_t* es, la_ethernet_port* ep1, la_ethernet_port* ep2)
{
    // Create switch
    la_switch_gid_t switch_id = es->switch_next_gid++;
    la_switch* sw = nullptr;
    es->xdevice->create_switch(switch_id, sw);

    // Create switch ports
    la_l2_service_port* ac1 = nullptr;
    la_l2_service_port* ac2 = nullptr;

    es->xdevice->create_ac_l2_service_port(es->l2_port_next_gid++,
                                           ep1,
                                           8 /* outer VID */,
                                           LA_VLAN_ID_INVALID /* inner VID */,
                                           es->default_ingress_qos_profile,
                                           es->default_egress_qos_profile,
                                           la_egress_qos_marking_source_e::QOS_TAG,
                                           ac1);

    ac1->attach_to_switch(sw);

    es->xdevice->create_ac_l2_service_port(es->l2_port_next_gid++,
                                           ep2,
                                           5 /* outer VID */,
                                           3 /* inner VID */,
                                           es->default_ingress_qos_profile,
                                           es->default_egress_qos_profile,
                                           la_egress_qos_marking_source_e::QOS_TAG,
                                           ac2);

    ac2->attach_to_switch(sw);
}

void
create_sw2(example_system_t* es, la_ethernet_port* ep1, la_ethernet_port* ep2)
{
    // Create switch
    la_switch_gid_t switch_id = es->switch_next_gid++;
    la_switch* sw = nullptr;
    es->xdevice->create_switch(switch_id, sw);

    // Create switch ports
    la_l2_service_port* ac1 = nullptr;
    la_l2_service_port* ac2 = nullptr;

    es->xdevice->create_ac_l2_service_port(es->l2_port_next_gid++,
                                           ep1,
                                           8 /* outer VID */,
                                           LA_VLAN_ID_INVALID /* inner VID */,
                                           es->default_ingress_qos_profile,
                                           es->default_egress_qos_profile,
                                           la_egress_qos_marking_source_e::QOS_TAG,
                                           ac1);
    ac1->attach_to_switch(sw);

    es->xdevice->create_ac_l2_service_port(es->l2_port_next_gid++,
                                           ep2,
                                           5 /* outer VID */,
                                           3 /* inner VID */,
                                           es->default_ingress_qos_profile,
                                           es->default_egress_qos_profile,
                                           la_egress_qos_marking_source_e::QOS_TAG,
                                           ac2);
    ac2->attach_to_switch(sw);
}

int
main()
{
    example_system_t es;

    example_system_init(&es);

    la_ethernet_port* ep1 = nullptr;
    la_ethernet_port* ep2 = nullptr;

    create_ethernet_ports(&es, ep1, ep2);
    configure_ac_profile(es.xdevice, ep1, ep2);

    create_sw1(&es, ep1, ep2);
    create_sw2(&es, ep1, ep2);

    return 0;
}
