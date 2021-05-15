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
/// @brief Point-to-Point AC service example
///
/// @example p2p_ac1.cpp
///
/// Creates a Point-to-Point AC service.
///
/// Traffic is serviced between Ethernet port 1 (using VLAN 5) and Ethernet port 2 (using VLAN 8).
///
/// @dot
/// digraph p2p_ac1{
///     rankdir=LR;
///     node[shape = box, style="bold, rounded", fontname = "Helvetica:bold", fontsize = 10];
///     edge [tailport="e", headport="w", arrowhead="none"];
///     ep1 [label = "Eth 1"];
///     ep2 [label = "Eth 2"];
///     ac1 [label = "AC 1"];
///     ac2 [label = "AC 2"];
///     ep1->ac1 [label = "VLAN 5"];
///     ac1->ac2;
///     ac2->ep2 [label = "VLAN 8"];
/// }
/// @enddot

#include "example_system.h"

#include "api/npu/la_ac_profile.h"
#include "api/npu/la_ethernet_port.h"
#include "api/npu/la_l2_service_port.h"
#include "api/types/la_common_types.h"

#include <iostream>
using namespace std;

using namespace silicon_one;

la_l2_service_port* acp1 = nullptr;
la_l2_service_port* acp2 = nullptr;

void
create_ac_ports(example_system* es)
{
    la_status status = LA_STATUS_SUCCESS;

    // Ethernet ports
    la_ethernet_port* ac1_ep = es->slice[0].ifg[0].l2_ethernet_ports[0];
    la_ethernet_port* ac2_ep = es->slice[1].ifg[1].l2_ethernet_ports[1];

    // Create AC port 1
    status = es->device->create_ac_l2_service_port(es->l2_port_next_gid++,
                                                   ac1_ep,
                                                   5 /* outer VID */,
                                                   LA_VLAN_ID_INVALID /* inner VID */,
                                                   es->default_filter_group,
                                                   es->default_ingress_qos_profile,
                                                   es->default_egress_qos_profile,
                                                   acp1);
    assert_status(status, "Failed to create AC port 1.");

    // Set VLAN editing: drop existing VLAN and apply new tag on egress
    la_vlan_tag_t acp1_out_tag = {.tpid = 0x8100, .tci = {.fields = {.pcp = 0, .dei = 0, .vid = 5}}};
    la_vlan_edit_command acp1_egress_edit_cmd(1 /* num tags to pop */, acp1_out_tag);

    status = acp1->set_egress_vlan_edit_command(acp1_egress_edit_cmd);
    assert_status(status, "Failed to configure egress VLAN editing on AC port 1.");

    status = acp1->set_stp_state(la_port_stp_state_e::FORWARDING);
    assert_status(status, "Failed to configure STP state on AC port 1.");

    // Create AC port 2
    status = es->device->create_ac_l2_service_port(es->l2_port_next_gid++,
                                                   ac2_ep,
                                                   8 /* outer VID */,
                                                   LA_VLAN_ID_INVALID /* inner VID */,
                                                   es->default_filter_group,
                                                   es->default_ingress_qos_profile,
                                                   es->default_egress_qos_profile,
                                                   acp2);
    assert_status(status, "Failed to create AC port 2.");

    // Set VLAN editing: drop existing VLAN and apply new tag on egress
    la_vlan_tag_t acp2_out_tag = {.tpid = 0x8100, .tci = {.fields = {.pcp = 0, .dei = 0, .vid = 8}}};
    la_vlan_edit_command acp2_egress_edit_cmd(1 /* num tags to pop */, acp2_out_tag);

    status = acp2->set_egress_vlan_edit_command(acp2_egress_edit_cmd);
    assert_status(status, "Failed to configure egress VLAN editing on AC port 2.");

    status = acp2->set_stp_state(la_port_stp_state_e::FORWARDING);
    assert_status(status, "Failed to configure STP state on AC port 2.");
}

void
connect_ac_ports(example_system* es)
{
    acp1->set_destination(acp2);
    acp2->set_destination(acp1);
}

void
create_topology(example_system* es)
{
    create_ac_ports(es);
    connect_ac_ports(es);

    es->device->flush();
}

void
run_packet(example_system* es)
{
    bool success = true;

    const char ingress_packet[]
        = "cafecafecafedeaddeaddead810050050800450000280001000040067ccd7f0000017f00000100140050000000000000000050022000917c0000";
    const char egress_packet[]
        = "cafecafecafedeaddeaddead810050080800450000280001000040067ccd7f0000017f00000100140050000000000000000050022000917c0000";

    // Inject packet to simulation
    sim_packet_info_desc packet_desc = {.packet = ingress_packet, .slice = 0, .ifg = 0, .pif = 0};
    success = es->sim_ifc->inject_packet(packet_desc);
    assert_bool(success, "Failed to inject packet.");

    // Simulate packet
    success = es->sim_ifc->step_packet();
    assert_bool(success, "Failed to simulate packet.");

    // Ensure
    auto packets = es->sim_ifc->get_packets();
    assert_bool(packets.size() == 1, "Number of egress packets should be 1.");

    assert_bool(packets[0].packet == egress_packet, "egress packet different than excepted.");
}

int
main()
{
    example_system* es = create_example_system();

    // Create topology
    create_topology(es);

    // Inject a packet from AC port 1 to AC port 2, and make sure it comes out correctly.
    run_packet(es);

    return 0;
}
