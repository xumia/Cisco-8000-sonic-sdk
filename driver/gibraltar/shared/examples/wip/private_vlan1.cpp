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
/// @brief Private VLAN example
///
/// @example private_vlan1.cpp
///
/// Private VLAN configuration example.
///
/// Creates virtual switch with five ports.
/// - Port 1 set to promiscuous mode.
/// - Ports 2, 3 are isolated.
/// - Ports 4, 5 are part of the same community.
/// @dot
/// digraph private_vlan1{
///     splines="polyline";
///     node[shape = box, style="bold, rounded", fontname = "Helvetica:bold", fontsize = 10];
///     edge [tailport="s", headport="n"];
///     sw  [label = "Switch\nVLAN 5"];
///     ep1 [label = "Eth 1"];
///     ep2 [label = "Eth 2"];
///     ep3 [label = "Eth 3"];
///     ep4 [label = "Eth 4"];
///     ep5 [label = "Eth 5"];
///     sp1 [label = "SP 1"];
///     sp2 [label = "SP 2"];
///     sp3 [label = "SP 3"];
///     sp4 [label = "SP 4"];
///     sp5 [label = "SP 5"];
///     sw->{ep1 ep2 ep3 ep4 ep5};
///     subgraph cluster1 {
///         style=dotted;
///         label="Promiscuous";
///         labelloc="b";
///         ep1->sp1;
///     }
///     subgraph cluster2 {
///         style=dotted;
///         label="Isolated";
///         labelloc="b";
///         ep2->sp2;
///         ep3->sp3;
///     }
///     subgraph cluster3 {
///         style=dotted;
///         label="Community";
///         labelloc="b";
///         ep4->sp4;
///         ep5->sp5;
///     }
/// }
/// @enddot

#include "example_system.h"

#include "api/npu/la_ethernet_port.h"
#include "api/npu/la_filter_group.h"
#include "api/npu/la_switch.h"
#include "api/system/la_device.h"
#include "api/types/la_common_types.h"

using namespace silicon_one;

la_switch_gid_t switch_gids = 1;

la_switch* sw = nullptr;

void
create_sw(example_system* es)
{
    // Create switch
    la_switch_gid_t switch_id = switch_gids++;
    es->xdevice->create_switch(switch_id, sw);
}

void
configure_filtering(example_system* es)
{
    // To model simple Private VLAN configurations with one community,
    // allocate 3 filter groups.
    //
    // 1. Promiscuous group: can send to any other group
    // 2. Community group:   can send to promiscuous group and community group
    // 3. Isolated group:    can send to promiscuous group only
    la_filter_group* promiscuous_group = nullptr;
    la_filter_group* community_group = nullptr;
    la_filter_group* isolated_group = nullptr;

    es->xdevice->create_filter_group(promiscuous_group);
    es->xdevice->create_filter_group(community_group);
    es->xdevice->create_filter_group(isolated_group);

    // Promiscuous group can send messages to any group, including itself.
    promiscuous_group->set_filtering_mode(promiscuous_group, la_filter_group::filtering_mode_e::PERMIT);
    promiscuous_group->set_filtering_mode(community_group, la_filter_group::filtering_mode_e::PERMIT);
    promiscuous_group->set_filtering_mode(isolated_group, la_filter_group::filtering_mode_e::PERMIT);

    // Community group can send messages to both the promiscuous and community groups.
    community_group->set_filtering_mode(promiscuous_group, la_filter_group::filtering_mode_e::PERMIT);
    community_group->set_filtering_mode(community_group, la_filter_group::filtering_mode_e::PERMIT);
    community_group->set_filtering_mode(isolated_group, la_filter_group::filtering_mode_e::DENY);

    // Isolated group can send messages only to the promiscuous group.
    isolated_group->set_filtering_mode(promiscuous_group, la_filter_group::filtering_mode_e::PERMIT);
    isolated_group->set_filtering_mode(community_group, la_filter_group::filtering_mode_e::DENY);
    isolated_group->set_filtering_mode(isolated_group, la_filter_group::filtering_mode_e::DENY);

    // Set filter group per each port
    es->l2_ethernet_ports[0]->set_filter_group(promiscuous_group);

    es->l2_ethernet_ports[1]->set_filter_group(community_group);
    es->l2_ethernet_ports[2]->set_filter_group(community_group);

    es->l2_ethernet_ports[3]->set_filter_group(isolated_group);
    es->l2_ethernet_ports[4]->set_filter_group(isolated_group);
}

int
main()
{
    example_system es;
    example_system_init(&es);

    create_sw(&es);
    configure_filtering(&es);

    return 0;
}
