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
/// @brief Router with VRRP configuration example
///
/// @example vrrp_router.cpp
///
/// The following example is a two router example, Router A and Router B each belong to two VRRP groups.
///
/// @code{.unparsed}
///       +----------+                             +----------+
///       | Router A |                             | Router B |
///       +----+-----+                             +----+-----+
///            |                                        |
///            | MAC: 00:00:5E:00:53:01                 | MAC: 00:00:5E:00:53:02
///            | IP: 10.1.0.1                           | IP: 10.1.0.2
///            |                                        |
///            |                                        |
///        +---+----------------------------------------+--------+
///        | Master             VRRP group 10       Backup       |
///        | Priority=120       IP: 10.1.0.100      Priority=100 |
///        |                MAC: 00:00:5E:00:01:0A               |
///        +---+----------------------------------------+--------+
///            |                                        |
///        +---+----------------------------------------+--------+
///        | Backup             VRRP group 20       Master       |
///        | Priority=100       IP: 10.1.0.200      Priority=120 |
///        |                MAC: 00:00:5E:00:01:14               |
///        +---+----------------------------------------+--------+
///            |                                        |
/// @endcode
///
/// Router A IP is: 10.1.0.1\n
/// Router B IP is: 10.1.0.2
///
/// Group 10: Virtual IP address is 10.1.0.100, Router A is the master and Router B is the backup.\n
/// Group 20: Virtual IP address is 10.1.0.200, Router B is the master and Router A is the backup.
///
/// Router A\n
/// Router(config)# interface GigabitEthernet 1/0/0 \n
/// Router(config-if)# ip address 10.1.0.1 255.255.255.0 \n
/// Router(config-if)# vrrp 10 priority 120 \n
/// ...\n
/// Router(config-if)# vrrp 10 ip 10.1.0.100\n
/// Router(config-if)# vrrp 20 priority 100 \n
/// ...\n
/// Router(config-if)# vrrp 20 ip 10.1.0.200\n
/// \n
/// Router B\n
/// Router(config)# interface GigabitEthernet 1/0/0 \n
/// Router(config-if)# ip address 10.1.0.2 255.255.255.0 \n
/// Router(config-if)# vrrp 10 priority 100 \n
/// ...\n
/// Router(config-if)# vrrp 10 ip 10.1.0.100\n
/// Router(config-if)# vrrp 20 priority 120 \n
/// ...\n
/// Router(config-if)# vrrp 20 ip 10.1.0.200\n
/// \n
/// __Clarification__: Although this is one file example with two functions, we expect each function to run on different physical
/// devices.
///

#include "api/npu/la_ethernet_port.h"
#include "api/npu/la_l3_ac_port.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_switch.h"
#include "api/npu/la_vrf.h"
#include "api/system/la_device.h"
#include "api/types/la_ip_types.h"

#include "example_system.h"

using namespace silicon_one;

void
vrrp_routerAB_create(example_system_t* es, bool is_router_a)
{
    // TODO: This example doesn't contain the configuration for the control:
    // E.g. Multicast DA (01:00:5e:00:00:12) and Multicast DIP (224.0.0.18) to transfer to CPU

    la_vrf_gid_t vrid_10_id = 1;
    la_vrf_gid_t vrid_20_id = 2;

    la_l3_port_gid_t rp1_id = 1;
    la_l3_port_gid_t rp2_id = 2;

    // Phase 1: Create two Virtual Routers (10 and 20) and a port on each of them
    // Create two Routers
    la_vrf* vrid_10 = nullptr;
    es->xdevice->create_vrf(vrid_10_id, vrid_10);
    la_vrf* vrid_20 = nullptr;
    es->xdevice->create_vrf(vrid_20_id, vrid_20);

    // Router port on VRID 10, from Ethernet Port 1
    la_l3_ac_port* vrid_10_rp = nullptr;
    la_mac_addr_t mac_addr1 = la_mac_addr_from_string("00:00:5E:00:01:0A"); // MAC for VRID 10
    es->xdevice->create_l3_ac_port(rp1_id,
                                   nullptr,
                                   EXAMPLE_SYSTEM_AC_PROFILE_VID1,
                                   EXAMPLE_SYSTEM_AC_PROFILE_VID2,
                                   mac_addr1,
                                   vrid_10,
                                   es->default_ingress_qos_profile,
                                   es->default_egress_qos_profile,
                                   la_egress_qos_marking_source_e::QOS_TAG,
                                   vrid_10_rp);

    // set port parameters
    la_ipv4_prefix_t ip_and_prefix1 = la_ipv4_prefix_from_string("10.1.0.100/24");
    vrid_10->add_ipv4_route(ip_and_prefix1, LA_L3_DESTINATION_CPU, 0 /* user-data */, false /* latency_sensitive */);

    // Router port on VRID 20, also from Ethernet Port 1
    la_l3_ac_port* vrid_20_rp = nullptr;
    la_mac_addr_t mac_addr2 = la_mac_addr_from_string("00:00:5E:00:01:14"); // MAC for VRID 20
    es->xdevice->create_l3_ac_port(rp2_id,
                                   nullptr,
                                   0,
                                   0,
                                   mac_addr2,
                                   vrid_20,
                                   es->default_ingress_qos_profile,
                                   es->default_egress_qos_profile,
                                   la_egress_qos_marking_source_e::QOS_TAG,
                                   vrid_20_rp);

    // set port parameters
    la_ipv4_prefix_t ip_and_prefix2 = la_ipv4_prefix_from_string("10.1.0.200/24");
    vrid_20->add_ipv4_route(ip_and_prefix2, LA_L3_DESTINATION_CPU, 0 /* user-data */, false /* latency_sensitive */);

    // Phase 2: Set the backup as inactive
    if (is_router_a) {
        /* Router A */
        vrid_20_rp->set_active(false);
    } else {
        /* Router B */
        vrid_10_rp->set_active(false);
    }
}

void
vrrp_routerA()
{
    example_system_t es;
    example_system_init(&es);

    vrrp_routerAB_create(&es, true /* Router A */);
}

void
vrrp_routerB()
{
    example_system_t es;
    example_system_init(&es);

    vrrp_routerAB_create(&es, false /* Router B */);
}

int
main()
{
    vrrp_routerA();
    vrrp_routerB();

    return 0;
}
