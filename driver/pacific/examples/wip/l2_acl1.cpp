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

/// @example l2_acl1.cpp
///
/// Configures the following ACL on two ports.
///
/// ### ACL: #
/// | Condition                                                 | Action                |
/// | :-----------                                              | :---                  |
/// | (DA & 0xFFFF000000) == 0x3333000000 and VLAN1 in 1000-2000| Accept (don't filter) |
/// | (DA & 0xFFFF000000) == 0x3333000000 and VLAN1 is 300      | Deny (do filter)      |

#include "example_system.h"

#include "api/npu/la_acl.h"
#include "api/npu/la_ethernet_port.h"
#include "api/npu/la_l2_service_port.h"
#include "api/types/la_common_types.h"

using namespace silicon_one;

void
configure_ranges(example_system_t* es)
{
    es->xdevice->set_acl_range(
        la_acl::stage_e::INGRESS_FWD, la_acl::range_type_e::VLAN, 0 /* vlan_range_idx */, 100 /* vid_start */, 200 /* vid_end */);
    es->xdevice->set_acl_range(
        la_acl::stage_e::INGRESS_FWD, la_acl::range_type_e::VLAN, 1 /* vlan_range_idx */, 1000 /* vid_start */, 2000 /* vid_end */);
}

void
configure_acl(example_system_t* es, la_acl*& list1)
{
    es->xdevice->create_acl(la_acl::stage_e::INGRESS_FWD, la_acl::type_e::UNIFIED, la_acl::key_type_e::MAC, list1);

    la_acl_key key1;

    key1.val.mac.da.flat = 0x3333000000ULL;
    key1.mask.mac.da.flat = 0xFFFF00000000ULL;
    key1.val.mac.vlan1_range_bitmap = 1;
    key1.mask.mac.vlan1_range_bitmap = 0xFFFF;

    la_acl_command cmd1;
    cmd1.type = la_acl_cmd_type_e::INGRESS_UNIFIED;
    cmd1.data.ingress_unified.sec.drop = false;

    list1->append(key1, cmd1);

    la_acl_key key2;

    key2.val.mac.da.flat = 0x3333000000ULL;
    key2.mask.mac.da.flat = 0xFFFF00000000ULL;
    key2.val.mac.vlan1.tci.fields.vid = 300;
    key2.mask.mac.vlan1.tci.fields.vid = 0xFFF;

    la_acl_command cmd2;
    cmd2.type = la_acl_cmd_type_e::INGRESS_UNIFIED;
    cmd2.data.ingress_unified.sec.drop = true;

    list1->insert(1 /* position */, key2, cmd2);
}

void
configure_ports(example_system_t* es, la_acl* list1, la_l2_service_port* ap0, la_l2_service_port* ap1)
{
    // Create AC L2 service ports
    es->xdevice->create_ac_l2_service_port(es->l2_port_next_gid++,
                                           es->l2_ethernet_ports[0],
                                           5 /* outer VID */,
                                           3 /* inner VID */,
                                           es->default_ingress_qos_profile,
                                           es->default_egress_qos_profile,
                                           la_egress_qos_marking_source_e::QOS_TAG,
                                           ap0);

    es->xdevice->create_ac_l2_service_port(es->l2_port_next_gid++,
                                           es->l2_ethernet_ports[1],
                                           5 /* outer VID */,
                                           3 /* inner VID */,
                                           es->default_ingress_qos_profile,
                                           es->default_egress_qos_profile,
                                           la_egress_qos_marking_source_e::QOS_TAG,
                                           ap1);

    // Configure ACL profile and attach to L2 ethernet ports
    ap0->set_acl(list1);
    ap1->set_acl(list1);
}

int
main()
{
    example_system_t es;
    la_acl* list1 = nullptr;
    la_l2_service_port* ap0 = nullptr;
    la_l2_service_port* ap1 = nullptr;

    example_system_init(&es);

    configure_ranges(&es);
    configure_acl(&es, list1);

    configure_ports(&es, list1, ap0, ap1);

    return 0;
}
