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
/// @brief L2 QoS example
///
/// @example l2_qos1.cpp
///
/// Configures QoS profiles and associates them with a port.
///
/// Traffic Class mapping
///     On ingress, each PCP value is mapped to a distinct traffic class.
///
/// Traffic metering
///     On ingress, the traffic is marked not to be metered (policed).
///
/// Coloring
///     On ingress, packet color (which is used by meters and congestion management) is assigned based on the DEI field.
///
/// QoS remarking
///     The ingress and egress profiles are configured such that the (PCP, DEI) of the received packet remains the same when the
///     packet is transmitted.
///     On ingrees, (PCP, DEI) of the packet is configured with a one-to-one mapping to canonical QoS tag.
///     On egress, (PCP, DEI) is generated back from ingress-generated QoS tag.
///
/// AC port configuration
///     Port is configured using the defined ingress, egress QoS profiles.
///     On egress, QoS field remarking is configured to use the canonical QoS tag instead of QoS group.
///
#include "example_system.h"

#include "api/npu/la_l2_port.h"
#include "api/npu/la_l2_service_port.h"
#include "api/npu/la_switch.h"
#include "api/qos/la_egress_qos_profile.h"
#include "api/qos/la_ingress_qos_profile.h"
#include "api/system/la_device.h"
#include "api/types/la_common_types.h"
#include "api/types/la_qos_types.h"

#include "example_system.h"

using namespace silicon_one;

void
create_ingress_qos_profile(example_system_t* es, la_ingress_qos_profile*& ingress_qos_profile)
{
    es->xdevice->create_ingress_qos_profile(ingress_qos_profile);

    // Configure the Ethernet forwarding table
    la_ingress_qos_profile::forwarding_header_e eth_header = la_ingress_qos_profile::forwarding_header_e::ETHERNET;
    for (la_uint_t pcp = 0; pcp <= 0x7; pcp++) {
        la_vlan_pcpdei pcpdei0(pcp, 0 /* dei */);
        la_vlan_pcpdei pcpdei1(pcp, 1 /* dei */);

        // Configure a traffic class per PCP, ignoring DEI
        la_traffic_class_t tc = pcp;
        ingress_qos_profile->set_traffic_class_mapping(eth_header, pcpdei0, tc);
        ingress_qos_profile->set_traffic_class_mapping(eth_header, pcpdei1, tc);

        // Configure not to meter any PCP, DEI
        ingress_qos_profile->set_metering_enabled_mapping(eth_header, pcpdei0, false);
        ingress_qos_profile->set_metering_enabled_mapping(eth_header, pcpdei1, false);

        // Configure color based on DEI, where DEI == 0 is gets GREEN and DEI == 1 gets YELLOW
        ingress_qos_profile->set_color_mapping(eth_header, pcpdei0, la_qos_color_e::GREEN);
        ingress_qos_profile->set_color_mapping(eth_header, pcpdei1, la_qos_color_e::YELLOW);

        // Configure marking indication to egress such that no actual remarking is performed
        ingress_qos_profile->set_qos_tag_mapping(pcpdei0, pcpdei0);
        ingress_qos_profile->set_qos_tag_mapping(pcpdei1, pcpdei1);
    }
}

void
create_egress_qos_profile(example_system_t* es, la_egress_qos_profile*& egress_qos_profile)
{
    es->xdevice->create_egress_qos_profile(egress_qos_profile);

    for (la_uint_t pcp = 0; pcp <= 0x7; pcp++) {
        for (la_uint_t dei = 0; dei <= 0x1; dei++) {
            la_vlan_pcpdei pcpdei(pcp, dei);

            // Set encapsulating headers QoS fields to mimic the PCP field of the forwarding header when possible
            la_egress_qos_profile::encapsulating_headers_qos_values encap_headers_qos_values;

            encap_headers_qos_values.pcpdei = pcpdei;
            encap_headers_qos_values.tc.value = pcpdei.fields.pcp;
            encap_headers_qos_values.tos.flat = pcpdei.fields.pcp;

            // Configure the marking mapping from Packet QoS tag ID. This mapping is used by the egress port if the port is in
            // la_egress_qos_marking_source_e::QOS_TAG mode.
            egress_qos_profile->set_qos_tag_mapping(pcpdei, pcpdei, encap_headers_qos_values);
        }
    }
}

void
apply_profiles(example_system_t* es,
               la_ingress_qos_profile* ingress_qos_profile,
               la_egress_qos_profile* egress_qos_profile,
               la_l2_service_port* ap)
{
    es->xdevice->create_ac_l2_service_port(es->l2_port_next_gid++,
                                           es->l2_ethernet_ports[0],
                                           5 /* outer VID */,
                                           3 /* inner VID */,
                                           ingress_qos_profile,
                                           egress_qos_profile,
                                           la_egress_qos_marking_source_e::QOS_TAG,
                                           ap);
}

int
main()
{
    example_system_t es;
    la_ingress_qos_profile* ingress_qos_profile1 = nullptr;
    la_egress_qos_profile* egress_qos_profile1 = nullptr;
    la_l2_service_port* ap0 = nullptr;

    example_system_init(&es);

    create_ingress_qos_profile(&es, ingress_qos_profile1);
    create_egress_qos_profile(&es, egress_qos_profile1);

    apply_profiles(&es, ingress_qos_profile1, egress_qos_profile1, ap0);

    return 0;
}
