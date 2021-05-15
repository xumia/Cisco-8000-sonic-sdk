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
/// @brief Leaba Example infrastructure
///

#include "example_system.h"
#include "nplapi/translator_creator.h"
#include "nsim_provider/nsim_test_flow.h"

#include "api/npu/la_ac_profile.h"
#include "api/qos/la_egress_qos_profile.h"
#include "api/qos/la_ingress_qos_profile.h"
#include "api/system/la_device.h"
#include "api/system/la_mac_port.h"
#include "api/system/la_system_port.h"
#include "api/tm/la_unicast_tc_profile.h"

#include <assert.h>
#include <stdio.h>

#include <memory>

using namespace silicon_one;

static const la_device_id_t device_id = 0;

void
assert_bool(bool success, const char* msg)
{
    if (!success) {
        fprintf(stderr, "Error: %s\n", msg);
    }

    assert(success);
}

void
assert_status(la_status status, const char* msg)
{
    assert_bool(status == LA_STATUS_SUCCESS, msg);
}

la_device*
create_device(example_system* es)
{
    const char* dp = "/dev/testdev1";

    nsim_provider* sim_ifc = create_and_run_simulator_server(nullptr /* host */, 0 /* port */, dp);
    std::string sim_path = sim_ifc->get_connection_handle();

    la_device* dev = nullptr;
    la_status status = la_create_device(sim_path.c_str(), device_id, dev);
    assert_status(status, "Failed to create la_device.");

    es->device = dev;
    es->sim_ifc = sim_ifc;

    return dev;
}

void
initialize_device(example_system* es)
{
    la_device* dev = es->device;

    la_status status = dev->initialize(la_device::init_phase_e::DEVICE);
    assert_status(status, "Failed to initialize device to init_phase_e::DEVICE phase.");

    for (la_slice_id_t slice : dev->get_used_slices()) {
        dev->set_slice_mode(slice, la_slice_mode_e::NETWORK);
    }

    status = dev->initialize(la_device::init_phase_e::TOPOLOGY);
    assert_status(status, "Failed to initialize device to init_phase_e::TOPOLOGY phase.");
}

la_ac_profile*
initialize_default_ac_profile(la_device* dev)
{
    la_ac_profile* ac_profile = nullptr;

    la_status status = dev->create_ac_profile(ac_profile);
    assert_status(status, "Failed creating default AC profile.");

    status = ac_profile->set_key_selector_per_format(LA_PACKET_VLAN_FORMAT_UNTAGGED, la_ac_profile::key_selector_e::PORT);
    assert_status(status, "Failed setting AC profile untagged packets mapping.");

    status = ac_profile->set_key_selector_per_format(LA_PACKET_VLAN_FORMAT_802Q, la_ac_profile::key_selector_e::PORT_VLAN);
    assert_status(status, "Failed setting AC profile 802.q packets mapping.");

    status = ac_profile->set_key_selector_per_format(LA_PACKET_VLAN_FORMAT_802QinQ, la_ac_profile::key_selector_e::PORT_VLAN_VLAN);
    assert_status(status, "Failed setting AC profile 802.QinQ packets mapping.");

    return ac_profile;
}

la_tc_profile*
initialize_default_tc_profile(la_device* dev)
{
    la_tc_profile* tc_profile = nullptr;

    la_status status = dev->create_tc_profile(tc_profile);
    assert_status(status, "Failed creating default TC profile.");

    for (la_traffic_class_t tc = 0; tc < 8; tc++) {
        la_status status = tc_profile->set_mapping(tc, tc);
        assert_status(status, "Failed setting TC profile mapping.");
    }

    return tc_profile;
}

la_egress_qos_profile*
initialize_default_egress_qos_profile(la_device* dev)
{
    la_egress_qos_profile* p = nullptr;
    la_egress_qos_profile::encapsulating_headers_qos_values encap_qos_values;

    la_status status = dev->create_egress_qos_profile(la_egress_qos_marking_source_e::QOS_TAG, p);
    assert_status(status, "Failed creating egress QOS profile.");

    // PCP-DEI mapping
    for (size_t pcp = 0; pcp < 8; pcp++) {
        for (size_t dei = 0; dei < 2; dei++) {
            la_vlan_pcpdei pcp_dei(pcp, dei);
            status = p->set_qos_tag_mapping_pcpdei(pcp_dei, pcp_dei, encap_qos_values);
            assert_status(status, "Failed setting PCP-DEI mapping for default egress QOS profile.");
        }
    }

    // DSCP mapping
    for (la_uint8_t val = 0; val < 64; val++) {
        la_ip_dscp dscp = {.value = val};
        status = p->set_qos_tag_mapping_dscp(dscp, dscp, encap_qos_values);
        assert_status(status, "Failed setting IP DSCP mapping for default egress QOS profile.");
    }

    // MPLS TC mapping
    for (la_uint8_t val = 0; val < 8; val++) {
        la_mpls_tc tc = {.value = val};
        status = p->set_qos_tag_mapping_mpls_tc(tc, tc, encap_qos_values);
        assert_status(status, "Failed setting MPLS TC mapping for default egress QOS profile.");
    }

    return p;
}

la_ingress_qos_profile*
initialize_default_ingress_qos_profile(la_device* dev)
{
    la_ingress_qos_profile* p = nullptr;

    la_status status = dev->create_ingress_qos_profile(p);
    assert_status(status, "Failed creating ingress QOS profile.");

    // PCP-DEI mapping
    for (size_t pcp = 0; pcp < 8; pcp++) {
        for (size_t dei = 0; dei < 2; dei++) {
            la_vlan_pcpdei pcp_dei(pcp, dei);
            status = p->set_qos_tag_mapping_pcpdei(pcp_dei, pcp_dei);
            assert_status(status, "Failed setting PCP-DEI mapping for default ingress QOS profile.");
        }
    }

    // DSCP mapping for IPv4 and IPv6
    for (la_uint8_t val = 0; val < 64; val++) {
        la_ip_dscp dscp = {.value = val};
        status = p->set_qos_tag_mapping_dscp(la_ip_version_e::IPV4, dscp, dscp);
        assert_status(status, "Failed setting IPv4 DSCP mapping for default ingress QOS profile.");
        status = p->set_qos_tag_mapping_dscp(la_ip_version_e::IPV6, dscp, dscp);
        assert_status(status, "Failed setting IPv6 DSCP mapping for default ingress QOS profile.");
    }

    // MPLS TC mapping
    for (la_uint8_t val = 0; val < 8; val++) {
        la_mpls_tc tc = {.value = val};
        status = p->set_qos_tag_mapping_mpls_tc(tc, tc);
        assert_status(status, "Failed setting MPLS TC mapping for default ingress QOS profile.");
    }

    return p;
}

la_filter_group*
initialize_default_filter_group(la_device* dev)
{
    la_filter_group* filter_group = nullptr;

    la_status status = dev->create_filter_group(filter_group);
    assert_status(status, "Failed creating filter group.");

    return filter_group;
}

void
initialize_default_profiles(example_system* es)
{
    la_device* dev = es->device;

    es->ac_profile = initialize_default_ac_profile(dev);
    es->tc_profile = initialize_default_tc_profile(dev);
    es->default_egress_qos_profile = initialize_default_egress_qos_profile(dev);
    es->default_ingress_qos_profile = initialize_default_ingress_qos_profile(dev);
    es->default_filter_group = initialize_default_filter_group(dev);
}

void
initialize_ports(example_system* es)
{
    la_device* dev = es->device;
    for (size_t slice_id : dev->get_used_slices()) {
        for (size_t ifg_id = 0; ifg_id < NUM_IFGS_PER_SLICE; ifg_id++) {
            for (size_t i = 0; i < NUM_IFCS_PER_IFG; i++) {
                la_mac_port* mac_port = nullptr;
                la_status status = dev->create_mac_port(slice_id,
                                                        ifg_id,
                                                        i,
                                                        i,
                                                        la_mac_port::port_speed_e::E_50G,
                                                        la_mac_port::fc_mode_e::NONE,
                                                        la_mac_port::fec_mode_e::RS_KR4,
                                                        mac_port);
                assert_status(status, "Failed creating MAC port.");

                la_voq_set* voq_set = nullptr;

                la_vsc_gid_vec_t base_vsc_vec = la_vsc_gid_vec_t(ASIC_MAX_SLICES_PER_DEVICE_NUM, LA_VSC_GID_INVALID);
                for (la_slice_id_t sid : dev->get_used_slices()) {
                    base_vsc_vec[sid] = es->vsc_next_id[slice_id][ifg_id];
                    es->vsc_next_id[slice_id][ifg_id] += NUM_OQS_PER_PORT;
                }

                status = dev->create_voq_set(
                    es->voq_next_gid, 8 /* set_size */, base_vsc_vec, device_id /* dest_device */, slice_id, ifg_id, voq_set);
                assert_status(status, "Failed creating VOQ set.");

                es->voq_next_gid += NUM_OQS_PER_PORT * 2;

                la_system_port* sys_port = nullptr;
                status = dev->create_system_port(es->sp_next_gid++, mac_port, voq_set, es->tc_profile, sys_port);
                assert_status(status, "Failed creating system port.");

                la_ethernet_port* eth_port = nullptr;
                status = dev->create_ethernet_port(sys_port, la_ethernet_port::port_type_e::AC, eth_port);
                assert_status(status, "Failed creating ethernet port.");

                status = eth_port->set_ac_profile(es->ac_profile);
                assert_status(status, "Failed assigning default AC profile to ethernet port.");

                es->slice[slice_id].ifg[ifg_id].l2_ethernet_ports[i] = eth_port;
            }
        }
    }
}

example_system*
create_example_system()
{
    example_system* es = new example_system();

    // Create device
    create_device(es);

    // Initialize device
    initialize_device(es);

    // Initialize default profiles
    initialize_default_profiles(es);

    // Initialize system ports
    initialize_ports(es);

    return es;
}

la_mac_addr_t
la_mac_addr_from_string(const char str[])
{
    return la_mac_addr_t();
}

la_ipv4_addr_t
la_ipv4_addr_from_string(const char str[])
{
    return la_ipv4_addr_t();
}

la_ipv4_prefix_t
la_ipv4_prefix_from_string(const char str[])
{
    return la_ipv4_prefix_t();
}

la_ipv6_addr_t
la_ipv6_addr_from_string(const char str[])
{
    return la_ipv6_addr_t();
}

la_ipv6_prefix_t
la_ipv6_prefix_from_string(const char str[])
{
    return la_ipv6_prefix_t();
}
