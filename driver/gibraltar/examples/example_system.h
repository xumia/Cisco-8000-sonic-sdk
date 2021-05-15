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

#ifndef __LA_EXAMPLE_SYSTEM_H__
#define __LA_EXAMPLE_SYSTEM_H__

/// @file
/// @brief Leaba Example system infrastructure
///
/// Defines types, structures and functions used by the Leaba examples.

#include "api/system/la_device.h"
#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_system_types.h"
#include "api/types/la_tm_types.h"

#include "nsim_provider/nsim_provider.h"

using namespace silicon_one;

enum {
    ASIC_MAX_SLICES_PER_DEVICE_NUM = 6,
    NUM_IFGS_PER_SLICE = 2,
    NUM_IFCS_PER_IFG = 18,
    NUM_SYSTEM_PORTS = ASIC_MAX_SLICES_PER_DEVICE_NUM * NUM_IFGS_PER_SLICE * NUM_IFCS_PER_IFG,
    NUM_OQS_PER_PORT = 8,
};

enum {
    EXAMPLE_SYSTEM_AC_PROFILE_VID1 = 0x11,
    EXAMPLE_SYSTEM_AC_PROFILE_VID2 = 0x0,
};

/// @brief Example system struct
///
/// Provides a set of basic objects to be used for constructing tests.
struct example_system {
    la_device* device;                    ///< Device C++ handle.
    la_system_port_gid_t sp_next_gid = 0; ///< Next available system port global ID.
    la_spa_port_gid_t spa_next_gid = 0;   ///< Next available system port aggregate global ID.
    la_voq_gid_t voq_next_gid = 0;        ///< Next available VOQ global ID.
    la_vsc_gid_t vsc_next_id[ASIC_MAX_SLICES_PER_DEVICE_NUM][NUM_IFGS_PER_SLICE] = {{0}}; ///< Next available VSC ID.
    la_l3_protection_group_gid_t l3_protection_group_next_gid; ///< Next available L3 protection group global ID.
    la_l2_port_gid_t l2_port_next_gid = 0;                     ///< Next available L2 port global ID.
    la_l3_port_gid_t l3_port_next_gid = 0;                     ///< Next available L3 port global ID.
    la_next_hop_gid_t next_hop_next_gid = 0;                   ///< Next available Next Hop global ID.
    la_switch_gid_t switch_next_gid = 0;                       ///< Next available Switch global ID.
    la_vrf_gid_t vrf_next_gid = 0;                             ///< Next available VRF global ID.

    la_mac_addr_t base_mac_addr;

    la_ac_profile* ac_profile; ///< Default AC profile.
    la_tc_profile* tc_profile; ///< Default TC profile.

    la_ingress_qos_profile* default_ingress_qos_profile; ///< Default ingress QoS profile to use.
    la_egress_qos_profile* default_egress_qos_profile;   ///< Default egress QoS profile to use.
    la_filter_group* default_filter_group;               ///< Default filter group.

    struct {
        struct {
            la_ethernet_port* l2_ethernet_ports[NUM_IFCS_PER_IFG]; ///< Configured L2 ethernet ports.
        } ifg[NUM_IFGS_PER_SLICE];
    } slice[ASIC_MAX_SLICES_PER_DEVICE_NUM];

    nsim_provider* sim_ifc;
};

/// @brief Initialize an example system.
///
/// @return     Pointer to initialized #example_system.
example_system* create_example_system();

/// @brief Translates string to MAC address.
///
/// @param[in]  str     String to translate.
///
/// @return MAC address in #la_mac_addr_t format.
///         Returns 00:00:00:00:00:00 in case of corrupt input string.
///
/// @note This helper does not do any safety checks.
///       It assumes the supplied address is always valid.
la_mac_addr_t la_mac_addr_from_string(const char str[]);

/// @brief Translates string to IPv4 address (e.g. "A.B.C.D").
///
/// @param[in]      str         String with the IP address .
///
/// @return IPv4 address in #silicon_one::la_ipv4_addr_t format.
///         Returns 0.0.0.0 in case of corrupt input string.
///
/// @note This helper does not do any safety checks.
///       It assumes the supplied address is always valid.
la_ipv4_addr_t la_ipv4_addr_from_string(const char str[]);

/// @brief Translates IPv4 address with prefix string in a CIDR notation (e.g. "A.B.C.D/P").
///
/// @param[in]      str             String with the IPv4 address and prefix.
///
/// @return IPv4 address and prefix in #silicon_one::la_ipv4_prefix_t format.
///         Returns 0.0.0.0/0 in case of corrupt input string.
///
/// @note This helper does not do any safety checks.
///       It assumes the supplied string is always valid.
la_ipv4_prefix_t la_ipv4_prefix_from_string(const char str[]);

/// @brief Translates string to IPv6 address (e.g. "2001:0DB8:CAFE:0001::1").
///
/// @param[in]      str       String with the IPv6 address .
///
/// @return IPv6 address in #silicon_one::la_ipv6_addr_t format.
///         Returns ::0 (unspecified) in case of corrupt input string.
///
/// @note This helper does not do any safety checks.
///       It assumes the supplied address is always valid.
la_ipv6_addr_t la_ipv6_addr_from_string(const char str[]);

/// @brief Translates IPv6 address with prefix length string (e.g. "2001:0DB8:CAFE:0001::1/64").
///
/// @param[in]      str             String with the IPv6 address and prefix.
///
/// @return IPv6 address and prefix in #silicon_one::la_ipv6_prefix_t format.
///         Returns ::0/0 in case of corrupt input string.
///
/// @note This helper does not do any safety checks.
///       It assumes the supplied string is always valid.
la_ipv6_prefix_t la_ipv6_prefix_from_string(const char str[]);

/// @brief assert and print provided message if boolean is false.
void assert_bool(bool success, const char* msg);

/// @brief assert and print provided message if status is not LA_STATUS_SUCCESS.
void assert_status(la_status status, const char* msg);

#endif // __LA_EXAMPLE_SYSTEM_H__
