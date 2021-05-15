// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_LB_TYPES_H__
#define __LA_LB_TYPES_H__

#include "api/types/la_ethernet_types.h"

/// @file
/// @brief Leaba load balance type definitions.
///
/// Defines load balancing related types and enumerations used by the Leaba API.

/// @addtogroup LB
/// @{

struct la_lb_vector_ipv4_t {
    la_uint16_t src_port;
    la_uint16_t dest_port;
    la_uint8_t protocol;
    la_uint32_t sip;
    la_uint32_t dip;
};

struct la_lb_vector_ipv6_t {
    la_uint16_t src_port;
    la_uint16_t dest_port;
    la_uint8_t next_header;
    la_uint32_t sip[4];
    la_uint32_t dip[4];
    la_uint32_t flow_label : 20;
};

struct la_lb_vector_ethernet_t {
    la_uint16_t vlan_id;
    la_uint16_t ether_type;
    la_mac_addr_t da;
    la_mac_addr_t sa;
};

struct la_lb_vector_cw_and_ethernet_t {
    la_uint32_t cw;
    la_lb_vector_ethernet_t ethernet;
};

struct la_lb_vector_mpls_label_stack_t {
    la_uint8_t num_valid_labels;
    la_uint32_t label[14];
};

enum la_lb_vector_type_e {
    LA_LB_VECTOR_IPV4_TCP_UDP = 1,
    LA_LB_VECTOR_IPV4_NON_TCP_UDP = 2,
    LA_LB_VECTOR_IPV6_TCP_UDP = 3,
    LA_LB_VECTOR_IPV6_NON_TCP_UDP = 4,
    LA_LB_VECTOR_ETHERNET_VLAN_TAG = 5,
    LA_LB_VECTOR_ETHERNET_NON_VLAN_TAG = 6,
    LA_LB_VECTOR_MPLS = 7,
    LA_LB_VECTOR_MPLS_IPV4 = 8,
    LA_LB_VECTOR_MPLS_IPV6 = 9,
    LA_LB_VECTOR_MPLS_ENTROPY_LI = 10,
    LA_LB_VECTOR_MPLS_CW_ETHERNET = 11,
    LA_LB_VECTOR_GTP = 12,
    LA_LB_VECTOR_ETHER_VLAN_IPV4_L4 = 13,
    LA_LB_VECTOR_ETHER_VLAN_IPV6_L4 = 14,
    LA_LB_VECTOR_MAX
};

struct la_lb_vector_t {
    la_lb_vector_type_e type;
    union {
        la_lb_vector_ipv4_t ipv4;
        la_lb_vector_ipv6_t ipv6;
        la_lb_vector_ethernet_t ethernet;
        la_lb_vector_cw_and_ethernet_t cw_and_ethernet;
        la_lb_vector_mpls_label_stack_t mpls;
        la_uint32_t mpls_entropy_li;
        la_uint32_t gtp_tunnel_id;
    };
};

using la_lb_pak_fields_vec = std::vector<la_lb_vector_t>;

/// @}
#endif
