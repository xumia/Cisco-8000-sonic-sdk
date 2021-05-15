# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

from saicli import *

sai_stats_info = {
    SAI_OBJECT_TYPE_ROUTER_INTERFACE:
    {
        "stat_ids": {
            SAI_ROUTER_INTERFACE_STAT_IN_OCTETS: "IN OCTETS",
            SAI_ROUTER_INTERFACE_STAT_IN_PACKETS: "IN PACKETS",
            SAI_ROUTER_INTERFACE_STAT_OUT_OCTETS: "OUT OCTETS",
            SAI_ROUTER_INTERFACE_STAT_OUT_PACKETS: "OUT PACKETS",
            SAI_ROUTER_INTERFACE_STAT_IPV4_IN_OCTETS: "IPV4 IN OCTETS",
            SAI_ROUTER_INTERFACE_STAT_IPV4_IN_PACKETS: "IPV4 IN PACKETS",
            SAI_ROUTER_INTERFACE_STAT_IPV6_IN_OCTETS: "IPV6 IN OCTETS",
            SAI_ROUTER_INTERFACE_STAT_IPV6_IN_PACKETS: "IPV6 IN PACKETS",
            SAI_ROUTER_INTERFACE_STAT_MPLS_IN_OCTETS: "MPLS IN OCTETS",
            SAI_ROUTER_INTERFACE_STAT_MPLS_IN_PACKETS: "MPLS IN PACKETS",
            SAI_ROUTER_INTERFACE_STAT_IPV4_OUT_OCTETS: "IPV4 OUT OCTETS",
            SAI_ROUTER_INTERFACE_STAT_IPV4_OUT_PACKETS: "IPV4 OUT PACKETS",
            SAI_ROUTER_INTERFACE_STAT_IPV6_OUT_OCTETS: "IPV6 OUT OCTETS",
            SAI_ROUTER_INTERFACE_STAT_IPV6_OUT_PACKETS: "IPV6 OUT PACKETS",
            SAI_ROUTER_INTERFACE_STAT_MPLS_OUT_OCTETS: "MPLS OUT OCTETS",
            SAI_ROUTER_INTERFACE_STAT_MPLS_OUT_PACKETS: "MPLS OUT PACKETS",
        },
        "get_func": "getRifCounters",
        "stat_vec": "rifStatVec"
    }
}
