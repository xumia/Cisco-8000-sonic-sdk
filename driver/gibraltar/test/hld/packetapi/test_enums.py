#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#!/usr/bin/env python3

import sys
import subprocess
import unittest

from leaba import sdk
import nplapicli

NUM_OF_BITS_IN_DESTINATION = 20

# enums that don't have a corresponding value in the NPL, and cannot be validated.
packetapi_exclude_list = [
    'LA_PROTOCOL_TYPE_VLAN_PREFIX',
    'LA_PROTOCOL_TYPE_SYSTEM_PREFIX',
    'LA_PROTOCOL_TYPE_L4_PREFIX',
    'LA_HEADER_TYPE_IPV4_HEADERS_PREFIX',
    'LA_HEADER_TYPE_IPV6_HEADERS_PREFIX',
    'LA_HEADER_TYPE_MPLS_HEADERS_PREFIX',
    'LA_HEADER_TYPE_IP_ROUTE_SUFFIX',
    'LA_HEADER_TYPE_IP_COLLAPSED_MC_SUFFIX',
    'LA_PACKET_INJECT_DOWN_DEST_DSP',
    'LA_PACKET_INJECT_DOWN_DEST_BVN',
    'LA_PACKET_DESTINATION_PREFIX_MCID',
    'LA_PACKET_DESTINATION_PREFIX_MASK_MCID',
    'LA_SYSTEM_PORT_GID_INVALID',
    'LA_L2_LOGICAL_PORT_GID_INVALID',
    'LA_L3_LOGICAL_PORT_GID_INVALID',
    "LA_LEARN_NOTIFICATION_TYPE_NEW",
    "LA_LEARN_NOTIFICATION_TYPE_UPDATE",
    "LA_LEARN_NOTIFICATION_TYPE_REFRESH"
]

# enums that have a clear SDK->NPL name mapping
packetapi_prefix_subst_list = {
    'LA_PROTOCOL': 'NPL_PROTOCOL',
    'LA_HEADER': 'NPL_FWD_HEADER',
    'LA_PACKET_TIME_STAMP_COMMAND': 'NPL_TS_CMD',
    'LA_PACKET_PUNT_SOURCE': 'NPL_PUNT_SRC',
    'LA_INJECT_HEADER': 'NPL_INJECT_HEADER',
    'LA_PACKET_INJECT_DOWN_ENCAP': 'NPL_INJECT_DOWN_ENCAP_TYPE',
    'LA_PACKET_INJECT': 'NPL_INJECT_HEADER'
}

packetapi_misc = {
    'LA_PACKET_DESTINATION_GID_PREFIX_DSP': nplapicli.NPL_DESTINATION_DSP_PREFIX << (
        NUM_OF_BITS_IN_DESTINATION -
        nplapicli.NPL_DESTINATION_DSP_PREFIX_LEN),
    'LA_PACKET_DESTINATION_GID_PREFIX_BVN': nplapicli.NPL_DESTINATION_BVN_PREFIX << (
        NUM_OF_BITS_IN_DESTINATION -
        nplapicli.NPL_DESTINATION_BVN_PREFIX_LEN),
}


class test_packetapi_enums(unittest.TestCase):

    def test_packetapi_enums(self):
        lapt_enums = list(filter(lambda n: n.find('LA_') == 0, dir(sdk.la_packet_types)))

        for sdk_enum in lapt_enums:
            found = False
            if sdk_enum in packetapi_exclude_list:
                found = True
            elif sdk_enum in packetapi_misc:
                found = True
                eq = eval('sdk.la_packet_types.%s == %s' % (sdk_enum, packetapi_misc[sdk_enum]))
                if not eq:
                    self.fail('Error: %s wrong enum value' % sdk_enum)
                    self.assertTrue(sdk_enum in packetapi_enums.keys())
            else:
                for prefix in packetapi_prefix_subst_list:
                    if sdk_enum.find(prefix) == 0:
                        found = True
                        npl_enum = '%s%s' % (packetapi_prefix_subst_list[prefix], sdk_enum[len(prefix):])
                        eq = eval('sdk.la_packet_types.%s == nplapicli.%s' % (sdk_enum, npl_enum))
                        if not eq:
                            self.fail('Error: %s wrong enum value' % (sdk_enum))
                        break

            if not found:
                self.fail('Error: %s unexpected enum' % sdk_enum)


if __name__ == '__main__':
    unittest.main()
