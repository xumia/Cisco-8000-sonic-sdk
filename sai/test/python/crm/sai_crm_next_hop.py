# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import pytest
import saicli as S
import sai_packet_utils as U
import sai_topology as topology
from sai_test_utils import *


class Cleanup:
    def __init__(self):
        self.next_hops = []
        self.addresses = []
        self.groups = []
        self.members = []
        self.routes = []

    def clean(self):
        for route in self.routes:
            pytest.tb.remove_route(pytest.tb.virtual_router_id, route['prefix'], route['mask'])
        for addr in self.addresses:
            pytest.tb.remove_neighbor(pytest.tb.rif_id_1, addr['ip'])
        for nhgm in self.members:
            pytest.tb.remove_object(nhgm)
        for nhg in self.groups:
            pytest.tb.remove_object(nhg)
        for nh in self.next_hops:
            pytest.tb.remove_object(nh)


class Crm_next_hop_base():

    def _clean(self, finalizer):
        clean = Cleanup()
        finalizer.add_cleanup(clean)
        return clean

    def _add_neighbor(self, mac, ip, rif, clean):
        ip_addr = U.sai_ip(ip)
        nbr = sai_neighbor_entry_t(pytest.tb.switch_id, rif, ip_addr)
        attrs = []
        attrs.append([SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS, mac])
        pytest.tb.obj_wrapper.create_object(SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, nbr, attrs)

    def _add_neighbors(self, count, v4_v6, clean):
        mac = "00:10:20:30:40:{:02X}"
        if v4_v6 == "v4":
            # ip addresses 4th octet assigned by topology < 10
            ip = "192.168.1.{}"
            start = 10
        else:
            # ip addresses assigned by topology start at 2222
            ip = "1111:db9:a0b:12f0::22{}"
            start = 23

        for i in range(start, start + count, 1):
            m = mac.format(i)
            i = ip.format(i)
            self._add_neighbor(m, i, pytest.tb.rif_id_1, clean)
            clean.addresses.append({"ip": i, "mac": m})

    def _add_next_hops(self, clean):
        for addr in clean.addresses:
            nh = pytest.tb.create_next_hop(addr["ip"], pytest.tb.rif_id_1)
            clean.next_hops.append(nh)

    def _generate_nexthops(self, count, v4_v6, clean):
        self._add_neighbors(count, v4_v6, clean)
        self._add_next_hops(clean)

    def _generate_next_hop_group(self, clean):
        nh_group = pytest.tb.create_next_hop_group()
        clean.groups.append(nh_group)
        return nh_group

    def _generate_next_hop_group_member(self, group, next_hop, weight, clean):
        mem = pytest.tb.create_next_hop_group_member(group, next_hop, weight)
        clean.members.append(mem)
        return mem

    def _create_route(self, prefix, mask, group, clean):
        pytest.tb.create_route(pytest.tb.virtual_router_id, prefix, mask, group)
        clean.routes.append({'prefix': prefix, 'mask': mask})

    def _create_routes_based_on_groups(self, clean):
        assert len(clean.groups) < 256 and len(clean.groups) >= 0
        prefix = "10.10.{}.0"
        mask = "255.255.255.0"
        i = 0
        for group in clean.groups:
            self._create_route(prefix.format(i), mask, group, clean)
            i = i + 1
