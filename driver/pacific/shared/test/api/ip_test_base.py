#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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


from leaba import sdk

CHAR_BIT = 8


class ipv4_test_base:
    BYTES_NUM_IN_ADDR = 4

    @staticmethod
    def build_prefix(dip, length):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = ipv4_test_base.apply_prefix_mask(dip.to_num(), length)
        prefix.length = length
        return prefix

    @staticmethod
    def get_default_prefix():
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0
        prefix.length = 0
        return prefix

    @staticmethod
    def apply_prefix_mask(addr_num, prefix_length):
        mask = ~((1 << (CHAR_BIT * ipv4_test_base.BYTES_NUM_IN_ADDR - prefix_length)) - 1)
        masked_addr_num = addr_num & mask
        return masked_addr_num

    @staticmethod
    def add_route(vrf, prefix, l3_dest, private_data, latency_sensitive=False):
        return vrf.hld_obj.add_ipv4_route(prefix, l3_dest.hld_obj, private_data, latency_sensitive)

    @staticmethod
    def modify_route(vrf, prefix, l3_dest):
        return vrf.hld_obj.modify_ipv4_route(prefix, l3_dest.hld_obj)

    @staticmethod
    def delete_route(vrf, prefix):
        return vrf.hld_obj.delete_ipv4_route(prefix)

    @staticmethod
    def clear_all_routes(vrf):
        return vrf.hld_obj.clear_all_ipv4_routes()

    @staticmethod
    def ip_route_bulk_entry(action, prefix, l3_dest, class_id, private_data, latency_sensitive):
        prefix_update = sdk.la_ipv4_route_entry_parameters()
        prefix_update.action = action
        prefix_update.prefix = prefix
        if (action != sdk.la_route_entry_action_e_DELETE):
            prefix_update.destination = l3_dest
            prefix_update.is_class_id_set = True
            prefix_update.class_id = class_id
            prefix_update.is_user_data_set = True
            prefix_update.user_data = private_data

        if (action == sdk.la_route_entry_action_e_ADD):
            prefix_update.latency_sensitive = latency_sensitive

        return prefix_update

    @staticmethod
    def ip_route_bulk_updates(vrf, prefixes_update_vec):
        return vrf.hld_obj.ipv4_route_bulk_updates(prefixes_update_vec)

    @staticmethod
    def get_route(vrf, dip):
        return vrf.hld_obj.get_ipv4_route(dip.hld_obj)

    @staticmethod
    def get_routing_entry(vrf, prefix):
        return vrf.hld_obj.get_ipv4_routing_entry(prefix)

    @staticmethod
    def add_subnet(l3_port, prefix):
        return l3_port.hld_obj.add_ipv4_subnet(prefix)

    @staticmethod
    def delete_subnet(l3_port, prefix):
        return l3_port.hld_obj.delete_ipv4_subnet(prefix)

    @staticmethod
    def get_subnets(l3_port):
        return l3_port.hld_obj.get_ipv4_subnets()

    @staticmethod
    def add_host(l3_port, dip, mac):
        return l3_port.hld_obj.add_ipv4_host(dip.hld_obj, mac.hld_obj)

    @staticmethod
    def add_host_with_class_id(l3_port, dip, mac, class_id):
        return l3_port.hld_obj.add_ipv4_host(dip.hld_obj, mac.hld_obj, class_id)

    @staticmethod
    def modify_host(l3_port, dip, mac):
        return l3_port.hld_obj.modify_ipv4_host(dip.hld_obj, mac.hld_obj)

    @staticmethod
    def modify_host_with_class_id(l3_port, dip, mac, class_id):
        return l3_port.hld_obj.modify_ipv4_host(dip.hld_obj, mac.hld_obj, class_id)

    @staticmethod
    def get_host(l3_port, dip):
        return l3_port.hld_obj.get_ipv4_host(dip.hld_obj)

    @staticmethod
    def get_ip_hosts(l3_port):
        return l3_port.hld_obj.get_ipv4_hosts()

    @staticmethod
    def delete_host(l3_port, dip):
        return l3_port.hld_obj.delete_ipv4_host(dip.hld_obj)


class ipv6_test_base:
    BYTES_NUM_IN_ADDR = 16

    @staticmethod
    def build_prefix(dip, length):
        prefix = sdk.la_ipv6_prefix_t()
        q0 = sdk.get_ipv6_addr_q0(dip.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(dip.hld_obj)
        masked_q0, masked_q1 = ipv6_test_base.apply_prefix_mask(q0, q1, length)
        sdk.set_ipv6_addr(prefix.addr, masked_q0, masked_q1)
        prefix.length = length
        return prefix

    @staticmethod
    def get_default_prefix():
        prefix = sdk.la_ipv6_prefix_t()
        sdk.set_ipv6_addr(prefix.addr, 0, 0)
        prefix.length = 0
        return prefix

    @staticmethod
    def apply_prefix_mask(q0, q1, prefix_length):
        dqw_addr = q1 << 64 | q0
        mask = ~((1 << (CHAR_BIT * ipv6_test_base.BYTES_NUM_IN_ADDR - prefix_length)) - 1)
        dqw_addr = dqw_addr & mask
        masked_q0 = dqw_addr & ((1 << 64) - 1)
        masked_q1 = dqw_addr >> 64
        return masked_q0, masked_q1

    @staticmethod
    def add_route(vrf, prefix, l3_dest, private_data, latency_sensitive=False):
        return vrf.hld_obj.add_ipv6_route(prefix, l3_dest.hld_obj, private_data, latency_sensitive)

    @staticmethod
    def modify_route(vrf, prefix, l3_dest):
        return vrf.hld_obj.modify_ipv6_route(prefix, l3_dest.hld_obj)

    @staticmethod
    def delete_route(vrf, prefix):
        return vrf.hld_obj.delete_ipv6_route(prefix)

    @staticmethod
    def ip_route_bulk_entry(action, prefix, l3_dest, class_id, private_data, latency_sensitive):
        prefix_update = sdk.la_ipv6_route_entry_parameters()
        prefix_update.action = action
        prefix_update.prefix = prefix
        if (action != sdk.la_route_entry_action_e_DELETE):
            prefix_update.destination = l3_dest
            prefix_update.is_class_id_set = True
            prefix_update.class_id = class_id
            prefix_update.is_user_data_set = True
            prefix_update.user_data = private_data

        if (action == sdk.la_route_entry_action_e_ADD):
            prefix_update.latency_sensitive = latency_sensitive
        return prefix_update

    @staticmethod
    def ip_route_bulk_updates(vrf, prefixes_update_vec):
        return vrf.hld_obj.ipv6_route_bulk_updates(prefixes_update_vec)

    @staticmethod
    def get_route(vrf, dip):
        return vrf.hld_obj.get_ipv6_route(dip.hld_obj)

    @staticmethod
    def clear_all_routes(vrf):
        return vrf.hld_obj.clear_all_ipv6_routes()

    @staticmethod
    def get_routing_entry(vrf, prefix):
        return vrf.hld_obj.get_ipv6_routing_entry(prefix)

    @staticmethod
    def add_subnet(l3_port, prefix):
        return l3_port.hld_obj.add_ipv6_subnet(prefix)

    @staticmethod
    def delete_subnet(l3_port, prefix):
        return l3_port.hld_obj.delete_ipv6_subnet(prefix)

    @staticmethod
    def get_subnets(l3_port):
        return l3_port.hld_obj.get_ipv6_subnets()

    @staticmethod
    def add_host(l3_port, dip, mac):
        return l3_port.hld_obj.add_ipv6_host(dip.hld_obj, mac.hld_obj)

    @staticmethod
    def add_host_with_class_id(l3_port, dip, mac, class_id):
        return l3_port.hld_obj.add_ipv6_host(dip.hld_obj, mac.hld_obj, class_id)

    @staticmethod
    def modify_host(l3_port, dip, mac):
        return l3_port.hld_obj.modify_ipv6_host(dip.hld_obj, mac.hld_obj)

    @staticmethod
    def modify_host_with_class_id(l3_port, dip, mac, class_id):
        return l3_port.hld_obj.modify_ipv6_host(dip.hld_obj, mac.hld_obj, class_id)

    @staticmethod
    def get_host(l3_port, dip):
        return l3_port.hld_obj.get_ipv6_host(dip.hld_obj)

    @staticmethod
    def get_ip_hosts(l3_port):
        return l3_port.hld_obj.get_ipv6_hosts()

    @staticmethod
    def delete_host(l3_port, dip):
        return l3_port.hld_obj.delete_ipv6_host(dip.hld_obj)
