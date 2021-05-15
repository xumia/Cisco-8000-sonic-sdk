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

# The function can create a list of various permutations of ACL table attributes and return
# each permutation set as list element. The caller of the function is expected
# to use each list element as an UDK acl profile and test it.


def create_v4_udk_acl_profiles():
    acl_attr_list = []
    # Case 1:
    # Run UDK tests with single list of v4 fields.
    acl_attrs = []
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
            S.SAI_ACL_TABLE_ATTR_FIELD_TTL,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS]:
            # When used with UDK, key size spills over 160 to 164bits..
            # NSIM_TABLE - [ERROR] Tried to place udk with key size 164 bigger than available, macro_id 11 key size type 160 const key width 7
            # S.SAI_ACL_TABLE_ATTR_FIELD_ICMP_CODE,
            # S.SAI_ACL_TABLE_ATTR_FIELD_ICMP_TYPE]:
        acl_attrs.append(attr)
    acl_attr_list.append(acl_attrs)

    # Case 2:
    # Run UDK tests with multiple lists of v4 fields; With first set being subset of second set.
    multi_udk_list = []
    acl_attrs = []
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
            S.SAI_ACL_TABLE_ATTR_FIELD_TTL,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT]:
        acl_attrs.append(attr)
    multi_udk_list.append(acl_attrs)
    acl_attrs = []
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
            S.SAI_ACL_TABLE_ATTR_FIELD_TTL,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS]:
        acl_attrs.append(attr)
    multi_udk_list.append(acl_attrs)
    acl_attr_list.append(multi_udk_list)

    # Case 3:
    # Run UDK tests with multiple lists of v4 fields; With second set being subset of first set.
    multi_udk_list = []
    acl_attrs = []
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
            S.SAI_ACL_TABLE_ATTR_FIELD_TTL,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS]:
        acl_attrs.append(attr)
    multi_udk_list.append(acl_attrs)
    acl_attrs = []
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
            S.SAI_ACL_TABLE_ATTR_FIELD_TTL,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT]:
        acl_attrs.append(attr)
    multi_udk_list.append(acl_attrs)
    acl_attr_list.append(multi_udk_list)

    # Case 4:
    # Run UDK tests with both v4 and v6 fields. This should test
    # SAI code to seperate combined v4 and v6 UDK fields into
    # two sets.
    acl_attrs = []
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            # Enable when object group ACL is available.
            # S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
            # S.SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
            # S.SAI_ACL_TABLE_ATTR_FIELD_TTL,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT]:
            # S.SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT]:
            # S.SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS]:
        acl_attrs.append(attr)
    acl_attr_list.append(acl_attrs)

    return acl_attr_list


def generate_ipv4_acl_udk_key():
    args = {}
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
            # S.SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
            # S.SAI_ACL_TABLE_ATTR_FIELD_TTL,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT]:
            # S.SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT]:
            # S.SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS]:
        args[attr] = True
    return args


def create_v4_custom_udk_acl_profiles():
    acl_attr_list = []
    acl_attrs = []
    # Case 1:
    # Run ACL test with UDF field in v4 match profile.
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            # S.SAI_ACL_TABLE_ATTR_FIELD_INNER_IP_PROTOCOL,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
            # S.SAI_ACL_TABLE_ATTR_FIELD_TTL,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_INNER_L4_SRC_PORT]:
        acl_attrs.append(attr)
    acl_attr_list.append(acl_attrs)

    # Case 2:
    # Run UDK tests with both v4 and v6 fields. This should test
    # SAI code that seperates combined v4 and v6 UDK fields into
    # two sets one for each protocol.
    acl_attrs = []
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            # Enable when object group ACL is available.
            # S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            # S.SAI_ACL_TABLE_ATTR_FIELD_INNER_IP_PROTOCOL,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
            # S.SAI_ACL_TABLE_ATTR_FIELD_TTL,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT]:
            # S.SAI_ACL_TABLE_ATTR_FIELD_INNER_L4_SRC_PORT]:
        acl_attrs.append(attr)
    acl_attr_list.append(acl_attrs)

    return acl_attr_list


def generate_ipv4_acl_custom_udk_key():
    args = {}
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            # S.SAI_ACL_TABLE_ATTR_FIELD_INNER_IP_PROTOCOL,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
            # S.SAI_ACL_TABLE_ATTR_FIELD_TTL,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT]:
            # S.SAI_ACL_TABLE_ATTR_FIELD_INNER_L4_SRC_PORT]:
        args[attr] = True
    return args


def create_v4_udk_with_route_metadata_acl_profile():
    acl_attr_list = []
    acl_attrs = []
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
            S.SAI_ACL_TABLE_ATTR_FIELD_TTL,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_ROUTE_DST_USER_META]:
        acl_attrs.append(attr)
    acl_attr_list.append(acl_attrs)
    return acl_attr_list


def generate_ipv4_acl_udk_route_metadata_key():
    args = {}
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
            S.SAI_ACL_TABLE_ATTR_FIELD_TTL,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_ROUTE_DST_USER_META]:
        args[attr] = True
    return args


def create_v4_udk_with_neighbor_metadata_acl_profile():
    acl_attr_list = []
    acl_attrs = []
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
            S.SAI_ACL_TABLE_ATTR_FIELD_TTL,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_NEIGHBOR_DST_USER_META]:
        acl_attrs.append(attr)
    acl_attr_list.append(acl_attrs)
    return acl_attr_list


def generate_ipv4_acl_udk_neighbor_metadata_key():
    args = {}
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
            S.SAI_ACL_TABLE_ATTR_FIELD_TTL,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_NEIGHBOR_DST_USER_META]:
        args[attr] = True
    return args


def create_v4_udk_with_l3_dest_metadata_acl_profile():
    acl_attr_list = []
    acl_attrs = []
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
            S.SAI_ACL_TABLE_ATTR_FIELD_TTL,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_ROUTE_DST_USER_META,
            S.SAI_ACL_TABLE_ATTR_FIELD_NEIGHBOR_DST_USER_META]:
        acl_attrs.append(attr)
    acl_attr_list.append(acl_attrs)
    return acl_attr_list


def generate_ipv4_acl_udk_l3_dest_metadata_key():
    args = {}
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
            S.SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
            S.SAI_ACL_TABLE_ATTR_FIELD_TTL,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT,
            S.SAI_ACL_TABLE_ATTR_FIELD_ROUTE_DST_USER_META,
            S.SAI_ACL_TABLE_ATTR_FIELD_NEIGHBOR_DST_USER_META]:
        args[attr] = True
    return args


def create_l2_v4_v6_udk_acl_profiles():
    acl_attr_list = []
    acl_attrs = []
    # Case 1:
    # Run ACL test with L2, L4 with v4 fields match profile.
    for attr in [
            # S.SAI_ACL_TABLE_ATTR_FIELD_ETHER_TYPE,
            S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_MAC,
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT]:
            # S.SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT]:
            # NSIM error 19 byte ACL key becomes 163bits
            # 21.08.2020 15:31:06 - NSIM_TABLE [ERROR   ] Tried to place udk with key size 163 bigger than available, macro_id 14 key size type 160 const key width 7
            # 21.08.2020 15:31:06 - NSIM_PACKET [ERROR   ] place_udk failed, macro id 14, table id 0, number of udk components 7
            # 21.08.2020 15:31:06 - NSIM       [ERROR   ] place_udk command failed, error num 3
        acl_attrs.append(attr)
    acl_attr_list.append(acl_attrs)

    # Case 2:
    # Run UDK tests with both v4 and v6 fields. This should test
    # SAI code that seperates combined v4 and v6 UDK fields into
    # two sets one for each protocol.
    acl_attrs = []
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_MAC,
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6,
            S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
            S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT]:
            # S.SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT]:
        acl_attrs.append(attr)
    acl_attr_list.append(acl_attrs)

    # Case 3:
    # Run UDK test with TTL and v6 fields. These match qualifiers has to be applied on v6 packets alone.
    acl_attrs = []
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6,
            # Enable when object group ACL is available.
            # S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6,
            S.SAI_ACL_TABLE_ATTR_FIELD_TTL]:
        acl_attrs.append(attr)
    acl_attr_list.append(acl_attrs)

    # Case 4:
    # Run UDK test with TTL and v4 fields. These match qualifiers has to be applied on v4 packets alone.
    acl_attrs = []
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_TTL]:
        acl_attrs.append(attr)
    acl_attr_list.append(acl_attrs)

    # Case 5:
    # Run UDK test with TTL only. This match qualifier has to be applied on both v4  and v6 packets.
    acl_attrs = []
    # UDK placer issue
    for attr in [S.SAI_ACL_TABLE_ATTR_FIELD_TTL]:
        acl_attrs.append(attr)
    acl_attr_list.append(acl_attrs)

    return acl_attr_list


def generate_l2_v4_v6_udk_acl_key(profile_case):
    args = {}
    if profile_case == 0:
        for attr in [
                S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
                S.SAI_ACL_TABLE_ATTR_FIELD_DST_MAC,
                S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
                S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
                S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
                S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
                S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT]:
            # S.SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT]:
            args[attr] = True
    elif profile_case == 1:
        for attr in [
                S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
                S.SAI_ACL_TABLE_ATTR_FIELD_DST_MAC,
                S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
                S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
                S.SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6,
                S.SAI_ACL_TABLE_ATTR_FIELD_DSCP,
                S.SAI_ACL_TABLE_ATTR_FIELD_ECN,
                S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT]:
            # S.SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT]:
            args[attr] = True
    elif profile_case == 2:
        for attr in [
                S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
                S.SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6,
                # Enable when object group ACL is available.
                # S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6,
                S.SAI_ACL_TABLE_ATTR_FIELD_TTL]:
            args[attr] = True
    elif profile_case == 3:
        for attr in [
                S.SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
                S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
                S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
                S.SAI_ACL_TABLE_ATTR_FIELD_TTL]:
            args[attr] = True
    elif profile_case == 4:
        for attr in [S.SAI_ACL_TABLE_ATTR_FIELD_TTL]:
            args[attr] = True

    return args


def create_l2_v4_v6_l2cid_acl_profiles():
    acl_attr_list = []
    acl_attrs = []
    # Case 1:
    # Run ACL test with L2, L4 with v4 fields match profile.
    for attr in [
            # S.SAI_ACL_TABLE_ATTR_FIELD_ETHER_TYPE,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_MAC,
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_FDB_DST_USER_META,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT]:
        acl_attrs.append(attr)
    acl_attr_list.append(acl_attrs)

    # Case 2:
    # Run UDK tests with both v4 and v6 fields. This should test
    # SAI code that seperates combined v4 and v6 UDK fields into
    # two sets one for each protocol.
    acl_attrs = []
    for attr in [
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_MAC,
            S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
            S.SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6,
            S.SAI_ACL_TABLE_ATTR_FIELD_FDB_DST_USER_META,
            S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT]:
        acl_attrs.append(attr)
    acl_attr_list.append(acl_attrs)

    return acl_attr_list


def generate_l2_v4_v6_l2cid_acl_key(profile_case):
    args = {}
    if profile_case == 0:
        for attr in [
                S.SAI_ACL_TABLE_ATTR_FIELD_DST_MAC,
                S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
                S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
                S.SAI_ACL_TABLE_ATTR_FIELD_FDB_DST_USER_META,
                S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT]:
            args[attr] = True
    elif profile_case == 1:
        for attr in [
                S.SAI_ACL_TABLE_ATTR_FIELD_DST_MAC,
                S.SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
                S.SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
                S.SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6,
                S.SAI_ACL_TABLE_ATTR_FIELD_FDB_DST_USER_META,
                S.SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT]:
            args[attr] = True
    return args
