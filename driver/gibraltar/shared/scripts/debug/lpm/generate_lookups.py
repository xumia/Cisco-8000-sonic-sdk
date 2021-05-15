#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from collections import OrderedDict
import random


def prefix_to_binary_string(prefix, prefix_len):
    prefix_str = bin(prefix)[2:]
    missing_len = prefix_len - len(prefix_str)
    assert(missing_len >= 0)
    return '0' * missing_len + prefix_str

# ---------------- Prefix Tree ----------------- #


class PrefixNode:
    def __init__(self, new_prefix, new_payload=None):
        self.left = None
        self.right = None
        self.prefix = new_prefix  # A binary string!
        self.payload = new_payload

    def insert_left(self, new_node):
        """
        Inserts a node to the left (without checking)
        :param new_node: The new node
        :return: None
        """
        if self.left is None:
            self.left = PrefixNode(self.prefix + '0')
        self.left.insert(new_node)

    def insert_right(self, new_node):
        """
        Inserts a node to the right (without checking)
        :param new_node: The new node
        :return: None
        """
        if self.right is None:
            self.right = PrefixNode(self.prefix + '1')
        self.right.insert(new_node)

    def insert(self, new_node):
        """
        Inserts a new node to the subtree self is its root
        :param new_node: The new node to insert
        :return: If the insertion succeeded
        """
        if not new_node.prefix.startswith(self.prefix):
            return False

        if new_node.prefix == self.prefix:
            self.payload = new_node.payload
            return True

        prefix_length = len(self.prefix)
        if new_node.prefix[prefix_length] == '0':
            self.insert_left(new_node)
        elif new_node.prefix[prefix_length] == '1':
            self.insert_right(new_node)
        else:
            return False

        return True

    def find(self, key):
        if key == '':
            return self
        if key[0] == '0' and self.left is not None:
            return self.left.find(key[1:])
        elif key[0] == '1' and self.right is not None:
            return self.right.find(key[1:])
        return None

    def __repr__(self):
        left_repr = '' if self.left is None else str(self.left)
        right_repr = '' if self.right is None else str(self.right)
        return '(' + left_repr + ') [' + self.prefix + ', ' + str(self.payload) + '] (' + right_repr + ')'


class PrefixTree:
    def __init__(self, list_of_prefixes=[]):
        self.root = PrefixNode('')
        for (prefix, prefix_len, payload) in list_of_prefixes:
            self.insert(prefix, prefix_len, payload)

    def insert(self, prefix, prefix_len, payload):
        """
        Inserts a new entry of (prefix, prefix_len, payload) to the prefix tree
        :param prefix: The prefix
        :param prefix_len: The prefix length
        :param payload: The payload
        :return: If the insertion was successful
        """
        prefix_str = prefix_to_binary_string(prefix, prefix_len)
        return self.root.insert(PrefixNode(prefix_str, payload))

    def find(self, prefix, prefix_len):
        prefix_str = prefix_to_binary_string(prefix, prefix_len)
        return self.root.find(prefix_str)

    def __repr__(self):
        return str(self.root)


# ---------------- Functions ----------------- #


def hex_to_binary(hex_string):
    """
    Converts a hex string into a binary while keeping the leading zeros
    :param hex_string: The hex_string
    :return: The binary string
    """
    return bin(int(hex_string, base=16))[2:]


def format_address(hex_address, prefix_size):
    """
    Formats the prefix into binary proper form
    :param hex_address: The address in hexa
    :param prefix_size: The prefix size
    :return: The formatted prefix
    """
    address = hex_to_binary(hex_address)  # Converts to binary

    return '0' * (prefix_size - len(address)) + address


def complete_prefix(prefix, full_length, randomize_padding):
    """
    Returns a full address that matches the given prefix
    :param prefix: The prefix
    :return: An address mathces the prefix
    """
    assert((len(prefix) > 0) and prefix[0] in ['0', '1'])
    if randomize_padding:
        padding = ''.join(['%d' % random.randint(0, 1) for _ in range(full_length - len(prefix))])
    else:
        padding = '0' * (full_length - len(prefix))

    return hex(int(prefix + padding, 2))[2:]


def find_empty_leaf(node):
    son = None
    if node.left is None and node.right is None:
        return node.prefix
    if node.left is None:
        return node.prefix + '0'
    if node.right is None:
        return node.prefix + '1'

    if node.left.payload is None:
        son = find_empty_leaf(node.left)
    if son is None and node.right.payload is None:
        son = find_empty_leaf(node.right)
    return son


def address_for_prefix(tree, prefix, prefix_len, full_length, randomize_padding=False):
    node = tree.find(prefix, prefix_len)
    if node is None:
        return None
    result = find_empty_leaf(node)
    if result is None:
        return None
    return complete_prefix(result, full_length, randomize_padding)
