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
from parser_formats import lpm_instruction
import ipaddress

IPV6_INDICATOR = 1

IPV4_INDICATOR = 0

IPV6_ADDRESS_LENGTH = 128

IPV4_ADDRESS_LENGTH = 32

VRF_LENGTH = 11

IPV6_FULL_ADDRESS_LENGTH = IPV6_ADDRESS_LENGTH + VRF_LENGTH + 1

IPV4_FULL_ADDRESS_LENGTH = IPV4_ADDRESS_LENGTH + VRF_LENGTH + 1


# ---------------- Prefix Tree ----------------- #


class prefix_node:
    def __init__(self, new_prefix, new_value=None):
        self.left = None
        self.right = None
        self.prefix = new_prefix  # A binary string!
        self.value = new_value

    def insert_left(self, new_node):
        """
        Inserts a node to the left (without checking)
        :param new_node: The new node
        :return: None
        """
        if self.left is None:
            self.left = prefix_node(self.prefix + '0')
        self.left.insert(new_node)

    def insert_right(self, new_node):
        """
        Inserts a node to the right (without checking)
        :param new_node: The new node
        :return: None
        """
        if self.right is None:
            self.right = prefix_node(self.prefix + '1')
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
            self.value = new_node.value
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
        return '(' + left_repr + ') [' + self.prefix + ', ' + str(self.value) + '] (' + right_repr + ')'


class prefix_tree:
    def __init__(self, list_of_inserts=()):
        self.root = prefix_node('')
        for (prefix, value) in list_of_inserts:
            self.insert(prefix, value)

    def insert(self, prefix, value):
        """
        Inserts a new pair of (prefix, value) to the prefix tree
        :param prefix: The prefix (in binary representation)
        :param value: The value
        :return: If the insertion was successful
        """
        return self.root.insert(prefix_node(prefix, value))

    def find(self, key):
        return self.root.find(key)

    def __repr__(self):
        return str(self.root)


# ---------------- Functions ----------------- #


def int_to_binary(integer):
    """
    Converts an integer into a binary string
    :param integer: The integer
    :return: The binary string representing the integer
    """
    return bin(integer)[2:]


def format_prefix(prefix_value, prefix_size):
    """
    Converts a prefix to binary representation
    :param prefix_value: The integer value of the prefix
    :param prefix_size: The size of the prefix
    :return: The binary representation of the prefix
    """
    prefix = int_to_binary(prefix_value)  # Converts to binary

    return '0' * (prefix_size - len(prefix)) + prefix


def get_prefix_value_and_size(instruction):
    """
    Gets an instruction and returns the integer value and length of the instruction's prefix
    :param instruction: The instruction
    :return: prefix_value, prefix_length
    """
    address_type = IPV4_INDICATOR if isinstance(instruction.ip_address, ipaddress.IPv4Network) else IPV6_INDICATOR
    full_address_length = IPV4_ADDRESS_LENGTH if address_type == IPV4_INDICATOR else IPV6_ADDRESS_LENGTH
    key_value = address_type << instruction.ip_address.prefixlen + VRF_LENGTH
    key_value += instruction.vrf << instruction.ip_address.prefixlen
    key_value += int(instruction.ip_address.network_address) >> (full_address_length - instruction.ip_address.prefixlen)
    return key_value, instruction.ip_address.prefixlen + VRF_LENGTH + 1


def address_from_prefix(prefix):
    """
    Returns a full address that matches the given prefix
    :param prefix: The prefix
    :return: A pair of address matches the prefix (as int value) and it's length
    """
    if prefix == '':
        return '0' * IPV4_FULL_ADDRESS_LENGTH
    if prefix[0] == '0':
        return int(prefix + '0' * (IPV4_FULL_ADDRESS_LENGTH - len(prefix)), 2), IPV4_FULL_ADDRESS_LENGTH
    elif prefix[0] == '1':
        return int(prefix + '0' * (IPV6_FULL_ADDRESS_LENGTH - len(prefix)), 2), IPV6_FULL_ADDRESS_LENGTH


def parse_instruction(insertions, instruction):
    """
    Performs the appropriate changes in the insertion list according to the given instruction
    :param insertions: The insertion list
    :param instruction: The instruction
    :return: None
    """
    address_value, prefix_size = get_prefix_value_and_size(instruction)
    address = format_prefix(address_value, prefix_size)
    if instruction.action in (lpm_instruction.INSERT, lpm_instruction.MODIFY):
        value = instruction.payload
        if address in insertions:
            insertions.pop(address)
        insertions[address] = value
    elif instruction.action == lpm_instruction.REMOVE:
        if address in insertions:
            insertions.pop(address)


def create_insert_list(instructions):
    """
    Creates an insertions list that results in the same tree that is created by the given instructions
    :param instructions: A list of LpmInstruction
    :return: The appropriate insertion list
    """
    insertions = OrderedDict()
    for instruction in instructions:
        parse_instruction(insertions, instruction)
    return insertions.items()


def find_empty_leaf(node):
    """
    Finds an empty leaf in the tree that it's root is the given node
    :param node: The tree's root
    :return: An empty leaf if exists, else None
    """
    son = None
    if node.left is None and node.right is None:
        return node.prefix
    if node.left is None:
        return node.prefix + '0'
    if node.right is None:
        return node.prefix + '1'

    if node.left.value is None:
        son = find_empty_leaf(node.left)
    if son is None and node.right.value is None:
        son = find_empty_leaf(node.right)
    return son


def address_for_prefix(tree, prefix):
    """
    Finds an address that will be mapped to the node with the given prefix
    :param tree: The tree
    :param prefix: The prefix
    :return: The address
    """
    node = tree.find(prefix)
    if node is None:
        return None
    result = find_empty_leaf(node)
    if result is None:
        return None
    return address_from_prefix(result)


def generate_lookups_for_instructions(instructions):
    """
    Generates a list of lookup instructions that matches the tree that is generated by the given instruction list
    :param instructions: A list of instructions
    :return: A list of 3-tuples of (address (as int), address length, expected payload)
    """
    insert_list = create_insert_list(instructions)
    p_tree = prefix_tree(insert_list)  # Creates a prefix tree
    lookups = []
    for prefix, payload in insert_list:
        address = address_for_prefix(p_tree, prefix)
        if address is not None:
            address_value, address_length = address
            lookups.append((address_value, address_length, payload))
    return lookups


class normal_node_wrapper():
    def __init__(self, node):
        self.node = node

    def get_prefix(self):
        if self.node is None:
            return None
        return self.node.prefix

    def get_payload(self):
        if self.node is None:
            return None
        return self.node.value

    def get_left(self):
        node = self.node.left
        while node is not None and node.value is None and (node.left is None or node.right is None):
            node = node.left if node.left is not None else node.right
        return normal_node_wrapper(node)

    def get_right(self):
        node = self.node.right
        while node is not None and node.value is None and (node.left is None or node.right is None):
            node = node.right if node.right is not None else node.left
        return normal_node_wrapper(node)

    def __repr__(self):
        return "({}, {})".format(self.get_prefix(), self.get_payload())
