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


import json
import lldcli
import lbr_parsing_common
import re

# Interrupt types, must be in sync with driver/pacific/src/hld/interrupt_types.h - TODO
TYPE_MEM_PROTECT = 0
TYPE_ECC_1B = 1
TYPE_ECC_2B = 2
TYPE_MAC_LINK_DOWN = 3
TYPE_LINK_DOWN = 4
TYPE_MISCONFIGURATION = 5
TYPE_MAC_LINK_ERROR = 6
TYPE_LINK_ERROR = 7
TYPE_LACK_OF_RESOURCES = 8
TYPE_RESERVED_UNUSED = 9
TYPE_THRESHOLD_CROSSED = 10
TYPE_OTHER = 11
TYPE_SUMMARY = 12
TYPE_INFORMATIVE = 13
TYPE_DESIGN_BUG = 14
TYPE_NO_ERR_NOTIFICATION = 15
TYPE_NO_ERR_INTERNAL = 16
TYPE_COUNTER_THRESHOLD_CROSSED = 17
TYPE_CREDIT_DEV_UNREACHABLE = 18
TYPE_LPM_SRAM_ECC_1B = 19
TYPE_LPM_SRAM_ECC_2B = 20
TYPE_QUEUE_AGED_OUT = 21
TYPE_DRAM_CORRUPTED_BUFFER = 22
TYPE_LAST = 22

type_to_string = {
    TYPE_MEM_PROTECT: "MEM_PROTECT",
    TYPE_ECC_1B: "ECC_1B",
    TYPE_ECC_2B: "ECC_2B",
    TYPE_MAC_LINK_DOWN: "MAC_LINK_DOWN",
    TYPE_LINK_DOWN: "LINK_DOWN",
    TYPE_MISCONFIGURATION: "MISCONFIGURATION",
    TYPE_MAC_LINK_ERROR: "MAC_LINK_ERROR",
    TYPE_LINK_ERROR: "LINK_ERROR",
    TYPE_LACK_OF_RESOURCES: "LACK_OF_RESOURCES",
    TYPE_RESERVED_UNUSED: "RESERVED_UNUSED",
    TYPE_THRESHOLD_CROSSED: "THRESHOLD_CROSSED",
    TYPE_OTHER: "OTHER",
    TYPE_SUMMARY: "SUMMARY",
    TYPE_INFORMATIVE: "INFORMATIVE",
    TYPE_DESIGN_BUG: "DESIGN_BUG",
    TYPE_NO_ERR_NOTIFICATION: "NO_ERR_NOTIFICATION",
    TYPE_NO_ERR_INTERNAL: "NO_ERR_INTERNAL",
    TYPE_COUNTER_THRESHOLD_CROSSED: "COUNTER_THRESHOLD_CROSSED",
    TYPE_CREDIT_DEV_UNREACHABLE: "CREDIT_DEV_UNREACHABLE",
    TYPE_LPM_SRAM_ECC_1B: "LPM_SRAM_ECC_1B",
    TYPE_LPM_SRAM_ECC_2B: "LPM_SRAM_ECC_2B",
    TYPE_QUEUE_AGED_OUT: "QUEUE_AGED_OUT",
    TYPE_DRAM_CORRUPTED_BUFFER: "DRAM_CORRUPTED_BUFFER",
    TYPE_LAST: "LAST"
}

SW_ACTION_NONE = 0
SW_ACTION_HARD_RESET = 1
SW_ACTION_SOFT_RESET = 2
SW_ACTION_REPLACE_DEVICE = 3

sw_action_lookup = {
    '': '',
    SW_ACTION_NONE: 'SW_ACTION_NONE',
    SW_ACTION_HARD_RESET: 'SW_ACTION_HARD_RESET',
    SW_ACTION_SOFT_RESET: 'SW_ACTION_SOFT_RESET',
    SW_ACTION_REPLACE_DEVICE: 'SW_ACTION_REPLACE_DEVICE'
}

# JSON object types
OBJTYPE_REG = 'REG'
OBJTYPE_BIT = 'BIT'
OBJTYPE_NODE = 'NODE'

# Some known register addresses
REG_MASTER_INTERRUPT = lldcli.lld_register.MASTER_INTERRUPT
REG_MEM_PROTECT_INTERRUPT = lldcli.lld_register.MEM_PROTECT_INTERRUPT
REG_SELECTED_SER_ERROR_INFO = lldcli.lld_register.SELECTED_SER_ERROR_INFO
REG_SER_ERROR_DEBUG_CONFIGURATION = lldcli.lld_register.SER_ERROR_DEBUG_CONFIGURATION

# Bitfields of Leaba registers and memories, loaded from JSON
lbr_json = None


def initialize(lbr_filename):
    global lbr_json
    with open(lbr_filename, 'r') as f:
        lbr_json = json.loads(f.read())


def lld_register_is_interrupt(reg):
    return reg.get_desc().type == lldcli.lld_register_type_e_INTERRUPT


def lld_register_is_mask(reg):
    return reg.get_desc().type == lldcli.lld_register_type_e_INTERRUPT_MASK


def lld_register_to_dict(reg):
    if reg is None:
        return None
    return {
        'objtype': OBJTYPE_REG,
        'block_id': reg.get_block_id(),
        'addr': reg.get_desc().addr,
        'name': reg.get_name()
    }


def lld_register_from_dict(lbr_tree, reg_dict):
    reg = lbr_tree.get_register(reg_dict['block_id'], reg_dict['addr'])
    assert reg.get_name() == reg_dict['name']
    return reg


def master_interrupt_node(rstatus, bits):
    assert rstatus.get_desc().addr == REG_MASTER_INTERRUPT, "rstatus must be MASTER register"

    return interrupt_node(rstatus, None, bits)


# Interrupt node (status reg, mask reg, dictionary of bits)
def interrupt_node(rstatus, rmask, bits, is_mask_active_low=True, mem_protect_fields=None):
    assert rstatus is not None, "rstatus is not set"

    name = rstatus.get_name()
    assert rstatus.is_valid(), "reg={} is invalid".format(name)
    assert lld_register_is_interrupt(rstatus), "reg={} is not an interrupt register".format(name)

    # Master and Mem Protect interrupts do not have a mask register.
    # Master is unmaskable and Mem Protect is masked through dedicated mask regs.
    if rstatus.get_desc().addr in [REG_MASTER_INTERRUPT, REG_MEM_PROTECT_INTERRUPT]:
        assert not rmask, "mask must NOT be set for Master or Mem Protect {0}".format(name)
    else:
        assert rmask, "mask must be set for {0}".format(name)

    if rmask:
        assert rmask.get_block_id() != 0xffffffff, "rmask is not initialized"
        assert lld_register_is_mask(rmask), "{0} is not a mask register".format(rmask.get_name())
        assert rmask.get_desc().width_in_bits == rstatus.get_desc().width_in_bits,\
            "{0} status and mask widths do not match".format(name)

    assert len(bits) == rstatus.get_desc().width_in_bits, "bit count mismatch {} vs {}".format(
        len(bits), rstatus.get_desc().width_in_bits)

    for i, key in enumerate(bits):
        assert i == key, "'bits' dictionary is unordered, expected {0}, got {1}".format(i, key)

    # Convert this format LLD_REGISTER_MAC_POOL8_RX_LINK_STATUS_DOWN to this mac_pool8_rx_link_status_down
    key = rstatus.get_desc().name.replace('LLD_REGISTER_', '').lower()

    # Check that interrupt bits match with bit fields from lbr_json.
    try:
        for field in lbr_json[key]['fields']:
            name, pos, width = field[0], field[1], field[2]
            if name != bits[pos]['name']:
                print('ERROR: reg={}, pos={}, actual={}, expected={}'.format(rstatus.get_name(), pos, bits[pos]['name'], name))
                assert False
    except KeyError:
        print('ERROR: Key Error for {}, keys are:'.format(key))
        for key in lbr_json:
            print(key)
        assert False

    return {
        'objtype': OBJTYPE_NODE,
        'status': lld_register_to_dict(rstatus),   # Interrupt status register
        'mask': lld_register_to_dict(rmask),       # Interrupt mask register
        'mem_protect_fields': mem_protect_fields,  # Register fields, specific to mem_protect interrupt
        'is_mask_active_low': is_mask_active_low,  # Default is "active_high", this is the override.
        'bits': bits                               # Interrupt "cause" or "summary" bits
    }


def bit(LbrCamelCaseName, children=None, type=TYPE_SUMMARY, sw_action=SW_ACTION_NONE, is_masked=False):
    # A "cause" bit has no children.
    # A "summary" bit is normally mapped 1:1 to a single next-level node.
    # Rarely, "summary" bit is mapped 1:N to multiple next-level nodes.

    assert type >= 0 and type <= TYPE_LAST, "should be an integer between 0 and {}".format(TYPE_LAST)
    assert (type != TYPE_SUMMARY or children is not None), "type {0}, children {1}".format(type, children)

    snake_case_name = lbr_parsing_common.camel_case_to_underscore_delimiter(LbrCamelCaseName)

    return {
        'objtype': OBJTYPE_BIT,
        'name': snake_case_name,
        'type': type,
        'sw_action': sw_action,
        'children': children,
        'is_masked': is_masked}


def get_field(reg, field_name):
    key = reg.get_desc().name.lower().replace('lld_register_', '')
    for field in lbr_json[key]['fields']:
        name, pos, width = field[0], field[1], field[2]
        if name == field_name:
            return {'register_name': key, 'field_name': field_name, 'pos': pos, 'width': width}

    assert False, "Cannot find field {0} in register {1}".format(field_name, reg.get_name())


def dump_interrupt_tree(root):
    def node_cb(node, depth, unused):
        pass

    def bit_cb(node, bit, bit_i, depth, unused):
        prefix = '+' * depth + ' '
        print(prefix, '{0}:b{1} name={2}, type={3}'.format(node['status']['name'], bit_i, bit['name'], bit['type']))

    traverse_tree([root], 1, node_cb, None, bit_cb, None)
    print('----')


def to_json(root):
    return json.dumps(root, indent=2)


def traverse_tree(nodes, depth, node_cb, node_cb_args, bit_cb, bit_cb_args):
    if not len(nodes):
        return
    for node in nodes:
        node_cb(node, depth, node_cb_args)
        bits = node['bits']
        for i in bits:
            bit = bits[i]
            bit_cb(node, bit, i, depth, bit_cb_args)
            if bit['children']:
                traverse_tree(bit['children'], depth + 1, node_cb, node_cb_args, bit_cb, bit_cb_args)


def validate_and_print_summary(lbr_tree, all_interrupt_roots):
    stats0 = {'blocks_n': 0, 'reg_status_n': 0, 'reg_mask_n': 0, 'bits_n': 0, 'regs': []}
    for root in all_interrupt_roots:
        validate_and_get_interrupt_tree_stats(root, stats0)

    stats1 = {'blocks_n': 0, 'reg_status_n': 0, 'reg_mask_n': 0, 'bits_n': 0, 'regs': []}
    get_lbr_tree_stats(lbr_tree, stats1)

    not_in_tree_registers = list(set(stats1['regs']) - set(stats0['regs']))

    # Print all entries in stats0/1 except for 'regs', remove from dictionary before printing
    stats0.pop('regs')
    stats1.pop('regs')
    print('*** Interrupt tree stats', stats0)
    print('*** LBR tree stats', stats1)
    print('*** Model coverage: blocks %2.f%%, registers %.2f%%, bits %.2f%%' % (
        stats0['blocks_n'] * 100.0 / stats1['blocks_n'],
        stats0['reg_status_n'] * 100.0 / stats1['reg_status_n'],
        stats0['bits_n'] * 100.0 / stats1['bits_n']))
    print('*** Interrupt registers not in tree:', len(not_in_tree_registers))
    not_in_tree_registers.sort()
    for r in not_in_tree_registers:
        print('    ', r)


def get_lbr_tree_stats(lbr_tree, tree_stats):
    for block in lbr_tree.get_leaf_blocks():
        block_has_interrupt_regs = False
        for reg in block.get_registers():
            if lld_register_is_interrupt(reg):
                tree_stats['reg_status_n'] += 1
                tree_stats['bits_n'] += reg.get_desc().width_in_bits
                tree_stats['regs'] += [reg.get_name()]
                block_has_interrupt_regs = True
            elif lld_register_is_mask(reg):
                tree_stats['reg_mask_n'] += 1
        if block_has_interrupt_regs:
            tree_stats['blocks_n'] += 1
    return tree_stats


def validate_and_get_interrupt_tree_stats(root, tree_stats):
    def node_cb(node, depth, args):
        tree_stats, uniq_nodes = args[0], args[1]

        # Check that full path of 'status' register is unique, e.g. slice[5].npu.txpp.cluster[1].interrupt_register
        name = node['status']['name']
        assert name not in uniq_nodes, name + ' is not unique'
        uniq_nodes.add(name)

        # Accumulate stats
        tree_stats['reg_status_n'] += 1
        if node['status']['addr'] == REG_MASTER_INTERRUPT:
            tree_stats['blocks_n'] += 1
        if node['mask'] is not None:
            tree_stats['reg_mask_n'] += 1
        tree_stats['bits_n'] += len(node['bits'])
        tree_stats['regs'] += [name]

    def bit_cb(node, bit, bit_i, depth, unused):
        pass

    uniq_nodes = set()
    traverse_tree([root], 1, node_cb, (tree_stats, uniq_nodes), bit_cb, None)

    return tree_stats


# printing to the csv file
def print_tree(f, tr, asic):
    f.write("block,register,bit,bit_i,is_masked,reviewed,interrupt_type,notification_type,description,error_effect,app SW action\n")
    if asic == 'asic5':
        lld_tree = lldcli.asic5_tree.create(lldcli.la_device_revision_e_ASIC5_A0)
    elif asic == 'asic4':
        lld_tree = lldcli.asic4_tree.create(lldcli.la_device_revision_e_ASIC4_A0)
    elif asic == 'asic3':
        lld_tree = lldcli.asic3_tree.create(lldcli.la_device_revision_e_ASIC3_A0)
    elif asic == 'gibraltar':
        lld_tree = lldcli.gibraltar_tree.create(lldcli.la_device_revision_e_GIBRALTAR_A0)
    elif asic == 'pacific':
        lld_tree = lldcli.pacific_tree.create(lldcli.la_device_revision_e_PACIFIC_A0)
    else:
        exception_message = "parameter {} is not an asic".format(asic)
        raise Exception(exception_message)

    # A dictionary of unique LBR templates.
    # The key is a full path without the index numbers, e.g. cdb.core[].interrupt_register
    dict = tree_into_dict(tr, {}, lld_tree)

    # Arrange nodes by blocks
    nodes = list(dict.values())
    block_to_nodes = {}
    for node in nodes:
        reg = lld_register_from_dict(lld_tree, node['status'])
        block_name = reg.get_block().get_name()
        if block_name not in block_to_nodes:
            block_to_nodes[block_name] = [node]
        else:
            block_to_nodes[block_name].append(node)
    for block_name in sorted(block_to_nodes):
        block_to_nodes[block_name].sort(key=lambda node: node['status']['addr'])
        for node in block_to_nodes[block_name]:
            print_node(f, node, lld_tree)


def tree_into_dict(tree, dict, lld_tree):
    for node in tree:
        name = node['status']['name']
        name = re.sub(r'\[[0-9]+\]', '[]', name)  # removing duplications of blocks by remove digits from their index
        dict[name] = node
        for bit in node['bits']:
            if node['bits'][bit]['type'] == TYPE_SUMMARY:
                tree_into_dict(node['bits'][bit]['children'], dict, lld_tree)
    return dict


def print_node(f, node, lld_tree):
    reg = lld_register_from_dict(lld_tree, node['status'])
    block_name = reg.get_block().get_name()
    block_name = re.sub(r'\[[0-9]+\]', '[]', block_name)
    reg_name = reg.get_short_name()
    reg_name = re.sub(r'\[[0-9]+\]', '[]', reg_name)
    for bit_i in node['bits']:
        print_bit(f, node['bits'][bit_i], block_name, reg_name, bit_i)


def print_bit(f, bit, block_name, reg_name, bit_i):
    s = "{},{},{},{},{},{},{},{},{},{},{}\n".format(
        block_name,
        reg_name,
        bit['name'],
        bit_i,
        bit['is_masked'],  # is masked
        "",  # reviewed
        type_to_string[bit['type']],
        "",  # TBD - Notification type
        "",  # TBD - Description
        "",  # TBD - error effect
        sw_action_lookup[bit['sw_action']]  # App SW action
    )
    f.write(s)
