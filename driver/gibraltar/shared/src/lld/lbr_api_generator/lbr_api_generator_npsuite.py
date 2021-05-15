#!/usr/bin/env python3
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

import os
import json
import io

# @brief Writes to npsuite_lbr.json based on parsed lbr files


def write_npsuite_lbr_json(file_name, lbr_parsed, uids_to_block_name, additional_blocks, sbif_overrides):
    global asic_name
    path, file = os.path.split(file_name)
    asic_path, file = os.path.split(path)
    asic_name = os.path.basename(asic_path).lower()

    blocks = {}
    names = []
    other_revisions = []
    for block_data in lbr_parsed.values():
        block_name = block_data['Name']
        names.append(block_name)
        members = {}
        # Write registers
        block_members = block_data['Registers']
        for reg_element in block_members:
            mem_revisions = [reg_element]
            member_revisions_dict = {}
            if reg_element['OtherRevisions'] != []:
                other_revisions = reg_element['OtherRevisions']
                for other_rev in other_revisions:
                    mem_revisions.append(other_rev['regmem_dict'])
            for reg_dict in mem_revisions:
                member_dict = {}
                member_dict['name'] = reg_dict['Name']
                # block_member_name = block_name + "_" + member_name
                member_dict['type'] = 'register'
                member_address = get_address(block_name, reg_dict, sbif_overrides)
                member_dict['width'] = int(reg_dict['Width'])
                member_dict['desc'] = reg_dict['Description']
                member_dict['entries'] = reg_dict['ArrayLength']
                member_dict['default_values'] = hex_array_to_default_value(reg_dict['DefaultValue'][0])
                member_dict['subfields'] = get_subfields(reg_dict['Fields'])
                revision_name = 'all'
                if len(reg_dict['ValidInRevisions']) == 1 or reg_dict['RevisionName'] != 'rev2' or len(mem_revisions) > 1:
                    revision_name = reg_dict['RevisionName']
                member_revisions_dict[revision_name] = member_dict
            members[member_address.lower()] = member_revisions_dict

        # Write memories
        block_members = block_data['Memories']
        for mem_element in block_members:
            member_address = get_address(block_name, mem_element, sbif_overrides)
            member_dict = {}
            mem_revisions = [mem_element]
            member_revisions_dict = {}
            if mem_element['OtherRevisions'] != []:
                other_revisions = mem_element['OtherRevisions']
                for other_rev in other_revisions:
                    mem_revisions.append(other_rev['regmem_dict'])
            for mem_dict in mem_revisions:
                member_dict['name'] = mem_dict['Name']
                member_dict['type'] = 'memory'
                member_dict['subtype'] = mem_dict['SubType'].lower()
                member_dict['width'] = get_mem_width(mem_dict)
                member_dict['desc'] = mem_dict['Description']
                member_dict['entries'] = get_mem_entries(block_name, mem_dict, sbif_overrides)
                member_dict['array_length'] = int(mem_dict['ArrayLength'])
                def_val = mem_dict.get('DefaultValue')
                if def_val is None:
                    member_dict['default_values'] = 0x0
                else:
                    member_dict['default_values'] = hex_array_to_default_value(mem_dict['DefaultValue'][0])
                member_dict['subfields'] = get_subfields(mem_dict['Fields'])
                revision_name = 'all'
                if len(mem_dict['ValidInRevisions']) == 1 or mem_dict['RevisionName'] != 'rev2' or len(mem_revisions) > 1:
                    revision_name = mem_dict['RevisionName']
                member_revisions_dict[revision_name] = member_dict
            members[member_address.lower()] = member_revisions_dict
        blocks[block_name] = members
    for block_name, block_data in additional_blocks.items():
        if block_name not in names:
            names.append(block_name)
            members = {}
            block_members = block_data['Registers']
            for reg_element in block_members:
                mem_revisions = [reg_element]
                member_revisions_dict = {}
                if reg_element['OtherRevisions'] != []:
                    other_revisions = reg_element['OtherRevisions']
                    for other_rev in other_revisions:
                        mem_revisions.append(other_rev['regmem_dict'])
                for reg_dict in mem_revisions:
                    member_dict = {}
                    member_dict['name'] = reg_dict['Name']
                    member_dict['type'] = 'register'
                    member_dict['entries'] = reg_dict['ArrayLength']
                    member_address = reg_dict['Address']
                    width = reg_dict.get('Width')
                    if width is None:
                        member_dict['width'] = 0
                    else:
                        member_dict['width'] = width
                    member_dict['desc'] = reg_dict['Description']
                    member_dict['default_values'] = hex_array_to_default_value(reg_dict['DefaultValue'][0])
                    member_dict['subfields'] = get_subfields(reg_dict['Fields'])
                    member_revisions_dict[revision_name] = member_dict
                members[member_address.lower()] = member_revisions_dict

            # Write memories
            block_members = block_data['Memories']
            for mem_element in block_members:
                member_address = mem_dict['Address']
                member_dict = {}
                mem_revisions = [mem_element]
                member_revisions_dict = {}
                if mem_element['OtherRevisions'] != []:
                    other_revisions = mem_element['OtherRevisions']
                for other_rev in other_revisions:
                    mem_revisions.append(other_rev['regmem_dict'])
                for mem_dict in mem_revisions:
                    member_dict['name'] = mem_dict['Name']
                    member_dict['type'] = 'memory'
                    member_dict['width'] = get_mem_width(mem_dict)
                    member_dict['desc'] = mem_dict['Description']
                    member_dict['entries'] = mem_dict['MemEntries']
                    member_dict['array_length'] = int(mem_dict['ArrayLength'])
                    def_val = mem_dict.get('DefaultValue')
                    if def_val is None:
                        member_dict['default_values'] = 0x0
                    else:
                        member_dict['default_values'] = hex_array_to_default_value(mem_dict['DefaultValue'][0])
                    member_dict['subfields'] = get_subfields(mem_dict['Fields'])
                    member_revisions_dict[revision_name] = member_dict
                members[member_address.lower()] = member_revisions_dict
            blocks[block_name] = members

    tags = {}
    tags['uid_to_block_instance'] = uids_to_block_name
    tags['block_structures'] = blocks
    root = {}
    root['lbr_definitions'] = tags
    print("dumping to file")
    with open(file_name, 'w', encoding='utf-8') as outfile:
        json.dump(root, outfile, ensure_ascii=False, indent=4, separators=(',', ': '))


# @brief Generate addresses, optionally add offset.
#
# @param[in] block_name                     Name of a block that owns this memory
# @param[in] regmem_dict                    Register or Memory dict
# @param[in] sbif_overrides                 Overrides specific to SBIF
def get_address(block_name, regmem_dict, sbif_overrides):
    addr = regmem_dict['Address']
    name = regmem_dict['Name']

    # add offset
    if (block_name == 'sbif') and not (name in sbif_overrides['base_address_skip_names']):
        return hex(int(addr, 16) + int(sbif_overrides['base_address'], 16))

    return addr


# @brief Get an int for number of memory entries
#
# Optionally, multiply by a factor and fixup XY TCAM.
#
# @param[in] block_name                     Name of a block that owns this memory
# @param[in] mem_dict                       Memory dict
# @param[in] sbif_overrides                 Overrides specific to SBIF


def get_mem_entries(block_name, mem_dict, sbif_overrides):
    mem_entries = mem_dict['MemEntries']
    if block_name == 'sbif':
        mem_entries *= int(sbif_overrides['phys_per_logical'])

    # in XY tcams, each entry takes two lines
    if mem_dict['SubType'] == "X_Y_TCAM" or mem_dict['SubType'] == "KEY_MASK_TCAM":
        mem_entries *= 2

    return mem_entries


def get_mem_width(mem_dict):
    if mem_dict['SubType'] in ["REG_TCAM", "X_Y_TCAM", "KEY_MASK_TCAM"]:
        # use total width for reg, XY, and key/mask TCAMs to include "delete" bit
        return int(mem_dict['MemTotalWidth'])
    else:
        return int(mem_dict['MemLogicalWidth'])


def hex_array_to_default_value(dic):
    if len(dic) == 0:
        return '0x0'
    ret_val = 0
    for i in range(0, len(dic)):
        ret_val = ret_val + (int(dic[i], 0) << 8 * i)
    return str(hex(ret_val))


# @brief Gets subfields of a parsed register or memory field.
#
# @param[in] fields         Subfields of parsed register or memory
#
# @return Dictionary of subfield position to subfield name, type, width and description.
def get_subfields(fields):
    subfields = {}

    for field_elem in fields:
        field = {}
        field['name'] = field_elem['Name']
        field['type'] = field_elem['Type']
        field['width'] = field_elem['Width']
        field['desc'] = field_elem['Description']
        try:
            position_high, position_low = field_elem['Position'].split(':')
            position = position_low
        except ValueError:
            position = field_elem['Position']
        except BaseException:
            print("Error while handling field_elem['Position'] = %s in get_subfields()" % field['Position'])
            raise
        subfields[position] = field

    return subfields
