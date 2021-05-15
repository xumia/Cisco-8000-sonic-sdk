#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import math
import re
import os
import json
import logging
import operator
import importlib

#######################################################
# Global variables
#######################################################

asic_name = None
leaba_prefix = "lld"
lld_prefix = "lld"
master_interrupt_address = 0x0

NPSUITE_TARGET = 'npsuite'

PACIFIC_ASIC_NAME = 'pacific'

REGS_WITH_DEFAULT_VALUE = ("CONFIG", "INTERRUPT_MASK")

TotalSizes = {}
TotalSizes['NumOfRegs'] = 0
TotalSizes['RegsSizeInBits'] = 0
TotalSizes['RegsSizeInBytes'] = 0
TotalSizes['RegsSizeInQWords'] = 0

TotalSizes['NumOfMemEntries'] = 0
TotalSizes['NumOfMemInstances'] = 0
TotalSizes['MemsSizeInBits'] = 0
TotalSizes['MemsPerEntrySizeInBytes'] = 0
TotalSizes['MemsPerEntrySizeInQWords'] = 0
TotalSizes['MemsPerInstanceSizeInBytes'] = 0
TotalSizes['MemsPerInstanceSizeInQWords'] = 0


#######################################################
# Start of functions definitions
#######################################################


def get_asic_name(target, filename):
    global asic_name
    target = target.lower() if target is not None else None
    if target == NPSUITE_TARGET:
        path, file = os.path.split(filename)
        asic_path, file = os.path.split(path)
        asic_name = os.path.basename(asic_path).lower()
    else:
        asic_name = os.path.basename(filename).lower()

    asic_path = 'lbr_params_{}'.format(asic_name)
    asic_module = asic_path.replace('/', '.')

    global asic_params
    asic_params = importlib.import_module(asic_module)

    return asic_name


# @brief Translate list of ['key=value',...] entries to dictionary {'key' : 'value', ...}
#
# @param[in] key_eq_val_list  List of 'key=value' strings
#
# @return The dictionary format of 'key=value'
def key_eq_val_to_dict(key_eq_val_list):
    result_dict = {}
    # if the list is empty, then return an empty dict
    if not key_eq_val_list:
        return result_dict

    for key_eq_val in key_eq_val_list:
        # sanity. the expected syntax for each item is EXACTLY 'key=value', no extra spaces
        if re.search(r'.=.', key_eq_val) is None:
            raise Exception(
                "bad argument format in item '{0}'. correct usage is 'block_name=val'. full argument list is {1}".format(
                    key_eq_val, key_eq_val_list))

        key, val = re.split('=', key_eq_val)
        # verify that each key appears only once
        if key in result_dict:
            raise Exception(
                "bad argument format in item '{0}'. a value for '{1}' appears twice. previous='{2}', new='{3}'".format(
                    key_eq_val, key, result_dict[key], val))

        result_dict[key] = val

    return result_dict


# @brief Builds a dictionary of all LBR files
#
# Iterate over all LBR files, collect their data in a single dict in a {blockname : block data} format
#
# @param[in] lbr_filenames  List of LBR filenames
#
# @return The dictionary format LBR files
def process_multiple_lbr_files(lbr_filenames):
    lbr_raw = []

    for lbr_filename in lbr_filenames:
        block_dict = process_lbr_file(lbr_filename)
        lbr_raw.append(block_dict)

    return lbr_raw

# @brief Builds a default value table from verilog file
#
# Load the default verilog file, parse and create a table
#
# @param[in] verilog_default  Default verilog file
#
# @return The table of verilog default macro


def parse_verilog_default(verilog_default):
    global akpg_default_table
    akpg_default_table = {}

    skip = False

    with open(verilog_default, 'r') as f:
        for line in f:
            line = line.strip().split('//')[0]
            match_ifdef = re.search(r'`ifdef\s+(\w+)', line)
            match_endif = re.search(r'`endif', line)
            match_define = re.search(r'`define\s+(\w+)\s+(\d+)', line)
            if match_ifdef:
                if match_ifdef.group(1) != asic_params.defaults_group:
                    skip = True
            elif match_endif:
                skip = False
            elif not skip and match_define:
                akpg_default_table[match_define.group(1)] = match_define.group(2)


# @brief Builds a dictionary from an LBR file
#
# Loads the LBR file, translates in into JSON format, and creates a dictionary from the JSON format
#
# @param[in] lbr_filename   LBR filename
#
# @return The dictionary format of the LBR file


def process_lbr_file(lbr_filename):
    logging.debug("Processing file '%s'", lbr_filename)
    if os.path.isfile(lbr_filename) == False:
        exception_message = "file '{0}' doesnt exist."\
                            .format(lbr_filename)
        raise Exception(exception_message)

    with open(lbr_filename, 'r', errors='replace') as lbr_file:
        perl_hash_str = lbr_file.read()
        json_str = translate_perl_hash_to_json(perl_hash_str)
        # in case the JSON parsing fails, add a custom message to the raised exception
        try:
            block_dict = json.loads(json_str)
        except Exception as inst:
            new_msg = "Failed to parse '{0}' as a JSON file after translation".format(lbr_filename)
            reraise(inst, new_msg)

        if len(block_dict) > 1:
            exception_message = "file '{0}' has more than one block definition. block names: %s"\
                                .format(lbr_filename, block_dict.keys())
            raise Exception(exception_message)
        return block_dict


# @brief Translates an LBR perl-hash format string to JSON format string
#
# @param[in] lbr_filename   LBR filename
#
# @return The LBR info on JSON format
def translate_perl_hash_to_json(perl_hash_str):
    # remove comments.
    # searches for: '{', spaces, '#', any text.
    # preserves the '{' with spaces
    no_comments_str = re.sub(r'([\{,][ ])#.*', r'\1', perl_hash_str)

    # the value part (of key : value) may heve linefeed (\n) or carriage-return (\r) characters. change them into spaces.
    # search for:  '=>', spaces, '"', any sequence except " and \n, '\n' - this should match only relevant lines, any sequence except ", '"'
    # call the remove_linefeed_newline function for the substitution
    escaped_values = re.sub(r'=>[ ]*"[^"\n]*\n[^"]*"', remove_linefeed_newline, no_comments_str)

    # enclose the key part (of key => value) with quotes, and replaces the => with :
    # search for spaces, any non-space sequence (this should be the key), spaces, =>, any sequence (this should be the value
    # replaces: the key as "key", and => as :
    key_value_str = re.sub(r'\n(\s*)(\w+)(\s*)=\>(.*)', r'\n\1"\2"\3:\4', escaped_values)

    # change the block definition in the header to the key:value syntax
    # searches for: <the beginning a line>, '$block', '{', any sequence (should be the block name), '}', spaces, =, spaces
    # creates: {, linefeed, "block name", :, {
    block_def_str = re.sub(r'^\$block\{(.*)\}([ ]*)=([ ]*)', r'{\n"\1"\2:\3', key_value_str)

    # change the '};' to ' } \n }' (the extra closing bracket is because in the block change one is added)
    block_end_str = re.sub(r'[\r]*\n\};', r'\n}\n}', block_def_str)

    # remove comma before close parenthesis (even through line feeds)
    # search for: ',' , spaces, linefeed, spaces, '}'
    # deletes the ','
    no_commas = re.sub(r',([ ]*[\r]*\n[ ]*\})', r'\1', block_end_str)

    # replace all non-text characters - the extended ASCII characters [0x80 .. 0xff] with a question mark
    no_extended_ascii = re.sub(r'[\x80-\xFF]', r'?', no_commas)

    final_str = no_extended_ascii

    return final_str


# @brief Changes linefeed (\n) and carraige-return(\r) characters to a space ' '
#
# @param[in] matchobj   A match-object that a a re.sub() finds
#
# @return The string with substituted \n\r characters
def remove_linefeed_newline(matchobj):
    orig_str = matchobj.group(0)
    # find an either an '\n' or '\r\ and change it to a space ' '.
    result = re.sub(r'(?<!\\)[\n\r]+', r' ', orig_str)  # re.sub(r'(?<!\\)\n', r'\\n', orig_str)
    return result

# @brief Parses the raw LBR dictionary and extracts information needed to create the C++ code.
#
# @param[in] lbr_raw        LBR in a JSON format
# @param[in] revision_name  LBR revision name
#
# @return A dictionary of parsed LBR data


def parse_raw_lbr(lbr_raw, revision_name, is_sv_convention):
    lbr_parsed = {}

    # lbr_raw is a list of dicts, where each element is a dict of a block:
    #   [{"block0_name": {...block0_data...}}, {"block1_name": {...block1_data...}}, ...]
    for block_dict in lbr_raw:
        assert len(block_dict) == 1, "there should be only one key in a dict"
        block_name = next(iter(block_dict))
        block_data = block_dict[block_name]
        logging.debug("parsing block '%s'", block_name)

        parsed_block_name = camel_case_to_underscore_delimiter(block_name, is_sv_convention)
        assert parsed_block_name not in lbr_parsed, "block " + str(parsed_block_name) + " already exists"

        lbr_parsed_block = {}   # temporary storage for the extracted data for a single block
        lbr_parsed_block_registers = []  # temporary storage for the registers data for a single block
        lbr_parsed_block_memories = []  # temporary storage for the memories data for a single block

        lbr_parsed_block['Name'] = parsed_block_name

        lbr_parsed[parsed_block_name] = lbr_parsed_block

        # block_data is a dictionary with keys being register and memory names, and values are their attributes
        for entry_name, entry_dict in block_data.items():
            logging.debug("parsing entry '%s'", entry_name)

            if entry_name == 'Defines_db' or entry_name == 'ProjectName' or entry_name == 'ProjectDocName':
                logging.debug("skipping entry '%s.%s'", block_name, entry_name)
                continue

            # sanity, all entries are expected to be of register or memory types. this
            # is indicated by a 'RegMem' key (the value is checked later).
            entry_type_key = 'RegMem'
            if entry_type_key not in entry_dict:
                exception_message = "block '{0}'  entry '{1}' doesnt have a '{2}' attribute.\n"\
                                    .format(block_name, entry_name, entry_type_key)
                if isinstance(entry_dict, dict):
                    exception_message += 'existing attributes: {0}'.format(entry_dict.keys())
                else:
                    exception_message += 'it doesnt have any attributes at all.'
                raise Exception(exception_message)

            entry_type = entry_dict[entry_type_key]
            if entry_type not in ('Reg', 'Mem'):
                exception_message = "block '{0}' entry '{1}' has unknown type '{2}'='{3}'"\
                                    .format(block_name, entry_name, entry_type_key, entry_type)
                raise Exception(exception_message)

            if entry_type == 'Reg':
                # entry is a register
                try:
                    parsed_register = parse_register_entry(entry_name, entry_dict, revision_name, is_sv_convention)
                except Exception as inst:
                    new_msg = "error in register='{0}' of block='{1}'".format(entry_name, block_name)
                    reraise(inst, new_msg)

                if parsed_register is not None:
                    if ('ArrayIndex' in parsed_register.keys()) and (parsed_register['ArrayIndex'] != 0):
                        first_reg_in_array = lbr_parsed_block_registers[-1]
                        assert first_reg_in_array['Name'] == parsed_register['Name'], "Registers in array are not parsed in sequence."
                        first_reg_in_array['DefaultValue'].append(parsed_register['DefaultValue'])
                        continue
                    lbr_parsed_block_registers.append(parsed_register)

                    TotalSizes['NumOfRegs'] += parsed_register['NumOfReg']
                    TotalSizes['RegsSizeInBits'] += parsed_register['SizeInBits']
                    TotalSizes['RegsSizeInBytes'] += parsed_register['SizeInBytes']
                    TotalSizes['RegsSizeInQWords'] += parsed_register['SizeInQWords']

            if entry_type == 'Mem':
                try:
                    parsed_memory = parse_memory_entry(entry_name, entry_dict, revision_name, is_sv_convention)
                except Exception as inst:
                    new_msg = "error in memory='{0}' of block='{1}'".format(entry_name, block_name)
                    reraise(inst, new_msg)

                if parsed_memory is not None:
                    lbr_parsed_block_memories.append(parsed_memory)

                    TotalSizes['NumOfMemEntries'] += parsed_memory['NumOfMemEntries']
                    TotalSizes['NumOfMemInstances'] += parsed_memory['NumOfMemInstances']
                    TotalSizes['MemsSizeInBits'] += parsed_memory['SizeInBits']
                    TotalSizes['MemsPerEntrySizeInBytes'] += parsed_memory['PerEntrySizeInBytes']
                    TotalSizes['MemsPerEntrySizeInQWords'] += parsed_memory['PerEntrySizeInQWords']
                    TotalSizes['MemsPerInstanceSizeInBytes'] += parsed_memory['PerInstanceSizeInBytes']
                    TotalSizes['MemsPerInstanceSizeInQWords'] += parsed_memory['PerInstanceSizeInQWords']

        # sort the registers and memories by their address field
        def entry_address_as_int(entry): return int(entry['Address'], 16)
        lbr_parsed_block_registers.sort(key=entry_address_as_int)
        lbr_parsed_block_memories.sort(key=entry_address_as_int)

        # store the registers and memories in the block data
        lbr_parsed_block['Registers'] = lbr_parsed_block_registers
        lbr_parsed_block['Memories'] = lbr_parsed_block_memories

    return lbr_parsed


# @brief Read and parse JSON file
#
# Extracts data from json file and return data struct equals to the file.
#
# @param[in] JSON file              File to parse.
#
# @return Data structure parsed from the file.
def parse_json_file(json_file):
    logging.debug("Processing JSON file '%s'", json_file)
    if os.path.isfile(json_file) == False:
        exception_message = "file '{0}' doesnt exist."\
                            .format(json_file)
        raise Exception(exception_message)

    with open(json_file, 'r', errors='replace') as fd:
        json_str = fd.read()
        # in case the JSON parsing fails, add a custom message to the raised exception
        try:
            data_parsed = json.loads(json_str)
        except Exception as inst:
            new_msg = "Failed to parse '{0}' as a JSON file after translation".format(json_file)
            reraise(inst, new_msg)

    return data_parsed


# @brief SDK overrides for register.
#
# Override/Add data to existing register entry.
#
# @param[in] reg_dict               The original register dictionary.
# @param[in] override_dict              The overrides datay.
#
# @return The parsed overridden register dictionary.
def override_lbr_regmem_data(reg_dict, override_dict):
    logging.debug("Overriding register data for '%s'", reg_dict['Name'])
    # Overrides register data
    for key in ['Description']:
        if key in override_dict:
            logging.debug("Overriding '%s' to '%s'", key, override_dict[key])
            reg_dict[key] = override_dict[key]

    # Overrides fields data
    if 'Fields' in override_dict:
        orig_fields = reg_dict['Fields']
        override_fields = override_dict['Fields']
        for (field_index, field_dict) in enumerate(orig_fields):
            if field_dict['Name'] not in override_fields:
                continue
            override_field = override_fields[field_dict['Name']]
            logging.debug("Overriding field '%s' to '%s'", override_field, field_dict)

            for key in ['Description', 'ArrayElementWidth']:
                if key in override_field:
                    field_dict[key] = override_field[key]

            orig_fields[field_index] = field_dict
        reg_dict['Fields'] = orig_fields

    return reg_dict


# Fix LBR representation of Register CAMs.
# Register CAMs are translated from LBR to HW with partially reversed order.
# Override SDK's representation to model that.
#
# A REG CAM has 3 fields: key, payload, valid.
# The order of key and payload should be swapped. Example:
#   LBR:
#       splitter_cache_lsb_em_cam_key [75:0] = 0x00000000000000350eab
#       splitter_cache_lsb_em_cam_payload [159:76] = 0x01a24580114a8000000000
#       splitter_cache_lsb_em_cam_valid [160:160] = 0x1
#   Should be:
#       splitter_cache_lsb_em_cam_payload [83:0] = 0x00000000000000350eab
#       splitter_cache_lsb_em_cam_key [159:84] = 0x1a24580114a80000000
#       splitter_cache_lsb_em_cam_valid [160:160] = 0x1
def override_reg_cam(mem):
    assert len(mem['Fields']) == 3, 'REG CAM should have 3 fields: key, payload, valid'
    assert '_key' in mem['Fields'][0]['Name'], '0th field should be *_key'
    assert '_payload' in mem['Fields'][1]['Name'], '1st field should be *_payload'
    assert '_valid' in mem['Fields'][2]['Name'], '2nd field should be *_valid'

    # Rearrange
    fields = [mem['Fields'][1], mem['Fields'][0], mem['Fields'][2]]

    width_0 = fields[0]['Width']
    width_1 = fields[1]['Width']
    fields[0]['PositionLow'] = 0
    fields[1]['PositionLow'] = width_0
    fields[0]['Position'] = '%d:%d' % (width_0 - 1, 0)
    fields[1]['Position'] = '%d:%d' % (width_0 + width_1 - 1, width_0)

    mem['Fields'] = fields

# @brief SDK overrides for lbr data
#
# Extracts data from LBR overrides json and assign to the lbr data model.
# Currently allowed override of field attributes: Description, ArrayElementWidth.
#
# @param[in] lbr_parsed             The parsed LBR data (blocks and their regs/mems/reg_fields).
# @param[in] lbr_overrides_filename      Json file with SDK overrides.
#
# @return The parsed LBR data that after overrides.


def override_lbr_data(lbr_parsed, lbr_overrides_filename):
    logging.debug("Using overrides file '%s'", lbr_overrides_filename)
    override_parsed = parse_json_file(lbr_overrides_filename)

    # Override based on JSON file
    for block_name in lbr_parsed:
        if block_name not in override_parsed:
            continue

        override_parsed_block = override_parsed[block_name]

        for storage_type in ['Registers', 'Memories']:
            # Overriding registers
            if storage_type in override_parsed_block:
                override_regmem = override_parsed_block[storage_type]
                orig_regmem = lbr_parsed[block_name][storage_type]
                for (index, regmem_dict) in enumerate(orig_regmem):
                    if regmem_dict['Name'] not in override_regmem:
                        continue
                    orig_regmem[index] = override_lbr_regmem_data(regmem_dict, override_regmem[regmem_dict['Name']])
                lbr_parsed[block_name][storage_type] = orig_regmem

    return lbr_parsed


def override_reg_cams(lbr_parsed):
    for block_name in lbr_parsed:
        for mem in lbr_parsed[block_name]['Memories']:
            if mem['SubType'] == 'REG_CAM':
                override_reg_cam(mem)

    return lbr_parsed


def find_dict_in_list_of_dicts(list_of_dicts, key, value):
    for d in list_of_dicts:
        if d[key] == value:
            return d
    return None


# Applies to all:
#  - Rev1 and Rev2 share the same LBR blocks, regs/mems may be different.

# Merging rules:
#  - Rev1 is a subset of Rev2 - checked with assertion!
#  - If identical reg/mem in Rev1 and Rev2, then take from Rev2 (e.g. the plain text description).
MERGE__REV1_SUBSET__REV2_SUPERSET = 1

# Merging rules:
#  - Rev1 is not a subset of Rev2, i.e. each can have different regs/mems
#  - If identical reg/mem in Rev1 and Rev2, then take from Rev2 (e.g. the plain text description).
MERGE__REV1_AND_REV2_ALLOW_DISJOINT = 2


def merge_rev1_and_rev2(lbr_rev1_parsed, lbr_rev2_parsed, merge_rule=MERGE__REV1_SUBSET__REV2_SUPERSET):
    # 'rev2' contains all LBRs
    # 'rev1' is a small subset of LBRs.
    lbr_parsed = {}
    for block_name in lbr_rev2_parsed:
        if block_name in lbr_rev1_parsed:
            block_rev1 = lbr_rev1_parsed[block_name]
            block_rev2 = lbr_rev2_parsed[block_name]
            lbr_parsed[block_name] = merge_rev1_and_rev2_single(block_rev1, block_rev2, merge_rule)
        else:
            # nothing to merge, no overrides ==> take rev2
            lbr_parsed[block_name] = lbr_rev2_parsed[block_name]

    return lbr_parsed

# @brief Merge rev1 and rev2 of a single LBR
#
# If reg/mem appears in both rev1 and rev2 and has identical size and fields, we prefer 'rev2'
# If reg/mem appears in both rev1 and rev2 and has different size or fields,
#    we add 'rev1' to the list of other revisions rev2['OtherRevisions]


def merge_rev1_and_rev2_single(block_rev1, block_rev2, merge_rule):
    logging.debug("Merging revisions for block '%s'", block_rev1['Name'])

    merged_block = {}
    merged_block['Name'] = block_rev1['Name']
    merged_block['Registers'] = []
    merged_block['Memories'] = []

    for storage_type in ['Registers', 'Memories']:
        regs_1 = block_rev1[storage_type]
        regs_2 = block_rev2[storage_type]

        reg_names_1 = set([r['Name'] for r in regs_1])
        reg_names_2 = set([r['Name'] for r in regs_2])

        reg_names_only_2 = reg_names_2 - reg_names_1
        reg_names_only_1 = reg_names_1 - reg_names_2
        reg_names_in_both = reg_names_1.intersection(reg_names_2)

        if merge_rule == MERGE__REV1_SUBSET__REV2_SUPERSET:
            assert len(reg_names_only_1) == 0, "rev1 must contain a subset of registers/memories of rev2"

        logging.debug("Registers/memories only in rev1: {}".format(reg_names_only_1))
        logging.debug("Registers/memories only in rev2: {}".format(reg_names_only_2))
        logging.debug("Registers/memories in all revisions: len={}".format(len(reg_names_in_both)))

        for r1 in regs_1:
            if r1['Name'] in reg_names_only_1:
                merged_storage = r1
                merged_storage['ValidInRevisions'] = ['rev1']

                merged_block[storage_type].append(merged_storage)
            else:
                pass  # Reg/Mem appears both in rev1 and rev2, use rev2

        for r2 in regs_2:
            merged_storage = r2
            if r2['Name'] in reg_names_only_2:
                # Reg/Mem appears only in rev2
                merged_storage['ValidInRevisions'] = ['rev2']
            else:
                # Reg/Mem appears both in rev1 and rev2.
                # Retrieve rev1 of this reg/mem
                r1 = find_dict_in_list_of_dicts(regs_1, 'Name', r2['Name'])

                # Find diff between rev1 and rev2, ignore plain-text 'Description' and 'RevisionName'
                attrs, fields = diff_regmem(r1, r2)
                if attrs or fields:
                    logging.debug('revision diff name {}, attrs={}, fields={}'.format(r2['Name'], attrs, fields))
                    merged_storage['OtherRevisions'] = [{
                        'regmem_dict': r1,
                        'fields_diff': fields,
                        'attrs_diff': attrs,
                    }]

            merged_block[storage_type].append(merged_storage)

    return merged_block


def diff_dicts(d1, d2, ignore_keys):
    diff = {}
    for key in d1:
        if (key not in ignore_keys) and (d1[key] != d2[key]):
            diff[key] = [d1[key], d2[key]]
    return diff


def diff_regmem(r1, r2):
    # Compare reg/mem attributes, ignore plain-text 'Description' and ignore 'Fields' which we compare later
    diff_attributes = diff_dicts(r1, r2, ['RevisionName', 'Description', 'Fields'])

    # Now compare 'Fields', again, ignore 'Description'
    fields1, fields2 = r1['Fields'], r2['Fields']

    if len(fields1) != len(fields2):
        return bool(diff_attributes), True

    diff_fields = []
    for i in range(len(fields1)):
        diff_field = diff_dicts(fields1[i], fields2[i], ['RevisionName', 'Description'])
        if diff_field:
            diff_fields.append(diff_field)

    return bool(diff_attributes), bool(diff_fields)


# @brief Coverts a string in a CamelCase notation underscore delimitered
#
# Coverts a string in a CamelCase notation to underscore delimitered, e.g., FooBoo to foo_boo
#
# @param[in] name   A string in CamelCase notation
#
# @return The string in underscore notation
def camel_case_to_underscore_delimiter(name, is_sv_convention=False):
    if not is_sv_convention:
        # if an acronym is followed by a a word, e.g., APIModifier; the following regexp will change it into API_Modifier
        name = re.sub('([^_])([A-Z][a-z]+)', r'\1_\2', name)

    # the regular case where a lower case is followed by an upper case, e.g.,
    # Foo2Boo; the following regexp will change it into Foo2_Boo. then change
    # the whole string to lower case
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()


def escape_doxygen_specials(description):
    # Doxygen has a special character for '#'
    return description.replace("#", "\#")


def get_register_fields_type(parsed_fields):
    # check if all register fields types are same
    # store register fields type as a register property
    types = []
    for parsed_field in parsed_fields:
        field_type = get_reg_fields_type_enum_name(parsed_field['Type'])
        types.append(field_type)
    return types

# @brief Parses a register structure from a raw LBR entry
#
# Extracts data about a register from a raw LBR
#
# @param[in] reg_name       The name of the register
# @param[in] reg_dict       The raw LBR register data
# @param[in] revision_name  LBR revision name
#
# @return The extracted register data


def parse_register_entry(reg_name, reg_dict, revision_name, is_sv_convention):

    # a lambda function to get a value of a key from a dict. if the key doesnt
    # exist, then by default fail (gracefully), and return a None
    get_safe_key_in_reg_dict = lambda key, fail_on_error = True, error_ret_val = None:\
        get_safe_key_in_dict('register', reg_name, reg_dict, key, fail_on_error, error_ret_val)

    # get the register type, and ignore types that don't represent real registers
    register_type = get_safe_key_in_reg_dict('Type')
    register_type = get_reg_type_enum_name(register_type)
    if register_type == 'HISTOGRAM':
        return
    reg_with_default_value = register_type in REGS_WITH_DEFAULT_VALUE

    # if the register has an ArrayIndex attribute, then there is an array of this register, else its a single instance.
    # in case of a register array, only the first is parsed completely. the
    # others are only parsed for default value. it is assumed that other
    # fields are the same.
    if 'ArrayIndex' in reg_dict:
        single_reg = False
        if int(reg_dict['ArrayIndex']) != 0:
            if not reg_with_default_value:
                return
            reg_name = get_safe_key_in_reg_dict('Name')
            parsed_register = parse_reg_in_array(reg_name, reg_dict, single_reg, is_sv_convention)
            return parsed_register
    else:
        single_reg = True

    if single_reg:
        # some single registers dont have a Name attribute (issue that should be
        # fixed by alexk), so take the name from the key of this reg_dict
        array_length = 1
    else:
        reg_name = get_safe_key_in_reg_dict('Name')
        # remove the array syntax from the name, e.g., foo[3] will become foo
        reg_name = remove_array_syntax(reg_name)
        array_length = int(get_safe_key_in_reg_dict('ArrayLength'))

    address = get_safe_key_in_reg_dict('Address')
    width = int(get_safe_key_in_reg_dict('Width'))
    # not all registers have a description, so dont fail, and return an empty string
    description = get_safe_key_in_reg_dict('Description', False, '')
    description = escape_doxygen_specials(description)

    # HISTOGRAM registers are non-readable, but they are omitted by parser anyway.
    # HISTOGRAM and READONLY are non-writable, in addition Master Interrupt Register of each block is also non-writable.
    register_writable = (int(address, 16) != master_interrupt_address and register_type not in ['HISTOGRAM', 'READONLY'])

    # store the extracted data
    parsed_register = {}
    parsed_register_name = camel_case_to_underscore_delimiter(reg_name, is_sv_convention)
    parsed_register['Name'] = parsed_register_name
    parsed_register['RevisionName'] = revision_name
    parsed_register['OtherRevisions'] = []
    parsed_register['ValidInRevisions'] = ['rev1', 'rev2']
    parsed_register['IsSingle'] = single_reg
    parsed_register['ArrayLength'] = array_length
    parsed_register['Address'] = address
    parsed_register['Width'] = width
    parsed_register['Description'] = description
    parsed_register['Type'] = register_type
    parsed_register['Writable'] = register_writable

    # parse and store init values - upon 'register' level, these values are optional and might be applied
    # (whether exist) if none are specified in the register fields' init values
    parse_and_store_init_values('register', reg_name, reg_dict, parsed_register)

    logging.debug(
        "parsed register: name='%s' single_reg='%s' array_length='%s' address='%s' width='%s' description='%s'\n"
        " writable='%s' init_value_all_modes='%s'  init_value_sa='%s'  init_value_lc_nwk='%s'  init_value_lc_fab='%s'"
        " init_value_lc_fe='%s'  instance_allocation='%s'",
        reg_name,
        single_reg,
        array_length,
        address,
        width,
        description,
        str(register_writable),
        parsed_register['InitValueAllModes'],
        parsed_register['InitValueSa'],
        parsed_register['InitValueLcNwk'],
        parsed_register['InitValueLcFab'],
        parsed_register['InitValueFe'],
        parsed_register['InstanceAllocation']
    )

    parsed_fields = parse_register_fields(reg_name, reg_dict, single_reg, is_sv_convention, True)

    parsed_register['FieldsTypes'] = get_register_fields_type(parsed_fields)

    # need to sort the fields by the lower bit pos.
    parsed_fields.sort(key=operator.itemgetter('PositionLow'))
    parsed_register['Fields'] = parsed_fields

    reg_default_value_hex_list = []   # most register types dont have a default value. so set it at 0,
    if reg_with_default_value:
        # the current register type (config, interrupt_test, ...) must have a
        # default value. so verify that all is fields have a default value
        if any(parsed_field['HasDefault'] == False for parsed_field in parsed_fields):
            fields_has_default_indication = [parsed_field['HasDefault'] for parsed_field in parsed_fields]
            exception_message = "one of the fields in register='{0}' doesn't have a default value. the has_default list is {1}".format(
                reg_name, fields_has_default_indication)
            raise Exception(exception_message)

        # get the default value from the fields
        binary_field_default_values_str_list = [parsed_field['BinaryDefault']
                                                for parsed_field in reversed(parsed_fields)]  # extract the per-field default value list
        binary_default_value_str = "".join(binary_field_default_values_str_list)  # concatenate the list into one big binary string

        reg_default_value_hex_list = get_n_byte_hex_list(binary_default_value_str, 1)

    parsed_register['DefaultValue'] = []
    parsed_register['DefaultValue'].append(reg_default_value_hex_list)

    parsed_register['NumOfReg'] = array_length
    parsed_register['SizeInBits'] = width * array_length
    parsed_register['SizeInBytes'] = width_in_bytes(width) * array_length
    parsed_register['SizeInQWords'] = width_in_bytes(width_in_bytes(width)) * array_length

    return parsed_register

# @brief Parse for default value for register in array of registers.
#
# @param[in] reg_name         The name of the register
# @param[in] reg_dict         The raw LBR register data
# @param[in] single_reg       Indicates whether this field belongs to a single entry (vs array or entries)
# @param[in] is_sv_convention Indicates whether SystemVerilog convention is used
#
# @return Parsed register dictionary


def parse_reg_in_array(reg_name, reg_dict, single_reg, is_sv_convention):
    # remove the array syntax from the name, e.g., foo[3] will become foo
    reg_name = remove_array_syntax(reg_name)
    parsed_register = {}
    parsed_register_name = camel_case_to_underscore_delimiter(reg_name, is_sv_convention)
    parsed_register['Name'] = parsed_register_name
    parsed_register['ArrayIndex'] = reg_dict['ArrayIndex']
    logging.debug(
        "parsed register: name='%s'\n",
        reg_name,
    )
    parsed_fields = parse_register_fields(reg_name, reg_dict, False, is_sv_convention, False)
    # need to sort the fields by the lower bit pos.
    parsed_fields.sort(key=operator.itemgetter('PositionLow'))
    parsed_register['Fields'] = parsed_fields
    if any(parsed_field['HasDefault'] == False for parsed_field in parsed_fields):
        fields_has_default_indication = [parsed_field['HasDefault'] for parsed_field in parsed_fields]
        exception_message = "one of the fields in register='{0}' doesn't have a default value. the has_default list is {1}".format(
            reg_name, fields_has_default_indication)
        raise Exception(exception_message)

    # get the default value from the fields
    binary_field_default_values_str_list = [parsed_field['BinaryDefault']
                                            for parsed_field in reversed(parsed_fields)]  # extract the per-field default value list
    binary_default_value_str = "".join(binary_field_default_values_str_list)  # concatenate the list into one big binary string

    reg_default_value_hex_list = get_n_byte_hex_list(binary_default_value_str, 1)

    parsed_register['DefaultValue'] = reg_default_value_hex_list

    return parsed_register

# @brief     Iterate over all attributes (these include the aldready parsed ones: Name, Address, etc..), and find register field definitions. A register field is detected as any attribute that is a dict, that has a 'RegMem' field with a 'RegField' value
#
# @param[in] reg_name           The name of the register
# @param[in] reg_dict           The raw LBR register data
# @param[in] single_reg         Indicates whether this field belongs to a single entry (vs array or entries)
# @param[in] is_sv_convention   Indicates whether SystemVerilog convention is used
# @param[in] first_reg_in_array False if register is not first in array of registers.
#
# @return List of parsed fields


def parse_register_fields(reg_name, reg_dict, single_reg, is_sv_convention, first_reg_in_array):
    parsed_fields = []
    for attribute_name, attribute_dict in reg_dict.items():
        if not isinstance(attribute_dict, dict):    # this is an indication that this attribute is not a register field
            continue
        if 'RegMem' not in attribute_dict or attribute_dict[
                'RegMem'] != 'RegField':  # this is an indication that this attribute is not a register field
            continue

        try:
            if first_reg_in_array:
                parsed_field = parse_field_entry(attribute_name, attribute_dict, single_reg, is_sv_convention)
            else:
                parsed_field = parse_default_value(attribute_name, attribute_dict, is_sv_convention)

        except Exception as inst:
            new_msg = "error in field='{0}' of register='{1}'".format(attribute_name, reg_name)
            reraise(inst, new_msg)

        parsed_fields.append(parsed_field)
    return parsed_fields

# @brief		Parses the init values from a ['register', 'regField', mem', 'memField'] raw LBR entry
#
# @param[in]	dict_type		The name of the dict type, can be one of the following: 'register', 'regField', mem', 'memField'
# @param[in]	name			The name of the object represented by 'type'
# @param[in]	raw_dict		The raw LBR object (which represented by 'type') data
# @param[out]	parsed_dict		The parsed 'dict' data


def parse_and_store_init_values(dict_type, name, raw_dict, parsed_dict):
    parsed_dict['InitValueAllModes'] = get_safe_key_in_dict(dict_type, name, raw_dict, 'InitValueAllModes', False, None)
    parsed_dict['InitValueSa'] = get_safe_key_in_dict(dict_type, name, raw_dict, 'InitValueSa', False, None)
    parsed_dict['InitValueLcNwk'] = get_safe_key_in_dict(dict_type, name, raw_dict, 'InitValueLcNwk', False, None)
    parsed_dict['InitValueLcFab'] = get_safe_key_in_dict(dict_type, name, raw_dict, 'InitValueLcFab', False, None)
    parsed_dict['InitValueFe'] = get_safe_key_in_dict(dict_type, name, raw_dict, 'InitValueFe', False, None)

    # Design team used the key 'InitValueLcFe' in the beginning, then we fixed it to 'InitValueFe' in LBRs, this error is to make sure
    # they use InitValueFe so we will not miss any configuration in FE.
    if get_safe_key_in_dict(dict_type, name, raw_dict, 'InitValueLcFe', False, None) is not None:
        raise KeyError("'InitValueLcFe' is not valid, please use 'InitValueFe'. {type}: {name}".format(type=dict_type, name=name))

    parsed_dict['InstanceAllocation'] = get_safe_key_in_dict(dict_type, name, raw_dict, 'InstanceAllocation', False, None)


# @brief Translates a register type from LBR name to C++ enum value name
#
# @param[in] reg_type_str       LBR register type string
#
# @return   The C++ enum value name for a register type
def get_reg_type_enum_name(reg_type_str):
    if reg_type_str == "Config":
        return "CONFIG"
    if reg_type_str == "InterruptTest":
        return "INTERRUPT_TEST"
    if reg_type_str == "InterruptMask":
        return "INTERRUPT_MASK"
    if reg_type_str == "Interrupt":
        return "INTERRUPT"
    if reg_type_str == "External":
        return "EXTERNAL"
    if reg_type_str == "ReadOnly":
        return "READONLY"
    if reg_type_str == "Histogram":
        return "HISTOGRAM"

    exception_message = "unknown register type='{0}'".format(reg_type_str)
    raise Exception(exception_message)


# @brief Translates a register fields type from LBR name to C++ enum value name
#
# @param[in]   reg_field_type_str      LBR register fields type string
#
# @return   The C++ enum value name for a register fields type


def get_reg_fields_type_enum_name(reg_field_type_str):

    if reg_field_type_str == "Config":
        return "CONFIG"
    if reg_field_type_str == "InterruptTest":
        return "INTERRUPT_TEST"
    if reg_field_type_str == "InterruptMask":
        return "INTERRUPT_MASK"
    if reg_field_type_str == "Interrupt":
        return "INTERRUPT"
    if reg_field_type_str == "External":
        return "EXTERNAL"
    if reg_field_type_str == "Status":
        return "STATUS"
    if reg_field_type_str == "Counter":
        return "COUNTER"
    if reg_field_type_str == "MaxWmk" or reg_field_type_str == 'SignedMaxWmk':
        return "MAX_WMK"
    if reg_field_type_str == "MinWmk" or reg_field_type_str == 'SignedMinWmk':
        return "MIN_WMK"
    if reg_field_type_str == "Capture":
        return "CAPTURE"
    if reg_field_type_str == "Event":
        return "EVENT"

    exception_message = "unknown register type='{0}'".format(reg_field_type_str)
    raise Exception(exception_message)


# @brief Translates a memory type from LBR name to C++ enum value name
#
# @param[in] mem_type_str       LBR memory type string
#
# @return   The C++ enum value name for a memory type


def get_mem_type_enum_name(mem_type_str):
    if mem_type_str == "Config":
        return "CONFIG"
    if mem_type_str == "Dynamic":
        return "DYNAMIC"
    if mem_type_str == "DocOnly":
        return "DOC_ONLY"

    exception_message = "unknown memory type='{0}'".format(mem_type_str)
    raise Exception(exception_message)


# @brief Translates a memory protection type from LBR name to C++ enum value name
#
# @param[in] mem_protect_str       LBR memory type string
#
# @return   The C++ enum value name for a memory type
def get_mem_protect_enum_name(mem_protect_str):
    if mem_protect_str == "ECC":
        return "ECC"
    if mem_protect_str == "ExtECC":
        return "EXT_ECC"
    if mem_protect_str == "Parity":
        return "PARITY"
    if mem_protect_str == "ExtParity":
        return "EXT_PARITY"
    if mem_protect_str == "None":
        return "NONE"

    exception_message = "unknown mem_protect='{0}'".format(mem_protect_str)
    raise Exception(exception_message)

# @brief Returns a value for key in a dict, and behaves gracefully if key doesn't exist
#
# Returns a value for a requested key in a dict. If the key doesn't exist, then either fail with a readable error, or return a default value
#
# @param[in] dict_family    The name of the dict type. Used for error print.
# @param[in] dict_name      The name of the dict. Used for error print.
# @param[in] key            The key for which to return the value.
# @param[in] fail_on_error  Whether to fail if key doesn't exist
# @param[in] error_ret_val  The value to return in case that key doesnt exist in dict, and fail_on_error==False.
#
# @return The value for a key in a dict, or a default value


def get_safe_key_in_dict(dict_family, dict_name, dict_ptr, key, fail_on_error=True, error_ret_val=None):
    if key not in dict_ptr:
        if fail_on_error:
            exception_message = "{0} '{1}' doesnt have a '{2}' attribute.\n"\
                                .format(dict_family, dict_name, key)
            raise Exception(exception_message)
        else:
            return error_ret_val

    return dict_ptr[key]


def remove_array_syntax(name):
    return re.sub(r'\[.*\]', r'', name)


# @brief Parses a field structure from a raw LBR entry
#
# @param[in] field_name     The name of the field
# @param[in] field_dict     The raw LBR field data
# @param[in] single_entry   Indicates whether this field belongs to a single entry (vs array or entries)
#
# @return The extracted field data
def parse_field_entry(field_name, field_dict, single_entry, is_sv_convention):
    get_safe_key_in_field_dict = lambda key, fail_on_error = True, error_ret_val = None:\
        get_safe_key_in_dict('field', field_name, field_dict, key, fail_on_error, error_ret_val)

    if single_entry:
        name = field_name
    else:
        name = get_safe_key_in_field_dict('Name')
        # remove the array syntax from the name, e.g., foo[3] will become foo
        name = remove_array_syntax(name)

    width = int(get_safe_key_in_field_dict('Width'))
    position = get_safe_key_in_field_dict('Position')
    field_type = get_safe_key_in_field_dict('Type', False, 'None')
    description = get_safe_key_in_field_dict('Description', False, '')
    description = escape_doxygen_specials(description)
    # if the width of the field > 1, then position indicates the range of the
    # occupied bits, in "end_bit:start_bit" format. extract the start_bit
    # part.
    position_low = int(re.sub(r'.*:', r'', position))
    default_value_str = get_safe_key_in_field_dict('DefaultValue', False, '')  # if there is no default, then use an empty string

    if asic_params.use_defaults and re.search('DEFAULT', default_value_str):
        default_value_str = default_value_str[2:]
        default_value_str = "d" + akpg_default_table[default_value_str]

    array_item_width = get_safe_key_in_field_dict('ArrayItemWidth', False)
    array_item_width = None if array_item_width is None else int(array_item_width)

    try:
        has_default, binary_default_value_str = get_bin_string(default_value_str, width)
    except Exception as inst:
        new_msg = "bad default value in field='{0}'".format(field_name)
        reraise(inst, new_msg)
    # remove '_' from the string (FFFF_FFFF ==> FFFFFFFF):
    binary_default_value_str = re.sub('_', '', binary_default_value_str)

    parsed_field = {}
    parsed_field_name = camel_case_to_underscore_delimiter(name, is_sv_convention)
    parsed_field['Name'] = parsed_field_name
    parsed_field['Width'] = width
    parsed_field['Position'] = position
    parsed_field['Type'] = field_type
    parsed_field['Description'] = description
    parsed_field['PositionLow'] = position_low
    parsed_field['BinaryDefault'] = binary_default_value_str
    parsed_field['HasDefault'] = has_default
    parsed_field['ArrayItemWidth'] = array_item_width

    # print('Position = ', position, '   BinaryDefault = ', binary_default_value_str)

    # parse and store init values, these values are optional.
    parse_and_store_init_values('field', field_name, field_dict, parsed_field)

    logging.debug(
        "parsed field: name='%s' width='%s' position='%s' description='%s' default_value_str='%s\n'"
        "init_value_all_modes='%s'  init_value_sa='%s'  init_value_lc_nwk='%s'  init_value_lc_fab='%s' init_value_lc_fe='%s'  instance_allocation='%s'  array_item_width='%s'",
        name,
        width,
        position,
        description,
        default_value_str,
        parsed_field['InitValueAllModes'],
        parsed_field['InitValueSa'],
        parsed_field['InitValueLcNwk'],
        parsed_field['InitValueLcFab'],
        parsed_field['InitValueFe'],
        parsed_field['InstanceAllocation'],
        array_item_width)

    return parsed_field

# @brief Parses a default value and name from a raw LBR entry
#
# @param[in] field_name       The name of the field
# @param[in] field_dict       The raw LBR field data
# @param[in] is_sv_convention Indicates whether SystemVerilog convention is used
#
# @return The extracted field data


def parse_default_value(field_name, field_dict, is_sv_convention):
    get_safe_key_in_field_dict = lambda key, fail_on_error = True, error_ret_val = None:\
        get_safe_key_in_dict('field', field_name, field_dict, key, fail_on_error, error_ret_val)

    name = get_safe_key_in_field_dict('Name')
    # remove the array syntax from the name, e.g., foo[3] will become foo
    name = remove_array_syntax(name)

    width = int(get_safe_key_in_field_dict('Width'))
    position = get_safe_key_in_field_dict('Position')
    # if the width of the field > 1, then position indicates the range of the
    # occupied bits, in "end_bit:start_bit" format. extract the start_bit
    # part.
    position_low = int(re.sub(r'.*:', r'', position))
    default_value_str = get_safe_key_in_field_dict('DefaultValue', False, '')  # if there is no default, then use an empty string

    try:
        has_default, binary_default_value_str = get_bin_string(default_value_str, width)
    except Exception as inst:
        new_msg = "bad default value in field='{0}'".format(field_name)
        reraise(inst, new_msg)
    # remove '_' from the string (FFFF_FFFF ==> FFFFFFFF):
    binary_default_value_str = re.sub('_', '', binary_default_value_str)

    parsed_field = {}
    parsed_field_name = camel_case_to_underscore_delimiter(name, is_sv_convention)
    parsed_field['Name'] = parsed_field_name
    parsed_field['PositionLow'] = position_low
    parsed_field['HasDefault'] = has_default
    parsed_field['BinaryDefault'] = binary_default_value_str

    logging.debug(
        "parsed field: name='%s' width='%s' position='%s' default_value_str='%s\n'",
        name,
        width,
        position,
        default_value_str)

    return parsed_field

# @brief Returns a binary string representing a value in other bases
#
# Gets a value in either binary, hex or decimal full formats (prefixed with '0b', '0d' or '0h' for binary, decimal and hexadecimal respectively)
# and returns their binary representation padded to a specified width
#
# @param[in] value_str      The value to be translated
# @param[in] bit_width      The bit-width of the result
#
# @return   The binary string representing a value in other bases


def get_bin_string(value_str, bit_width):
    has_default = False

    if value_str == " " or value_str == "" or value_str == "N/A":  # some entries have a " " instead of a number
        value = "0"
    else:
        has_default = True

        # remove ':
        value_str = re.sub('^\'', '', value_str)

        base = value_str[0]
        # To avoid a bug in python, if the string is long and contains '_' it raises a ValueError: int string too large to convert.
        value_without_base = value_str[1:].replace('_', '')

        if base == 'h':
            value = bin(int(value_without_base, 16))[2:]
        elif value_str[0] == 'd':
            if value_str[1] == '`':
                value = '0'  # e.g. DefaultValue => "d`MEMORY_SACR1_P_RM_DEFAULT"
            else:
                value = bin(int(value_without_base, 10))[2:]  # e.g. DefaultValue => "d4"

        elif value_str[0] == 'b':
            value = value_without_base
        else:
            raise Exception("unknown base='{0}' in value='{1}'".format(base, value_str))

    if len(value) > bit_width:
        raise Exception(
            "value_str='{0}' is bigger in bits than bit_width='{1}'. calculated value (binary) = '{2}'".format(
                value_str, bit_width, value))

    return has_default, value.zfill(bit_width)


# @brief Parses a memory structure from a raw LBR entry
#
# Extracts data about a memory from a raw LBR
#
# @param[in] mem_name       The name of the memory
# @param[in] mem_dict       The raw LBR memory data
# @param[in] revision_name  LBR revision name
#
# @return The extracted memory data
def parse_memory_entry(mem_name, mem_dict, revision_name, is_sv_convention):
    # if the memory has an ArrayIndex attribute, then there is an array of this memory, else its a single instance.
    # in case of an memory array, only the first is parsed. it is assumed that the others are identical.
    if'ArrayIndex' in mem_dict and int(mem_dict['ArrayIndex']) != 0:
        return  # if this is not the first memory, then exit

    get_safe_key_in_mem_dict = lambda key, fail_on_error = True, error_ret_val = None:\
        get_safe_key_in_dict('memory', mem_name, mem_dict, key, fail_on_error, error_ret_val)

    # get the memory type
    memory_type = get_safe_key_in_mem_dict('Type')
    memory_type = get_mem_type_enum_name(memory_type)

    # TODO - DOC_ONLY memory entries represent another view (different fields) on the same address as a non-DOC_ONLY memory.
    # TODO - they should be imported to C++, but then there is an issue with the shadow that should share the same shadow object with the non-DOC_ONLY memory.
    # TOOD - until its solved, ignore the DOC_ONLYs.
    if memory_type == 'DOC_ONLY':
        return

    # get memory protection type
    mem_protect = get_safe_key_in_mem_dict('MemProtect')
    mem_protect = get_mem_protect_enum_name(mem_protect)

    # get the memory UsedBy
    memory_used_by = get_safe_key_in_mem_dict('UsedBy')

    # a memory with MemWrapper == 'EM' doesnt represent a real memory, so skip it.
    mem_wrapper = get_safe_key_in_mem_dict('MemWrapper')
    if mem_wrapper == 'EM':
        return

    single_mem = 'ArrayIndex' not in mem_dict
    if single_mem:
        # some single memories dont have a Name attribute (issue that should be
        # fixed by alexk), so take the name from the key of this mem_name
        name = mem_name
        array_length = 1
    else:
        name = get_safe_key_in_mem_dict('Name')
        # remove the array syntax from the name, e.g., foo[3] will become foo
        name = remove_array_syntax(name)
        array_length = int(get_safe_key_in_mem_dict('ArrayLength'))

    if mem_wrapper == 'TCAM':
        # in a tcam, the logical width info is stored in another struct, in field 'Width'
        tcam_dict_key_name = None
        if 'tcam_key' in mem_dict:  # in some entries its stored under the 'tcam_key'
            tcam_dict_key_name = 'tcam_key'
        elif mem_name + '_key' in mem_dict:   # in some entries its stored under the name of the mem + '_key'
            tcam_dict_key_name = mem_name + '_key'
        else:   # if neither exist, then there is a problem
            exception_message = "mem_name '{0}' mem_wrapper=={1} so its logical width is stored under a subkey, but neither 'tcam_key' nor '{2}_key' exist"\
                                .format(mem_name, mem_wrapper, mem_name)
            raise Exception(exception_message)

        tcam_dict = get_safe_key_in_mem_dict(tcam_dict_key_name)

        mem_logical_width = int(get_safe_key_in_dict('memory', mem_name + tcam_dict_key_name, tcam_dict, 'Width'))

        # Workaround: some devices (e.g. Asic5) have the parity bit defined as
        # a field in the memory definition; this needs to be removed in order
        # for the correct total width to be reflected.
        width_adjust = 0
        num_parity_fields = 0
        for parity_field in [f for f in mem_dict if f.endswith('_parity')]:
            width_adjust += int(mem_dict[parity_field]['Width'])
            num_parity_fields += 1
            del mem_dict[parity_field]
        if num_parity_fields > 0:
            old_width = int(mem_dict['Width'])
            mem_dict['Width'] = old_width - width_adjust

    else:
        mem_logical_width = int(get_safe_key_in_mem_dict('MemLogicalWidth'))  # Logical width

    address = get_safe_key_in_mem_dict('Address')
    # not all memories have a description, so dont fail, and return an empty string
    description = get_safe_key_in_mem_dict('Description', False, "")
    description = escape_doxygen_specials(description)
    mem_entries = int(get_safe_key_in_mem_dict('MemEntries'))
    mem_total_width = get_safe_key_in_mem_dict('Width')  # Width with ECC bits
    additional_info = get_safe_key_in_mem_dict('AdditionalInfo')

    # Convert a comma-separated key=value string into a list: "key0=val0,key1=val1,..." ==> ["key0=val0", "key1=val1", ...]
    additional_info = additional_info.split(',')

    if memory_used_by in ['SBIF', 'CSS', 'ACM']:
        cpu_read_access, cpu_write_access = 'true', 'true'
    else:
        cpu_read_access = 'true' if 'CpuReadAccess=Enabled' in additional_info else 'false'
        cpu_write_access = 'true' if 'CpuWriteAccess=Enabled' in additional_info else 'false'

    if mem_wrapper == 'TCAM':
        if 'CAM=Enabled' in additional_info:
            # If CAM=Enabled is present, if yes, it doesn't matter if RegTcam=Enabled is also present or not.
            mem_subtype = 'REG_CAM'
        elif 'RegTcam=Enabled' in additional_info:
            mem_subtype = 'REG_TCAM'
        else:
            mem_subtype = asic_params.tcam_type
    else:
        mem_subtype = 'NONE'

    parsed_memory = {}
    parsed_memory_name = camel_case_to_underscore_delimiter(name, is_sv_convention)
    parsed_memory['Name'] = parsed_memory_name
    parsed_memory['RevisionName'] = revision_name
    parsed_memory['OtherRevisions'] = []
    parsed_memory['ValidInRevisions'] = ['rev1', 'rev2']
    parsed_memory['Address'] = address
    parsed_memory['Description'] = description
    parsed_memory['MemEntries'] = mem_entries
    parsed_memory['MemLogicalWidth'] = mem_logical_width
    parsed_memory['MemTotalWidth'] = mem_total_width
    parsed_memory['MemWrapper'] = mem_wrapper
    parsed_memory['ArrayLength'] = array_length
    parsed_memory['IsSingle'] = single_mem
    parsed_memory['Type'] = memory_type
    parsed_memory['SubType'] = mem_subtype
    parsed_memory['MemProtect'] = mem_protect
    parsed_memory['CpuReadAccess'] = cpu_read_access
    parsed_memory['CpuWriteAccess'] = cpu_write_access

    # parse and store init values - upon 'memory' level, these values are optional.
    parse_and_store_init_values('memory', mem_name, mem_dict, parsed_memory)

    logging.debug(
        "parsed memory: name='%s' address='%s' description='%s' mem_entries='%s' mem_logical_width='%s' "
        "mem_total_width='%s' mem_wrapper='%s' mem_protect='%s' array_length='%s' single_mem='%s' \n"
        "init_value_all_modes='%s'  init_value_sa='%s'  init_value_lc_nwk='%s'  init_value_lc_fab='%s' "
        "init_value_lc_fe='%s'  instance_allocation = '%s'",
        name,
        address,
        description,
        mem_entries,
        mem_logical_width,
        mem_total_width,
        mem_wrapper,
        mem_protect,
        array_length,
        single_mem,
        parsed_memory['InitValueAllModes'],
        parsed_memory['InitValueSa'],
        parsed_memory['InitValueLcNwk'],
        parsed_memory['InitValueLcFab'],
        parsed_memory['InitValueFe'],
        parsed_memory['InstanceAllocation'])

    # iterate over all attributes (these include the aldready parsed ones: Name, Address, etc.., and find memory field definitions.
    # a memory field is detected as any attibutes that is a dict, that has a 'RegMem' field with a 'MemField' value
    parsed_fields = []
    for attribute_name, attribute_dict in mem_dict.items():
        if not isinstance(attribute_dict, dict):    # this is an indication that this attribute is not a memory field
            continue
        if 'RegMem' not in attribute_dict or attribute_dict[
                'RegMem'] != 'MemField':  # this is an indication that this attribute is not a memory field
            continue

        try:
            parsed_field = parse_field_entry(attribute_name, attribute_dict, single_mem, is_sv_convention)
        except Exception as inst:
            new_msg = "error in field='{0}' of memory='{1}'".format(attribute_name, name)
            reraise(inst, new_msg)

        parsed_fields.append(parsed_field)

    # need to sort the fields by the lower bit pos.
    parsed_fields.sort(key=operator.itemgetter('PositionLow'))
    parsed_memory['Fields'] = parsed_fields

    parsed_memory['NumOfMemEntries'] = array_length * mem_entries
    parsed_memory['NumOfMemInstances'] = array_length
    parsed_memory['SizeInBits'] = mem_logical_width * array_length * mem_entries
    parsed_memory['PerEntrySizeInBytes'] = width_in_bytes(mem_logical_width) * array_length * mem_entries
    parsed_memory['PerEntrySizeInQWords'] = width_in_bytes(width_in_bytes(mem_logical_width)) * array_length * mem_entries
    parsed_memory['PerInstanceSizeInBytes'] = width_in_bytes(mem_logical_width * mem_entries) * array_length
    parsed_memory['PerInstanceSizeInQWords'] = width_in_bytes(width_in_bytes(mem_logical_width * mem_entries)) * array_length

    return parsed_memory


# @brief Translates Enabled/Disable strings to true/false respectively.
#
# @param[in] access_str       A string of access control from LBR
#
# @return   'true' if access_str=='Enabled' and 'false' if access_str=='Disabled'
def is_access_allowed(access_str):
    if access_str == "Enabled":
        return 'true'
    elif access_str == "Disabled":
        return 'false'
    else:
        exception_message = "unknown access='{0}' definition"\
            .format(access_str)
        raise Exception(exception_message)

# @brief Prints a dict in a friendly format
#
# @param[in] dict_data          The dictionary


def pretty_print(dict_data):
    print(json.dumps(dict_data, indent=4, separators=(',', ': ')))


# @brief Loads the block_to_sw_path_config file, and returns is as a dict.
#
# The block_to_sw_path_config holds the configurations that defines for each verilog blockname what SW path it should have, and whether this block has an SBUS block on it.
# The file holds a set of configuraitons. Each verilog blockname should match exactly one configuration.
# Loads the block_to_sw_path_config (that should be in almost-JSON) format, and stores it in a dictionary.
# Almost-JSON means that a backslash in some string in the file doesnt need to be escaped (by another backslash) to become backslash in the dictionary.
#
# @param[in] block_to_sw_path_config_filename   Path+filename of the sw_path config file
#
# @return A dict of the put_comma_after_last_item  Whether to put a comman after the last item.
def load_block_to_sw_path_config_list(block_to_sw_path_config_filename):
    with open(block_to_sw_path_config_filename, 'r') as block_to_sw_path_config_file:
        block_to_sw_path_config_str = block_to_sw_path_config_file.read()
        # in order to load as json, each backslash should be escaped (by another backslash)
        block_to_sw_path_config_str = re.sub(r'\\', r'\\\\', block_to_sw_path_config_str)
        # in case the JSON parsing fails, add a custom message to the raised exception
        try:
            # transform the json into list of dicts:
            block_to_sw_path_config_list = json.loads(block_to_sw_path_config_str)
        except Exception as inst:
            new_msg = "failed to parse '{0}' as a JSON file".format(block_to_sw_path_config_filename)
            reraise(inst, new_msg)

    # verify that the syntax is legal
    for block_to_sw_path_config_index, block_to_sw_path_config in enumerate(block_to_sw_path_config_list):
        # verify that the mandatory keys for each configuration block exist, and the type of the value part is correct
        for must_key, value_type in (('match_str', str), ('sw_path_calc_values', list), ('sw_path', str), ('lbr_block_name', str)):
            if must_key not in block_to_sw_path_config:
                exception_message = "block_to_sw_path_config number {0} does not have a setting for '{1}'. existing settigs: {2}".format(
                    block_to_sw_path_config_index, must_key, block_to_sw_path_config.keys())
                raise Exception(exception_message)

            if not isinstance(block_to_sw_path_config[must_key], value_type):
                exception_message = 'block_to_sw_path_config number {0} has a setting "{1}"="{2}". the type of the value is {3} != expected type {4}' .format(
                    block_to_sw_path_config_index, must_key, block_to_sw_path_config[must_key], type(block_to_sw_path_config[must_key]), value_type)
                raise Exception(exception_message)

        # verify that the type of the values of the 'sw_path_calc_values' key are correct
        sw_path_calc_values = block_to_sw_path_config['sw_path_calc_values']
        for sw_path_calc_value_index, sw_path_calc_value in enumerate(sw_path_calc_values):
            if not isinstance(sw_path_calc_value, str):
                exception_message = 'block_to_sw_path_config number {0} has a has a setting "{1}"="{2}". item number {3} in the "sw_path_calc_values" list has type {4} != expected type {5}'\
                                    .format(block_to_sw_path_config_index, 'sw_path_calc_values', sw_path_calc_values, sw_path_calc_value_index, type(sw_path_calc_value), str)
                raise Exception(exception_message)

    return block_to_sw_path_config_list


# @brief Parses the verilog file that defines blocknames to UIDs, and returns it in a list.
#
# Loads a verilog file that contains definitions of existing CIF blocks and their block_ids.
# From each line in the file extracts the blockname and the block_id, and returns a list of these.
#
# @param[in] block_to_sw_path_config_filename   Path+filename of the sw_path config file
#
# @return A list of elements that define the block_id for a blockname
def parse_verilog_blockname_uid_defines_file(blockname_uid_defines_filename):
    blockname_uid_list = []
    with open(blockname_uid_defines_filename, 'r') as blockname_uid_defines_file:
        for line in blockname_uid_defines_file:
            match_obj = parse_verilog_define_syntax(line)
            if match_obj is not None:
                block_uid_data = get_blockname_and_uid(match_obj)
                block_uid_data['entry_type'] = 'LBR_block'
                block_uid_data['source'] = 'verilog'
                blockname_uid_list.append(block_uid_data)

    return blockname_uid_list


# @brief Parses the JSON file that defines custom entries to the block_e enum, and adds then to the blockname_uid_list
#
# Loads a JSON file that defines custom entries to the block_e enum.
# Each entry defines a blockname, block_id, description and whether this entry represents a real LBR block, or a dummy entry.
# For the block_id field there is support for auto number allocation, based on the next free LBR block_id number. This is indicated by '{LBR_BLOCK_AUTO_NUMBER}' in the 'uid' field.
#
# @param[in] blockname_uid_list                 A list of blockname and its ID, collected so far
# @param[in] custom_blockname_defines_filename  Path+filename of the custom_blockname define file
#
# @return An updated list of elements that define the block_id for a blockname
def parse_custom_blockname_uid_file(blockname_uid_list, custom_blockname_defines_filename):
    # the uids for all blocks (including custom) should be a unique number, so set it +1 from the max in the verilog defines
    custom_block_uid_value = 0
    if blockname_uid_list:
        custom_block_uid_value = max(block_uid_data['uid_value'] for block_uid_data in blockname_uid_list) + 1

    with open(custom_blockname_defines_filename, 'r') as custom_blockname_defines_file:
        custom_blockname_defines_str = custom_blockname_defines_file.read()
        # parse the JSON file into a dict
        try:
            custom_blockname_defines = json.loads(custom_blockname_defines_str)
        except Exception as inst:
            new_msg = "failed to parse '{0}' as a JSON ".format(custom_blockname_defines_filename)
            reraise(inst, new_msg)

        for custom_block in custom_blockname_defines:
            if custom_block['entry_type'] == 'dummy_entry':  # this is a dummy block without real register behind it
                dummy_block_data = {'entry_type': custom_block['entry_type']}
                dummy_block_data['blockname'] = custom_block['blockname']
                dummy_block_data['uid'] = custom_block['uid']
                dummy_block_data['description'] = custom_block['description']
                dummy_block_data['source'] = 'custom'
                blockname_uid_list.append(dummy_block_data)

            elif custom_block['entry_type'] == 'LBR_block':
                # This is a block with real registers, but without a verilog UID.
                # Some blocks dont appear in the block_uid defines because they dont need
                # a UID, but its hw implementation choice so make the generated code
                # agnostic to it.
                blockname = custom_block['blockname']

                # a real value for the width is not really needed, but just for correctness
                # the max() is needed in case that custom_block_uid_value == 0
                custom_block_uid_bit_width = int(math.ceil(math.log(max(custom_block_uid_value, 1), 2)))
                current_uid_str = custom_block['uid']

                auto_gen_uid_str = "{0}'d{1}".format(custom_block_uid_bit_width, custom_block_uid_value)

                # update the uid string, by replacing the '{LBR_BLOCK_AUTO_NUMBER}' string with a UID value format.
                new_uid_str = re.sub(r'{LBR_BLOCK_AUTO_NUMBER}', '{' + auto_gen_uid_str + '}', current_uid_str)

                custom_block_verilog_line = "`define {0}_UID               {1}".format(blockname, new_uid_str)

                match_obj = parse_verilog_define_syntax(custom_block_verilog_line)
                if match_obj is not None:
                    block_uid_data = get_blockname_and_uid(match_obj)
                    block_uid_data['entry_type'] = custom_block['entry_type']   # should be 'LBR_block'
                    block_uid_data['description'] = custom_block['description']
                    block_uid_data['source'] = 'custom'
                    blockname_uid_list.append(block_uid_data)

                custom_block_uid_value += 1

            else:
                assert False, 'Unexpected entry_type ' + custom_block['entry_type']

    return blockname_uid_list


# @brief Parses a verilog define blockname to block_id string and returns the parsed data
#
# Verifies that syntax is of the verilog define is of the following format:  `define <block_name>              {<number_concatenation_syntax>}
# for example: `define MAC_POOL2              {2'b00, 4'b0000, 6'd11}.
# Performs a regexp search for the expected syntax, and in case of a correct syntax, returns the matches.
#
# @param[in] verilog_define_string      A single line of a verilog define
#
# @return If succeed, a match object of the matched string, else None
def parse_verilog_define_syntax(verilog_define_string):
    match_str = r"""^                   # this is the beginning of the string (so nothing should come before the text that shold be parsed next)
                    [\s]* (`define)     # the `define keyword, prepended by  "whitespace charactes" (space, tab, etc..)
                    [\s]* ([\w]+)       # matches a-zA-Z0-9_ which should be the block name, prepended by spaces
                    [\s]* \{(.*)\}      # matches all chars between curly brackets which should be the verilog bit concatenation, prepended by spaces
                    [\s]*
                 """
    match_obj = re.search(match_str, verilog_define_string, re.VERBOSE)  # the VERBOSE allows to add comments in the match_str
    if match_obj is None or len(match_obj.groups()) != 3:
        return None
    else:
        return match_obj


# @brief Parses verilog-style blockname block_id string, and returns a parsed block_id data object
#
# Gets a verilog-style define syntax, and returns a blockname, math formula for c++ string generation of the block_id, and decimal id number representing the block_id.
# The math formula uses the same concatenation elements as the verilog, just with shift-lefts.
# The bitwidth of an adjacent element to the right indicates the shift-left of the current element.
# For example, the following verilog block_id string:
#    {2'b11, 4'b0001, 6'd11}
# will be translated (in the C++ files) to the following math formula: ( assuming this: 'b11 = 3, 'b0001 = 1, 'd11 = 11)
#   ((3 << 4) + 1) << 6) + 11
#
# @param[in] match_obj      A match-object that is the result of a regexp match for a verilog define line
#
# @return A block_id_data struct with a block name, math formula for C++ string generation, and decimal id number for it the math formula result.
def get_blockname_and_uid(match_obj):
    blockname = match_obj.group(2)
    verilog_uid_str = match_obj.group(3)

    # split the verilog_uid_str (which should be "2'b00, 4'b0000, 6'd11") by ", " delimiters
    verilog_uid_list = verilog_uid_str.split(', ')

    uid_value = 0
    prev_space_size = 1
    math_formula = []    # list of (value, shift-left) pairs
    prev_bit_width = 0
    for verilog_uid_element in reversed(verilog_uid_list):
        (uid_element_value, bit_width) = parse_verilog_number(verilog_uid_element)
        space_size = 1 << bit_width

        uid_value += uid_element_value * prev_space_size
        prev_space_size *= space_size

        formula_element = (uid_element_value, prev_bit_width)
        math_formula.append(formula_element)
        prev_bit_width = bit_width

    math_formula.reverse()  # the MSB should be at the start
    block_uid_data = {'verilog_blockname': blockname, 'math_formula': math_formula, 'uid_value': uid_value}
    return block_uid_data


# @brief Parses verilog-style string representing number
#
# Gets a verilog number syntax: <bit_width>'<base_name><value>, e.g., 4'b0011, extracts the decima value and the bit_width and returns them
#
# @param[in] verilog_num_str      A verilog-style string representing a number
#
# @return The decimal value and the bit-width
def parse_verilog_number(verilog_num_str):
    match_obj = re.search("(\d*)'([bd])(\d*)", verilog_num_str)
    if len(match_obj.groups()) != 3:
        exception_message = "verilog_num_str='{0}' is not of <bit_width>'<base_name><value> format.  block name '{0}' matches conversion config with match_str='{1}' with sw_path_calc_values='{2}'. sw_path_calc_values has only {3} items, while sw_path='{4}' backreference item {5}\n"\
                            .format(block_str, block_regexp_str, sw_path_calc_values, len(sw_path_replacement_values), sw_path, max(backreferences_int))
        raise Exception(exception_message)

    bit_width = int(match_obj.group(1))
    base_name = match_obj.group(2)
    value = match_obj.group(3)

    base_name_to_size = {'b': 2, 'd': 10}

    decimal_val = int(value, base_name_to_size[base_name])

    return (decimal_val, bit_width)


# @brief Builds the classes that should be generated for the blocks in the device
#
# Each LBR-block in blockname_uid_list (mostly) represents a existing block in the device.
# The function finds the SW-path this block should have. The SW-path is then used to build two things:
# 1) A list of classes that should be generated, and their members
# 2) A list of paths and the block_id that the last element in the path (representing a block) should have
# For a block that should have an SBUS on it, a logical SBUS block is created, and is treated as a real block.
#
# @param[in] blockname_uid_list             A list of blockname and its ID, collected so far.
# @param[in] block_to_sw_path_config_list   A list of configurations that define for each blockname its SW-path and whether it has an SBUS on it.
#
# @return blockname_uid_list - An updated blockname_uid_list (adds the SBUS blocks).
# @return flat_classes - List of classes and their members as should be generated.
# @return sw_paths_with_uid - Dict of: {'project_tree' (i.e 'pacific_tree') : List of SW-paths to all LBR-blocks, and their block_ids}
def build_classes_and_sw_paths_with_sbus(blockname_uid_list, block_to_sw_path_config_list):
    # a dict of classes, as they will appear in C++ struct
    flat_classes = {}

    # a dict of sw paths with uid, as they will initilizes the structs, per
    # top level class name (which is the path-start, for now its only
    # 'pacific')
    sw_paths_with_uid = {}

    # list of block_uid_data entries that need to be added for sbus blocks
    sbus_blockname_uid_list = []

    # iterate over all blocks
    for block_uid_data in blockname_uid_list:
        if block_uid_data['entry_type'] == 'dummy_entry':    # dummy entries are not blocks and dont have an access SW path
            continue
        verilog_blockname = block_uid_data['verilog_blockname']

        # get the LBR-block name, SW-path for the block and the configuration struct that this block matched in the SW-path config
        lbr_block_name_and_sw_path_for_block = get_lbr_block_name_and_sw_path_for_block(
            verilog_blockname, block_to_sw_path_config_list)
        lbr_block_name_and_sw_path_for_block['block_uid_data'] = block_uid_data

        sw_path = lbr_block_name_and_sw_path_for_block['sw_path']
        lbr_block_name = lbr_block_name_and_sw_path_for_block['lbr_block_name']

        # there is currently no use for it, but it is possible that there will be two top-level device names (the first step in the path).
        # since the block_id configuration is done on the device level (in the C++
        # implementation), block_id of each block (that is equivalent to full
        # SW-path of it) should be stored per top-level device
        top_level_class_name = get_top_level_class_name(sw_path)
        if top_level_class_name not in sw_paths_with_uid:   # the paths list is stored per  top level class
            sw_paths_with_uid[top_level_class_name] = []

        # go over the SW-path and extract the new classes / class members that should be created
        # this func 1) updates parameter flat_classes, and 2) returns a reference to the class of the last step in the path
        last_step_class = add_block_path(flat_classes, sw_path, lbr_block_name)

        lbr_block_name_and_sw_path_for_block['class_data'] = last_step_class

        sw_paths_with_uid[top_level_class_name].append(lbr_block_name_and_sw_path_for_block)

        # if this block has an SBUS on it, then create an SBUS block under it
        block_to_sw_path_config = lbr_block_name_and_sw_path_for_block['block_to_sw_path_config']
        if 'has_sbus' in block_to_sw_path_config:
            # create a block_uid_data entry for the sbus block
            # if the parent blockname ends with _UID then remove it
            verilog_blockname = re.sub(r'_UID$', '', verilog_blockname)
            sbus_verilog_blockname = verilog_blockname + "_sbus"
            sbus_block_uid_data = {
                'verilog_blockname': sbus_verilog_blockname,
                'parent_block_uid_data': block_uid_data,
                'source': 'JSON sw-path sbus',
                'entry_type': 'LBR_block_sbus'}
            sbus_blockname_uid_list.append(sbus_block_uid_data)

            sbus_lbr_block_name = lbr_block_name + "_sbus"
            sbus_sw_path = sw_path + '.sbus'

            # add the sbus block path to the list of sw_paths_with_uid
            sbus_lbr_block_name_and_sw_path_for_block = {'lbr_block_name': sbus_lbr_block_name, 'sw_path': sbus_sw_path}
            sbus_lbr_block_name_and_sw_path_for_block['block_uid_data'] = sbus_block_uid_data

            sw_paths_with_uid[top_level_class_name].append(sbus_lbr_block_name_and_sw_path_for_block)

            # add the sbus block class
            last_step_class = add_block_path(flat_classes, sbus_sw_path, sbus_lbr_block_name)
            # this will indicate that this class, although being the end of a path, does not represent an LBR block
            last_step_class['has_sbus'] = True

    blockname_uid_list.extend(sbus_blockname_uid_list)

    return blockname_uid_list, flat_classes, sw_paths_with_uid


# @brief For a verilog blockname returns the LBR-blockname, SW-path and the SW-path config entry that it matches.
#
# Finds the SW-path configuration entry that this block matches. Calculates the SW-path number values (if such exist), and builds a SW-path string with the values
#
# @param[in] verilog_blockname              The name of the block in verilog file
# @param[in] block_to_sw_path_config_list   A list of configuration that define for each blockname its SW-path and wether it has an SBUS on it
#
# @return A dict with the LBR-blockname, SW-path and the SW-path config entry that the block matches
def get_lbr_block_name_and_sw_path_for_block(verilog_blockname, block_to_sw_path_config_list):
    block_to_sw_path_config = get_block_to_sw_path_config(verilog_blockname, block_to_sw_path_config_list)
    sw_path_replacement_values = get_sw_path_replacement_values(verilog_blockname, block_to_sw_path_config)
    replaced_sw_path = get_replaced_sw_path(verilog_blockname, block_to_sw_path_config, sw_path_replacement_values)

    lbr_block_name_and_sw_path_for_block = {
        'lbr_block_name': block_to_sw_path_config['lbr_block_name'],
        'sw_path': replaced_sw_path,
        'block_to_sw_path_config': block_to_sw_path_config}
    return lbr_block_name_and_sw_path_for_block


# @brief Returns the block_to_sw_path_config item that matches the verilog blockname
#
# Find the config entry in block_to_sw_path_config that provides the SW-path configuration for a blockname.
# A match is found when the blockname matches a regexp defined in the config, under the 'match_str' string.
# Exactly one config should match a block.
#
# @param[in] block_str                      The name of the block in verilog file
# @param[in] block_to_sw_path_config_list   A list of configuration that define for each blockname its SW-path and wether it has an SBUS on it
#
# @return The block_to_sw_path_config item that matches the verilog blockname
def get_block_to_sw_path_config(block_str, block_to_sw_path_config_list):
    matching_block_to_sw_path_config_index_list = []
    for block_to_sw_path_config_index, block_to_sw_path_config in enumerate(block_to_sw_path_config_list):
        # get the match_str, and add implicit start_of_string '^' and end_of_string '$' to do a strict regexp match
        block_regexp_str = '^' + block_to_sw_path_config['match_str'] + '$'
        match_block_obj = re.search(block_regexp_str, block_str)
        if match_block_obj is not None:
            matching_block_to_sw_path_config_index_list.append(block_to_sw_path_config_index)

    # verify that the block_str matched exactly one conversion config
    if len(matching_block_to_sw_path_config_index_list) == 0:
        exception_message = "block name '{0}' did no match any block_to_sw_path_config."\
            .format(block_str)
        raise Exception(exception_message)

    if len(matching_block_to_sw_path_config_index_list) > 1:
        matching_conversion_elements_str = [(i, block_to_sw_path_config_list[i]['match_str'])
                                            for i in matching_block_to_sw_path_config_index_list]
        exception_message = "block name '{0}' matched more than one conversion config. matching config in (index, match_str) format: {1}\n"\
            .format(block_str, matching_conversion_elements_str)
        raise Exception(exception_message)

    block_to_sw_path_config = block_to_sw_path_config_list[matching_block_to_sw_path_config_index_list[0]]
    return block_to_sw_path_config


# @brief Returns a list of values that should replace backreferences in the SW-path syntax
#
# A block_to_sw_path_config item defines values that need to be recalculated to produce a sw_path. This func calculates those values.
# The 'match_str' has regexp group expression that can be used to value calculations. The matched groups are calculated by the sw_path_calc_values list and returned as numbers.
#
# For example, with the followign input:
#           block_str = IFG7_MAC_POOL2_0_UID
#
# and the following block_to_sw_path_config:
#           "match_str":            "IFG(\d*)_MAC_POOL2_0_UID",
#           "sw_path_calc_values":  ["\1/2", "\1%2"],
#
# A regexp search of match_str in block_str will find a match, and the match has a single match group, that is caught by the "(\d*)"
# This is referred to as the first backreference in sw_path_calc_values, i.e., \1. So effectively, in this match example, \1 == 7
# The backreferences in sw_path_calc_values are replaced by their value, and the whole list is re-evaluated mathematically, e.g.,
#   sw_path_calc_values == ["\1/2", "\1%2"]         # \1 == 7
#                     v
#   sw_path_calc_values == [" 7/2", " 7%2"]         # 7/2 = 3,  and 7%2 = 1
#                     v
#   sw_path_calc_values == [     3,      1]
#
# The function would returns the [3, 1] list.
#
# @param[in] block_str                  The name of the block in verilog file
# @param[in] block_to_sw_path_config    A block_to_sw_path_config that matches the block_str block
#
# @return A list of values that should replace backreferences in the SW-path syntax
def get_sw_path_replacement_values(block_str, block_to_sw_path_config):
    block_regexp_str = block_to_sw_path_config['match_str']
    match_block_obj = re.search(block_regexp_str, block_str)
    sw_path_calc_values = block_to_sw_path_config['sw_path_calc_values']
    sw_path_int_values = []  # holds the recalculated values that should replace the backreferences in the sw_path string

    # go over each element in sw_path_calc_values and calculate its value, based on the matched regexp in match_block_obj
    for sw_path_calc_str in sw_path_calc_values:
        # need to replace each match backreference (\1, \2, etc..) in the sw_path_calc_str, and then evaluate it as a math equation.
        # first, find the largest match backreference number, and verify that
        # there are enough matches in the match_block_obj. i.e., if the match
        # string had only group element ( like "TX_CGM(\d*)_UID" ), and the
        # sw_path_calc_str uses " \2 " then error.
        backreferences_str = re.findall(r'\\(\d*)', sw_path_calc_str)
        backreferences_int = [int(i) for i in backreferences_str]
        if max(backreferences_int) > len(match_block_obj.groups()):
            exception_message = "block name '{0}' matches conversion config with match_str='{1}'. the match_str has only {2} match groups, while sw_path_calc_values has a '{3}' item that backreferences group {4}\n"\
                                .format(block_str, block_regexp_str, len(match_block_obj.groups()), sw_path_calc_str, max(backreferences_int))
            raise Exception(exception_message)

        # replace replace_backreferences in sw_path
        sw_path_calc_replaced_str = replace_backreferences(sw_path_calc_str, max(backreferences_int), match_block_obj.groups())

        sw_path_int_value = int(eval(sw_path_calc_replaced_str))    # this will round-down all floating point results
        sw_path_int_values.append(sw_path_int_value)

    return sw_path_int_values


# @brief Replaces backreferences in a string by values, and return the new string
#
# Replaces backreferences in a string by their appropriate value, from the list_of_replacements.
# The backreference number is used as the index in the replacemetn string.
# For example:
#       orig_str =  "device.slice[\1].ifg[\2].mac_pool"
#       num_of_backreferences = 2
#       list_of_replacements = [8, 11]
# The returned string is:
#       "device.slice[8].ifg[11].mac_pool"
#
# @param[in] orig_str                    The original string
# @param[in] num_of_backreferences       Number of backreferences to replaces
# @param[in] list_of_replacements        List of vales to replace the backreferences
#
# @return The string with backreferences replaces by values
def replace_backreferences(orig_str, num_of_backreferences, list_of_replacements):
    result_str = orig_str
    for backref_num in range(1, num_of_backreferences + 1):
        result_str = re.sub(r'\\' + str(backref_num), str(list_of_replacements[backref_num - 1]), result_str)

    return result_str


# @brief Replaces backreferences in a SW-path by values, and return the new string
#
# A block_to_sw_path_config item defines the sw_path a block should get. The sw_path relies on calculated values.
# This verifies that there are enough values to replaces all backreferences (if any are needed), and calls for the replacements.
#
# @param[in] block_str                      The name of the block in verilog file
# @param[in] block_to_sw_path_config        A block_to_sw_path_config that matches the block_str block
# @param[in] sw_path_replacement_values     A list of values that should replace backreferences in the SW-path syntax
#
# @return The SW-path string with backreferences replaces by values
def get_replaced_sw_path(block_str, block_to_sw_path_config, sw_path_replacement_values):
    sw_path = block_to_sw_path_config['sw_path']

    # find all the backerefences, and if there are none then just return the original string
    backreferences_str = re.findall(r'\\(\d*)', sw_path)
    backreferences_int = [int(i) for i in backreferences_str]
    if len(backreferences_int) == 0:    # if there are no backreferences, then return the original string
        return sw_path

    # verify that there are enough sw_path_replacement_values for all backreferences
    if max(backreferences_int) > len(sw_path_replacement_values):
        # these are needed only for the exception message print
        block_regexp_str = block_to_sw_path_config['match_str']
        sw_path_calc_values = block_to_sw_path_config['sw_path_calc_values']
        exception_message = "block name '{0}' matches conversion config with match_str='{1}' with sw_path_calc_values='{2}'. sw_path_calc_values has only {3} items, while sw_path='{4}' backreference item {5}\n"\
                            .format(block_str, block_regexp_str, sw_path_calc_values, len(sw_path_replacement_values), sw_path, max(backreferences_int))
        raise Exception(exception_message)

    # replace replace_backreferences in sw_path
    sw_path_replaced_str = replace_backreferences(sw_path, max(backreferences_int), sw_path_replacement_values)

    return sw_path_replaced_str


# @brief Finds the first dot '.' in a string, and returns the substring from the start till the dot
#
# Returns all the characters of a string from the start till the first dot.
# Used to get the top-level step of a path. e.g., for a path 'pacific.slice[2].ifg[8].foo' the top-level step is 'pacific'.
#
# @param[in] sw_path                    A string with dots as a delimeter between words
# @return The substring of a string from beginning till the first dot.
def get_top_level_class_name(sw_path):
    match_obj = re.search(r'([^.]*)\.', sw_path)
    return match_obj.group(1)


# @brief Parses a block SW-path and prepares the classes/members that should be creates to support it.
#
# Takes a SW-path of a block and prepares the classes from each step of the path for C++ writing.
# The class at the last step represents an actual LBR block.
# For example:
#           block_path = 'pacific.slice[2].ifg[8].foo'
#
# will become four classes: pacific, slice, ifg and foo. The classes will have the following members:
#           'pacific' class should have an array called 'slice' (of size=2) of a slice class
#           'slice' class should have an array called 'ifg' (of size=8) of an ifg class,
#           'ifg' class should have a member array called foo.
#           'foo' class represents an actual LBR block, so its members come from the LBR data (that is not handled in this function)
#
# To avoid a situation where a path step has the same name, but represents different classes, the actual class name is the full path.
# For example, the paths:
#           'pacific.ifg.ports'
#           'pacific.slice[2].ifg[8].foo'
# both have a path step 'ifg'. These classes are not necessarily identical, so the actual class names for the first example ('pacific.slice[2].ifg[8].foo') are:
#           pacific
#           pacific_slice
#           pacific_slice_ifg
#           pacific_slice_ifg_foo
#
# The function stores the classes in the flat_classes (which is input to the func). If a new class is parsed, then its added to flat_classes.
# After parsing the SW-path, return the class of the last step.
#
# @param[in] flat_classes               A list of classes with their members
# @param[in] block_path                 A SW-path string of an LBR block
# @param[in] lbr_block_name             The name of the LBR block for which the members are written.
#
# @return The class of the last step in the SW-path
def add_block_path(flat_classes, block_path, lbr_block_name):
    path_steps = block_path.split('.')
    path_len = len(path_steps)
    class_name = None

    # each path step will be a c++ class, so need to populate its members.
    # flat_classes is a dict where each item will become a c++ struct
    for cur_index, cur_step in enumerate(path_steps):
        cur_step_name = remove_array_syntax(cur_step)
        if class_name is None:
            class_name = cur_step_name
        else:
            class_name = class_name + '_' + cur_step_name

        # TODO - add a verification that in case that the cur_step is an array of class_name, then all indices of this class should have the same members.
        # e.g., if ONLY the two followig path are inserted:
        #   'pacific.slice[2].foo'
        #   'pacific.slice[1].boo'
        # then there are two issues (which should abort the script):
        #   1) slice[0] was never defined, but it will be generated in the C++ code.
        #   2) slice[2] should have a member 'foo', slice[1] should have 'boo'. The script assumes that all class instances are the same, so the 'pacific_slice' class that
        #      will be generate will have both 'boo' and 'foo', (so slice[1] will have both 'boo' and 'foo', same for slice[2]).

        if class_name not in flat_classes:  # if the class doesnt exist yet, init its data.
            # 'members' holds the items of this class, 'lbr_block_name' is used to find the parsed LBR, 'depth' is used to order the output to c++ structs
            flat_classes[class_name] = {
                'class_name': class_name,
                'base_name': cur_step_name,
                'members': {},
                'lbr_block_name': None,
                'depth': cur_index}

        if cur_index + 1 < path_len:    # if this is not the last step, then it has substeps
            next_step = path_steps[cur_index + 1]

            # a member is a dict with keys: 'member_class_name', 'instance_name',
            # 'multiplicity', which will be converted to the following c++ code. if
            # multiplicity==0, then 'class_name instance_name;' else 'class_name
            # instance_name[multiplicity];'

            # if the substep is a an array, then extract its size
            match_obj = re.search(r'.*\[(\d*)]', next_step)
            if match_obj is not None:
                multiplicity = int(match_obj.group(1)) + 1  # the array size is the index+1
            else:  # by default, all substeps are single elements
                multiplicity = 0

            class_members = flat_classes[class_name]['members']

            instance_name = remove_array_syntax(next_step)
            if instance_name not in class_members:  # if the member doesnt exist yet, init its data.
                class_members[instance_name] = {'member_class_name': class_name + '_' +
                                                instance_name, 'instance_name': instance_name, 'multiplicity': 0}

            class_members[instance_name]['multiplicity'] = max(class_members[instance_name]['multiplicity'], multiplicity)

        else:  # if this is the last step, then it is a block (and should hold registers and memories)
            flat_classes[class_name]['lbr_block_name'] = lbr_block_name
            return flat_classes[class_name]


def create_additional_block_structures(flat_classes, lbr_parsed):
    def classes_sorter(entry): return (entry['depth'], entry['class_name'])
    flat_classes_list = sorted(flat_classes.values(), key=classes_sorter)

    additional_block_structures = {}
    for class_data in flat_classes_list:

        # if this class is an LBR block, then it has reg/mems that need to be initialized, otherwise skip.
        lbr_block_name = class_data['lbr_block_name']
        if lbr_block_name is None:
            continue

        # Get the registers and memories of the block
        skip_registers = False
        skip_memories = False
        try:
            registers = lbr_parsed[lbr_block_name]['Registers']
        except KeyError:
            skip_registers = True

        try:
            memories = lbr_parsed[lbr_block_name]['Memories']
        except KeyError:
            skip_memories = True
        additional_block_structures[lbr_block_name] = {'Registers': registers, 'Memories': memories}
    return additional_block_structures


def create_block_id_dic(blockname_uid_list):

    # build and write the enum declaration

    dic = {}
    map = {}
    c_block_uid_enum_name = ''  # this is needed out the loop to write the LAST enum
    subs_base = 0x8000
    # for block in blockname_uid_list:
    #    if block.get('blockname') == 'subs_base':
    #        subs_base = block.get('uid')
    #        print('found uid value ' + str(subs_base))
    #        if subs_base == None:
    #            subs_base = block.get('uid_value')
    #        continue
    for block_uid_data in blockname_uid_list:
        mem_block = {}
        if block_uid_data['entry_type'] == 'dummy_entry':   # dummy entries represent custom enum entries. in the UID field
            mem_block['block_name'] = block_uid_data['blockname'].upper()
            mem_block['uid'] = block_uid_data['uid']
            mem_block['description'] = block_uid_data['description']

        else:
            verilog_blockname = block_uid_data['verilog_blockname']
            # if the blockname ends with _UID then remove it
            verilog_blockname = re.sub(r'_UID$', '', verilog_blockname)
            mem_block['block_name'] = verilog_blockname
            c_block_uid_enum_name = verilog_blockname.upper()
            block_uid_data['c_enum_name'] = c_block_uid_enum_name

            if block_uid_data['entry_type'] == 'LBR_block_sbus':
                parent_block_uid_data = block_uid_data['parent_block_uid_data']
                parent_block_enum_name = parent_block_uid_data['c_enum_name']
                parent_block_verilog_name = parent_block_uid_data['verilog_blockname']
                parent_block_value = parent_block_uid_data.get('uid')
                if parent_block_value is None:
                    parent_block_value = parent_block_uid_data['uid_value']
                mem_block['uid'] = str((parent_block_value << 16) | subs_base)
                c_block_uid_formula = "LLD_GET_SBUS_BLOCK_ID_FOR_CIF({0})".format(parent_block_enum_name)
                c_block_uid_enum_comment = "SBUS master on {0}".format(parent_block_verilog_name)
            else:  # block_uid_data['entry_type'] == 'LBR_block'
                math_formula = block_uid_data['math_formula']
                c_block_uid_formula = ''
                for formula_element in math_formula:
                    uid_element_value, shift_left = formula_element
                    if c_block_uid_formula != '':  # if the formula is not empty, then need to add the prev value to the new
                        c_block_uid_formula += " + "
                    if shift_left != 0:
                        new_element_str = "({0}<<{1})".format(uid_element_value, shift_left)
                    else:
                        # if shiftleft = 0, then there is nothing to do. this is for the last element of the formula (the LSB value)
                        new_element_str = "{0}".format(uid_element_value)
                    c_block_uid_formula = "({0}{1})".format(c_block_uid_formula, new_element_str)

                mem_block['uid'] = block_uid_data['uid_value']

                if 'description' in block_uid_data:
                    mem_block['description'] = block_uid_data['description']
            mem_block['math_formula'] = c_block_uid_formula
        dic[mem_block['uid']] = mem_block
        map[mem_block['uid']] = mem_block['block_name']
    return map, dic


def get_uids_to_block_name(block_uids, block_to_sw_path_config_list):
    uids_to_block_name = {}
    for key, value in block_uids.items():
        value = value.upper()
        block_instance_name = value
        sbus_str_pos = block_instance_name.find("_SBUS")
        uoff_str_pos = block_instance_name.find("_UNIT_OFF")
        if sbus_str_pos >= 0:
            block_instance_name = block_instance_name[0:sbus_str_pos] + "_UID"
        elif uoff_str_pos >= 0:
            pass
        else:
            block_instance_name += "_UID"
        try:
            lbr_block_name_and_sw_path_for_block = get_lbr_block_name_and_sw_path_for_block(
                block_instance_name, block_to_sw_path_config_list)
        except BaseException:
            uids_to_block_name[key] = {'instance_name': value, 'block_structure': "not_found"}
            continue

        uids_to_block_name[key] = {'instance_name': value,
                                   'block_structure': lbr_block_name_and_sw_path_for_block['lbr_block_name']}
    return uids_to_block_name


# @brief Helper class for indented file writing
#
# Writes lines to a file, indetnted to a specified depth


class indented_writer:
    # @brief Indented writed constuctor
    #
    # @param[in] fileobj   File object opened for writing

    def __init__(self, fileobj):
        self.indent_len = 4  # default number of indent spaces per depth
        self.depth = 0      # indentation level
        self.fileobj = fileobj

    # @brief Returns an indentation string
    #
    # @return The indentation string
    def indent(self):
        return " " * self.indent_len * self.depth

    # @brief Writes an indented string to a file
    def write(self, str):
        str = str.encode('ascii', 'ignore').decode('ascii')
        self.fileobj.write(self.indent() + str)

    # @brief Writes non-indented string to a file
    def write_noindent(self, str):
        self.fileobj.write(str)


def write_namespace_begin(writer, namespace):
    if namespace:
        writer.write("namespace {} {{\n\n".format(namespace))


def write_namespace_end(writer, namespace):
    if namespace:
        writer.write("}} // namespace {}\n\n".format(namespace))


# @brief Translates a binary representation into a big-endian-ordered list of n_byte elements
#
# Translates a binary string (of any length) into a list of hexadecimal n_byte elements. The list is big-endian.
# For example, the array of uint32_t representation of a binary string:
#       '10000000 01000000 00100000 00010000 00001001 00000111 00000101 00000011' (the spaces should be removed)
#       0x80      40       20       10       09       07       05       03       == 0x8040201009070503
#   as big-endian array of uint32_t is:
#       ['0x09070503', '0x80402010']
#
# @param[in] binary_str     The clean binary value string (without the '0b' at the beginning)
# @param[in] n_byte         The size in bytes of elements in the result string.
#
# @return The list of n_byte elements in big-endian order.
def get_n_byte_hex_list(binary_str, n_byte=None):
    # get a hex string from the binary
    hex_str = hex(int(binary_str, 2))[2:].rstrip("L")

    # the hex_str doesn't include any leading zeros, but its needed to build a
    # full-size array, so calc the length of the full hex string
    num_of_bytes = width_in_bytes(len(binary_str))

    if n_byte is None:
        n_byte = num_of_bytes

    hex_chars_in_n_bytes = 2 * n_byte

    num_of_n_byte_chunks = div_round_up(num_of_bytes, n_byte)
    hex_str = hex_str.zfill(num_of_n_byte_chunks * hex_chars_in_n_bytes)

    # split the hex_str into chunks of a n_bytes
    list_of_n_byte_elements = [
        hex_str[
            i *
            hex_chars_in_n_bytes:(
                i +
                1) *
            hex_chars_in_n_bytes] for i in range(
            0,
            num_of_n_byte_chunks)]

    # the list of n_byte elements is going to be used as a list of uint8/16/32/64 so it should be big endian
    list_of_n_byte_elements.reverse()

    # prepend each element with 0x
    list_of_n_byte_elements = ["0x" + clean_hex for clean_hex in list_of_n_byte_elements]

    return list_of_n_byte_elements


# @brief Returns the number of bytes needed to accomodate width_in_bits bits
#
# @param[in] width_in_bits          Number of bits
#
# @return The number of bytes needed to accomodate width_in_bits bits
def width_in_bytes(width_in_bits):
    return div_round_up(width_in_bits, 8)


# @brief Returns the result of a division, rounded up to smallest integer value greater than or equal to it.
#
# @param[in] dividend       The value to divide
# @param[in] divisor        The value to divide by
#
# @return The result of a division, rounded up to smallest integer value greater than or equal to it.
def div_round_up(dividend, divisor):
    return int(math.ceil(dividend / divisor))

# @brief Re-raises an exception appending a new message.
#
# @param[in] inst               Exception object
# @param[in] new_msg            New message to append


def reraise(inst, new_msg):
    raise type(inst)(new_msg)


# @brief updates 'slice', 'slice pair' and 'ifg' indices according to 'InstanceAllocation' paremeter and its corresponding 'instance'
#
# @param[in] slice_index            current known 'slice'      index
# @param[in] slice_pair_index       current known 'slice_pair' index
# @param[in] ifg_index              current known 'ifg'        index
# @param[in] instance_allocation    the interpretation of 'allocated_index', can be one of: ['per_slice', 'per_slice_pair', 'per_ifg']
# @param[in] allocated_index        the interpreted index
def update_indices_by_instance_allocation(slice_index, slice_pair_index, ifg_index, instance_allocation, allocated_index):
    if instance_allocation is not None:
        if instance_allocation == 'per_slice':
            if slice_index is None:
                if slice_pair_index is not None:
                    slice_index = (slice_pair_index * 2) + allocated_index
                else:
                    slice_index = allocated_index
            else:
                exception_massage = '\'InstanceAllocation\' with \'{0}\' attribute cannot be set when slice is already known. slice = {1}'.format(
                    instance_allocation, slice_index)
                raise Exception(exception_massage)
        elif instance_allocation == 'per_slice_pair':
            if slice_pair_index is None:
                slice_pair_index = allocated_index
            else:
                exception_massage = '\'InstanceAllocation\' with \'{0}\' attribute cannot be set when slice pair is already known. slice pair = {1}'.format(
                    instance_allocation, slice_pair_index)
                raise Exception(exception_massage)
        elif instance_allocation == 'per_ifg':
            if ifg_index is None:
                if slice_index is not None:
                    ifg_index = (slice_index * 2) + allocated_index
                elif (slice_pair_index is not None):
                    ifg_index = (slice_pair_index * 4) + allocated_index
                else:
                    ifg_index = allocated_index
            else:
                exception_massage = '\'InstanceAllocation\' with \'{0}\' attribute cannot be set when ifg is already known. ifg = {1}'.format(
                    instance_allocation, ifg_index)
                raise Exception(exception_massage)
        else:
            exception_massage = '\'InstanceAllocation\' attribute can hold only one the following: [\'per_slice\', \'per_slice_pair\', \'per_ifg\']. \'{0}\' is illegal.'.format(
                instance_allocation)
            raise Exception(exception_massage)

    # Calculate other indices:
    if ifg_index is not None:
        slice_index = slice_index if slice_index is not None else int(ifg_index / 2)
        slice_pair_index = slice_pair_index if slice_pair_index is not None else int(ifg_index / 4)
    elif slice_index is not None:
        slice_pair_index = slice_pair_index if slice_pair_index is not None else int(slice_index / 2)

    return slice_index, slice_pair_index, ifg_index


# @brief    parses slice, slice_pair, ifg and block indices from sw_path
def parse_sw_path(block_sw_path):
    re_pattern_slice = r'slice\[(\d*)\]'
    re_pattern_slice_pair = r'slice_pair\[(\d*)\]'
    re_pattern_ifg = r'ifg\[(\d*)\]'
    re_pattern_block = r'\[(\d*)\]$'       # if exists - ends with '[block_num]'

    slice_index = re.search(re_pattern_slice, block_sw_path)
    slice_pair_index = re.search(re_pattern_slice_pair, block_sw_path)
    ifg_index = re.search(re_pattern_ifg, block_sw_path)
    block_index = re.search(re_pattern_block, block_sw_path)

    slice_pair_index = int(slice_pair_index.group(1)) if (slice_pair_index is not None) else None
    slice_index = int(slice_index.group(1)) if (slice_index is not None) else None
    ifg_index = int(ifg_index.group(1)) if (ifg_index is not None) else None
    block_index = int(block_index.group(1)) if (block_index is not None) else None

    return slice_pair_index, slice_index, ifg_index, block_index

# @brief check whether 'init_macro' evaluation is dependent on 'dependence_to_check' token


def check_dependence(init_macro, dependence_to_check):
    if init_macro is None:
        return False

    # Example for 'line':   '[^_]line|^line'
    # without the [^_]line we might capture 'num_lines'
    # without the |^<token> we might miss capturing 'line' that appears in the
    # start of the expression (because the first part of the regex masks it)
    match = '[^_]' + dependence_to_check + '|^' + dependence_to_check
    return (re.search(match, init_macro) is not None)
