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

import os.path
import json
import argparse
from nplapi_utilities import file_utils
from device_tables_utils import files_specifications as fs

# Global variables
DEVICE = "device"
SLICE = "slice"
SLICE_PAIR = "slice_pair"

######################################################
# CLASS: device_tables_src_template
# @brief Generates device_tables source file
######################################################


class device_tables_src_template:
    file_name = 'device_tables.cpp'

    prefix = fs.get_source_prefix()
    suffix = fs.get_source_suffix()

    # GLOBAL LOGICAL COMMON FORMAT
    global_logical_format = '''
          {name} = std::make_shared<{type}>();
          retval = init_table(creator, {name}, {slice_index}, table_allocation_e::{allocation});
          return_on_error(retval, TABLES, ERROR, "table initialization failed: {name}, %s", la_status2str(retval).c_str());'''

    # PER SLICE-PAIR LOGICAL TABLES
    per_slice_pair_format = '''
          for (size_t slice_pair = 0; slice_pair < array_size({name}); slice_pair++) {{
             {name}[slice_pair] = std::make_shared<{type}>();
             retval = init_table(creator, {name}[slice_pair], {{slice_pair * 2, slice_pair * 2 + 1}}, table_allocation_e::{allocation});
             return_on_error(retval, TABLES, ERROR, "table initialization failed: {name}(%ld), %s", slice_pair, la_status2str(retval).c_str());
          }}'''

    # PER SLICE-PAIR LOGICAL TABLES (single-slice degenerate case)
    per_slice_pair_single_slice_format = '''
          for (size_t slice_pair = 0; slice_pair < array_size({name}); slice_pair++) {{
             {name}[slice_pair] = std::make_shared<{type}>();
             retval = init_table(creator, {name}[slice_pair], 0, table_allocation_e::{allocation});
             return_on_error(retval, TABLES, ERROR, "table initialization failed: {name}(%ld), %s", slice_pair, la_status2str(retval).c_str());
          }}'''

    # INTERNAL TABLES
    internal_format = '''
          for (la_slice_id_t slice_id = 0; slice_id < array_size({name}); slice_id++) {{
             {name}[slice_id] = std::make_shared<{type}>();
             retval = init_table(creator, {name}[slice_id], slice_id, table_allocation_e::{allocation});
             return_on_error(retval, TABLES, ERROR, "table initialization failed: {name}(%d), %s", slice_id, la_status2str(retval).c_str());
          }}'''

    def write_line(base_format, name, slice_index, allocation):
        line = base_format.format(
            name=name,
            type=device_tables_hdr_template.to_type(name),
            slice_index=slice_index,
            allocation=allocation)
        return line

    # Given table's properties, returns parameters for string format
    @classmethod
    def get_format_args(cls, name, table_dict, num_slices):
        loc = table_dict['location']
        allocation = loc.upper()
        override = table_dict['override']
        slice_index = None
        if table_dict['is_npu']:
            line_format = cls.global_logical_format
            allocation = "SLICE"
            slice_index = "{} /*slice id*/".format(num_slices)
            if name == "redirect_table":
                slice_index = "{" + ", ".join(str(s) for s in range(num_slices + 1)) + "} /*all slices with host*/"
        elif override == DEVICE:
            line_format = cls.global_logical_format
            if loc == DEVICE:
                slice_index = "0 /*slice id*/"
            elif loc == SLICE_PAIR:
                if num_slices == 1:
                    slice_index = "0 /*all slice pairs*/"
                else:
                    num_slice_pairs = int(max(num_slices / 2, 1))
                    slice_index = "{" + ", ".join(str(s) for s in range(num_slice_pairs)) + "} /*all slice pairs*/"
            else:
                if num_slices == 1:
                    slice_index = "0 /*all slices*/"
                else:
                    slice_index = "{" + ", ".join(str(s) for s in range(num_slices)) + "} /*all slices*/"
        elif loc == override:
            line_format = cls.internal_format
        else:
            if num_slices == 1:
                # Degenerate case, e.g. Asic5
                line_format = cls.per_slice_pair_single_slice_format
            else:
                line_format = cls.per_slice_pair_format

        return line_format, slice_index, allocation

    @classmethod
    def generate_file(cls, tables, dir_name, num_slices):
        lines = []
        lines.append(cls.prefix.replace('%(num_slices)', str(num_slices)))
        for name in tables:
            line_format, slice_index, allocation = cls.get_format_args(name, tables[name], num_slices)
            next_line = cls.write_line(line_format, name, slice_index, allocation)
            lines.append(next_line)
        lines.append(cls.suffix)
        file_utils.generate_source_file(dir_name, cls.file_name, lines)


######################################################
# CLASS: device_tables_hdr_template
# @brief Generates device_tables header file
######################################################

class device_tables_hdr_template:
    file_name = 'device_tables.h'

    prefix = fs.get_header_prefix()
    suffix = fs.get_header_suffix()

    def to_type(name):
        type_t = 'npl_' + name + '_t'
        return type_t

    def is_npuh_fi(name):
        npuh_fi_names = [
            'fi_core_tcam_table',
            'fi_macro_config_table',
            'rxpp_fi_rtc_stage_tcam_table',
            'rxpp_fi_rtc_stage_macro_config_table']
        return name in npuh_fi_names

    @classmethod
    def write_declaration(cls, name, table_dict, num_slices):
        loc = table_dict['location']
        override = table_dict['override']
        is_npuh = table_dict['is_npu']
        line_suffix = ''
        if not is_npuh:
            if override == SLICE:
                line_suffix = "[{}]".format(num_slices)
            elif override == SLICE_PAIR:
                num_slice_pairs = int(max(num_slices / 2, 1))
                line_suffix = '[{}]'.format(num_slice_pairs)
        if cls.is_npuh_fi(name):
            line_suffix = '[{}]'.format(num_slices + 1)  # per-slice and npuh
        type_t = cls.to_type(name)
        next_line = "std::shared_ptr<" + type_t + "> " + name + line_suffix + ";\n"

        return next_line

    @classmethod
    def write_lines(cls, tables, num_slices):
        lines = []
        for name in tables:
            next_line = cls.write_declaration(name, tables[name], num_slices)
            lines.append(next_line)
        return lines

    @classmethod
    def generate_file(cls, tables, dir_name, num_slices):
        lines = []
        lines.append(cls.prefix)
        lines += cls.write_lines(tables, num_slices)
        lines.append(cls.suffix)
        file_utils.generate_header_file(dir_name, cls.file_name, lines)


#######################################################
# SCRIPT
#######################################################

def device_to_slice_count(device):
    device_name = device.split('_')[0].lower()
    num_slices = None
    if device_name == 'asic5':
        num_slices = 1
    elif device_name == 'asic3':
        num_slices = 8
    elif device_name in ('pacific', 'gibraltar', 'asic4'):
        num_slices = 6
    else:
        raise ValueError('Unrecognized device "{}"'.format(device))
    return num_slices


def parse_arguments():
    # configure an argument parser
    parser = argparse.ArgumentParser(
        description="Generate device tables files, based on nplapi tables",
        add_help=True)

    req_group = parser.add_argument_group(title='required arguments')
    req_group.add_argument('--device', required=True, help='device for which to generate')
    req_group.add_argument('--databases', required=True, help='input JSON file, databases-placements data file')
    req_group.add_argument('--overrides_file', required=True, help='input JSON file, containing logical allocations of tables.')
    req_group.add_argument('--nplapi_tables', required=True, help='input JSON file, nplapi tables.')
    req_group.add_argument('-o', '--output', required=True, help='output directory to store results')

    # parse arguments
    parsed_args = parser.parse_args()

    return parsed_args


def read_file(file_name):
    with open(file_name, 'r') as fd:
        return json.load(fd)


def check_override(name, overrides, physical_loc):
    if name in overrides:
        dic_t = overrides[name]
        if 'granularity' in dic_t:
            return dic_t['granularity']
    return None


def is_internal(table):
    return table['location'] == 'internal'


def get_table_db(npl_table):
    return npl_table["database"]


def ext_table_has_placements(db, db_placements_dict):
    return 'placements' in db_placements_dict[db]


def get_placements(table, db_placements_dict):
    placements = {}
    if table["location"] == "internal":
        if 'placements' in table:
            placements = table['placements']
    else:  # external table
        db = get_table_db(table)
        if ext_table_has_placements(db, db_placements_dict):
            placements = db_placements_dict[db]["placements"]

    return placements


def is_npu_host(table, db_placements_dict):
    placements = get_placements(table, db_placements_dict)
    if placements:  # placements dictionary is not empty
        host_list = []
        if 'host' in placements:
            host_list = placements['host']
        elif 'context_none' in placements:
            host_list = placements['context_none']

        if host_list and ('engine' in host_list[0]):
            engine = host_list[0]['engine']
            if engine in ['npuh.npe', 'npu_host']:
                return True
    return False


def create_data_struct(overrides, npl_tables, db_placements_dict):
    tables = {}
    for table in npl_tables:
        if is_internal(npl_tables[table]):
            p_loc = SLICE
            npuh = is_npu_host(npl_tables[table], db_placements_dict)
        else:
            db = get_table_db(npl_tables[table])
            if db not in db_placements_dict:
                continue
            p_loc = db_placements_dict[db]['allocation']
            npuh = is_npu_host(npl_tables[table], db_placements_dict)

        l_loc = check_override(table, overrides, p_loc)
        if l_loc is None:
            l_loc = p_loc
        tables[table] = {'location': p_loc, 'override': l_loc, 'is_npu': npuh}

    # Manually add tables missing in external tables file
    tables['inject_mact_ldb_to_output_lr'] = {'location': SLICE, 'override': DEVICE, 'is_npu': False}
    tables['lr_filter_write_ptr_reg'] = {'location': DEVICE, 'override': DEVICE, 'is_npu': False}
    tables['lr_write_ptr_reg'] = {'location': DEVICE, 'override': DEVICE, 'is_npu': False}
    tables['learn_manager_cfg_max_learn_type_reg'] = {'location': DEVICE,
                                                      'override': DEVICE, 'is_npu': False}
    return tables


if __name__ == '__main__':
    # parse and store arguments
    args = parse_arguments()
    os.makedirs(args.output, exist_ok=True)
    db_placements_dict = read_file(args.databases)
    overrides = read_file(args.overrides_file)
    npl_tables = read_file(args.nplapi_tables)

    # rearrange and store all tables in dictionary
    tables = create_data_struct(overrides, npl_tables, db_placements_dict)

    num_slices = device_to_slice_count(args.device)

    # generate device_tables.h
    device_tables_hdr_template.generate_file(tables, args.output, num_slices)

    # generage device_tables.cpp
    device_tables_src_template.generate_file(tables, args.output, num_slices)
