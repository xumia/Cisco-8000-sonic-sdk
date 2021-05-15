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

# Generate C++ API for register/memory access on logical sw-path tree

import os.path
import logging
import sys
import argparse
import datetime
from lbr_parsing_common import *
from lbr_api_generator_sdk import *
from lbr_api_generator_npsuite import *
from sv_init_config_generator import load_verilog_to_sv_instance_dict, create_sv_config_files
from init_functions_generator import create_init_functions
from textwrap import dedent
import locale

# @brief Main function that manages the code-generation process
#
# 1. Parse script arguments.
#
# 2. Process the LBR file:
#    Read LBR file.
#    Modify its contents from perl-hash format to JSON format, and store a new string.
#    Load the new string as JSON data into a blocks dict.
#    Process all register and memory entries in each block and build register and memory lists.
#
# 3. Process verilog block defines:
#    Read the verilog block file.
#    For each block extract block name and UID calculation formula
#
# 4. Create SW paths:
#    Read the SW path mapping JSON file
#    For each block from the verilog defines calculate the SW path. For blocks marked as having an SBUS, also creates an SBUS sub-block
#
# 5. Prepare c++ classes
#    From the SW paths prepare classes and members to represent the SW path tree
#
# 6. Generate C API file
#
# 7. Generate SWIG interface file


def main():
    # TODO - merge the following: custom_blockname_defines_filename,
    # block_to_sw_path_config_filename, block_address_base_* to a single JSON file.
    lbr_rev1_filenames, \
        lbr_rev2_filenames, \
        lbr_overrides_filename, \
        blockname_uid_defines_filename, \
        custom_blockname_defines_filename, \
        block_to_sw_path_config_filename, \
        verilog_default, \
        base_address, \
        target, \
        out_filename, \
        verilog_to_sv_instance_filename, \
        sv_defines_file_path, \
        sdk_init_functions_out_path = parse_arguments()

    oldLocale = locale.getlocale()
    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')

    asic_name = get_asic_name(target, out_filename)

    create_hw_sv_init_config = True if verilog_to_sv_instance_filename is not None else False
    create_sdk_init_functions = True if sdk_init_functions_out_path is not None else False

    if verilog_default is not None:
        parse_verilog_default(verilog_default)

    # Optional older revision 'rev1'. Currently, we support only one "older" revision.
    lbr_raw = process_multiple_lbr_files(lbr_rev1_filenames)
    lbr_rev1_parsed = parse_raw_lbr(lbr_raw, "rev1", create_hw_sv_init_config)

    # Mandatory current revision 'rev2'
    lbr_raw = process_multiple_lbr_files(lbr_rev2_filenames)
    lbr_rev2_parsed = parse_raw_lbr(lbr_raw, "rev2", create_hw_sv_init_config)

    merge_rule = MERGE__REV1_SUBSET__REV2_SUPERSET
    lbr_parsed = merge_rev1_and_rev2(lbr_rev1_parsed, lbr_rev2_parsed, merge_rule)

    lbr_parsed = override_lbr_data(lbr_parsed, lbr_overrides_filename)
    lbr_parsed = override_reg_cams(lbr_parsed)
    blockname_uid_list = parse_verilog_blockname_uid_defines_file(blockname_uid_defines_filename)
    blockname_uid_list = parse_custom_blockname_uid_file(blockname_uid_list, custom_blockname_defines_filename)

    block_to_sw_path_config_list = load_block_to_sw_path_config_list(block_to_sw_path_config_filename)
    blockname_uid_list, flat_classes, sw_paths_with_uid = build_classes_and_sw_paths_with_sbus(
        blockname_uid_list, block_to_sw_path_config_list)

    if create_hw_sv_init_config:
        verilog_to_sv_instance = load_verilog_to_sv_instance_dict(verilog_to_sv_instance_filename)
        create_sv_config_files(sw_paths_with_uid, lbr_parsed, verilog_to_sv_instance, out_filename, False)
        create_sv_config_files(sw_paths_with_uid, lbr_parsed, verilog_to_sv_instance, out_filename, True)

    else:
        sbif_overrides = {
            'base_address': base_address,
            'base_address_skip_names': ['css_mem_even', 'css_mem_odd'],
            'need_memory_padding': 'false',  # default=='true'
            'register_step': 4,  # default==1
            'phys_per_logical': '2',  # default==1
            'MemLogicalWidth': 32,
            'MemTotalWidth': 32,
        }

        if target == NPSUITE_TARGET:
            uid_map, uid_dic = create_block_id_dic(blockname_uid_list)
            uids_to_block_name = get_uids_to_block_name(uid_map, block_to_sw_path_config_list)
            additional_blocks = create_additional_block_structures(flat_classes, lbr_parsed)
            write_npsuite_lbr_json(
                out_filename,
                lbr_parsed,
                uids_to_block_name,
                additional_blocks,
                sbif_overrides)
        else:
            create_c_files(
                out_filename,
                lbr_parsed,
                blockname_uid_list,
                flat_classes,
                sw_paths_with_uid,
                sbif_overrides)

            create_json_file(out_filename, lbr_parsed)

            create_swig_file(out_filename, flat_classes)

            if create_sdk_init_functions:
                create_init_functions(
                    lbr_parsed,
                    asic_name,
                    sv_defines_file_path,
                    sdk_init_functions_out_path)
    locale.setlocale(locale.LC_ALL, oldLocale)


# @brief Parses script arguments, and returns them
#
# Builds an argument parser object, and parses the arguments passed to the script.
# Enables global debugging if required.
#
# @return Input LBR filenames (lbr_filenames), Input verilog defines filename of blockname to UID (blockname_uid_defines_filename),...
# @return ..., Input custom additional blocks filename (custom_blockname_defines_filename), Input blockname to SW-path configuration filename (block_to_sw_path_config_filename),...
# @return ..., Output generated C++ file basename, Input dictionary of address offset base per blockname
def parse_arguments():
    # configure an argument parser
    parser = argparse.ArgumentParser(
        description='Create C++ code from LBR files',
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True)

    req_group = parser.add_argument_group(title='required arguments')
    req_group.add_argument('-l1', '--lbr_rev1', metavar='<lbr_file>', help='input LBR rev1 files', nargs='+', action='append')
    req_group.add_argument('-l2', '--lbr_rev2', metavar='<lbr_file>', required=True,
                           help='input LBR rev2 files', nargs='+', action='append',)
    req_group.add_argument('-bu', '--block_uid', metavar='<blockname_uid_defines_filename>',
                           required=True, help='input verilog file with blockname to UID defines')
    req_group.add_argument('-cb', '--custom_block', metavar='<custom_blockname_defines_filename>',
                           required=True, help='input JSON file with custom blocks - including mock blocks')
    req_group.add_argument('-slo', '--lbr_overrides', metavar='<lbr_overrides_filename>',
                           required=True, help='input JSON file with lbr overrides')
    req_group.add_argument('-bp', '--block_path', metavar='<block_to_sw_path_config_filename>',
                           required=True, help='input JSON with a mapping from blocknames and sw paths')
    req_group.add_argument('-vd', '--verilog_default', metavar='<verilog_default>',
                           required=False, nargs='?', help="Verilog default file")
    req_group.add_argument('-ba', '--base_address', metavar='<base_address>', required=True, help="Device sbif base adress")
    req_group.add_argument('-t', '--target', metavar='<target>', required=False, default='sdk',
                           help='generate different files, based on the provided target, sdk (default) or npsuite')
    req_group.add_argument('-o', '--out', metavar='<out_file>', required=True, help='output generated .cpp/.h file')
    req_group.add_argument('-si', '--sv_instance', metavar='<verilog_to_sv_instance>',
                           required=False, help='<verilog_blockname, sv instance name> map')
    req_group.add_argument('-sd', '--sv_defines', metavar='<sv_defines>', required=False, help='<SystemVerilog Defines')
    req_group.add_argument(
        '-sifo',
        '--sdk_init_functions_out',
        metavar='<sdk_init_functions_out>',
        required=False,
        help='sdk init functions out path')

    parser.add_argument('--debug', action='store_true', help='print debug information')

    # parse arguments
    parsed_args = parser.parse_args()

    # enable debugging if debug argument is enable
    if parsed_args.debug:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

    # store the parsed arguments in local variables
    # the flattening is required because the -action='append'- of the --lbr
    # parameter. for example, if one passess --lbr file1 file2 --lbr file3,
    # the arg will be [['file1', 'file2'], ['file3']]
    lbr_rev1_filenames = flatten_list(parsed_args.lbr_rev1) if parsed_args.lbr_rev1 else []
    lbr_rev2_filenames = flatten_list(parsed_args.lbr_rev2) if parsed_args.lbr_rev2 else []
    verilog_default = parsed_args.verilog_default
    base_address = parsed_args.base_address
    target = parsed_args.target
    out_filename = parsed_args.out
    lbr_overrides_filename = parsed_args.lbr_overrides
    blockname_uid_defines_filename = parsed_args.block_uid
    custom_blockname_defines_filename = parsed_args.custom_block
    block_to_sw_path_config_filename = parsed_args.block_path
    verilog_to_sv_instance = parsed_args.sv_instance
    verilog_to_sv_defines = parsed_args.sv_defines
    sdk_init_functions_out_path = parsed_args.sdk_init_functions_out

    logging.debug(
        "parsed arguments:\n lbr_rev1_filenames=%s\n lbr_rev2_filenames=%s\n blockname_uid_defines_filename=%s\n lbr_overrides_filename=%s\n custom_blockname_defines_filename=%s\n block_to_sw_path_config_filename=%s\n verilog_default=%s\n base_address=%s\n target=%s\n out_filename=%s\n verilog_to_sv_instance=%s\n verilog_to_sv_defines=%s\n sdk_init_functions_out_path=%s\n",
        lbr_rev1_filenames,
        lbr_rev2_filenames,
        lbr_overrides_filename,
        blockname_uid_defines_filename,
        custom_blockname_defines_filename,
        block_to_sw_path_config_filename,
        verilog_default,
        base_address,
        target,
        out_filename,
        verilog_to_sv_instance,
        verilog_to_sv_defines,
        sdk_init_functions_out_path)

    return lbr_rev1_filenames, lbr_rev2_filenames, lbr_overrides_filename, blockname_uid_defines_filename, custom_blockname_defines_filename, block_to_sw_path_config_filename, verilog_default, base_address, target, out_filename, verilog_to_sv_instance, verilog_to_sv_defines, sdk_init_functions_out_path


# @brief Flattens a list of lists (of lists..) of elements to a flat list.
#
# @param[in] l  Original variable depth list
#
# @return The flattened list
def flatten_list(l):
    if l == []:
        return l
    if isinstance(l, list):
        return flatten_list(l[0]) + flatten_list(l[1:])
    return [l]


if __name__ == "__main__":
    main()
    # pretty_print(TotalSizes)
