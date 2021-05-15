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
import fnmatch
from shutil import copyfile
import sys
import getopt
import argparse
import re
import json
import configparser



def copy_with_path(src_lbr_path, relative_path, dest_base_path, dry_run, verbose):
    src_lbr_dir_path, lbr_name = os.path.split(src_lbr_path)
    dest_lbr_dir_path = os.path.join(dest_base_path, relative_path)

    dst_lbr_path = os.path.join(dest_lbr_dir_path, lbr_name)

    if verbose:
        is_dry_run_str = 'DRY RUN ' if dry_run else ''
        print('%scopying file %s to %s' % (is_dry_run_str, src_lbr_path, dst_lbr_path))

    if not dry_run:
        os.makedirs(dest_lbr_dir_path, exist_ok=True)
        copyfile(src_lbr_path, dst_lbr_path)




def get_lbr_block_name(lbr_filename):
    lbr_block_name_pattern = re.compile("\$block *\{([A-Za-z0-9_]*)\}")
    with open(lbr_filename, "r") as lbr_file:
        line = lbr_file.readline()
        mo = re.match(lbr_block_name_pattern, line)

        if mo is not None:
            return mo.group(1).lower()
        else:
            return None




def check_unmapped_blocks(json_file_path, block_to_files_map, ignore_unmapped_blocks_set):

    block_name_line_pattern = re.compile('\s*\"lbr_block_name\"\:\s*\"(\w+)\"')
    mapped_lbrs = set()

    with open(json_file_path, "r") as json_file:
        for line in json_file:
            mo = re.match(block_name_line_pattern, line)
            if mo is not None:
                mapped_lbrs.add(mo.group(1).lower())

    for mapped_lbr in mapped_lbrs:
        if mapped_lbr not in block_to_files_map.keys():
            print('WARNING: LBR block %s is mapped in block_to_sw_path.json although it does not exist or ignored' % mapped_lbr)

    for block_name, files in block_to_files_map.items():
        if (block_name not in mapped_lbrs) and (block_name not in ignore_unmapped_blocks_set):
            file_paths = [f['full_path'] for f in files]
            print('ERROR: LBR block %s from file(s) %s not mapped in block_to_sw_path.json' % (block_name, ','.join(file_paths)))


def get_ignore_sets(ignore_path, design_trunk_path):
    ignore_blocks_set = set()
    ignore_files_set = set()
    non_hardware_blocks_set = set()
    no_update_blocks_set = set()
    ignore_unmapped_blocks_set = set()

    if not os.path.exists(ignore_path):
        print('.lbr_ignore file does not exist')
    else:
        config = configparser.ConfigParser(inline_comment_prefixes=(';'), allow_no_value=True)
        config.read(ignore_path)

        if 'Ignored Blocks' in config.sections():
            for block in config['Ignored Blocks'].keys():
                ignore_blocks_set.add(block)

        if 'Ignored Files' in config.sections():
            for lbr_path in config['Ignored Files'].keys():
                full_path = os.path.join(design_trunk_path, lbr_path)
                ignore_files_set.add(full_path)

        if 'Non Hardware Blocks' in config.sections():
            for block in config['Non Hardware Blocks'].keys():
                non_hardware_blocks_set.add(block)

        if 'No Update Blocks' in config.sections():
            for block in config['No Update Blocks'].keys():
                no_update_blocks_set.add(block)

        if 'Ignore Unmapped Blocks' in config.sections():
            for block in config['Ignore Unmapped Blocks'].keys():
                ignore_unmapped_blocks_set.add(block)

    return (ignore_blocks_set, ignore_files_set, non_hardware_blocks_set, no_update_blocks_set, ignore_unmapped_blocks_set)

def get_block_to_files_map(main_dir_path, subdirectories=['.'], ignore_blocks_set=set(), ignore_files_set=set(), non_hardware_blocks_set=set(), no_update_blocks_set=set()):
    block_to_files_map = {}

    for subdir in subdirectories:
        dir_path = os.path.join(main_dir_path, subdir)
        for directory, _, files in os.walk(dir_path):
            for f in files:
                if fnmatch.fnmatch(f, '*.lbr'):
                    full_path = os.path.join(directory, f)

                    if full_path in ignore_files_set:
                        continue

                    lbr_block_name = get_lbr_block_name(full_path)

                    if lbr_block_name == None:
                        print("ERROR: No LBR block name in file %s: " % full_path)
                    elif lbr_block_name in no_update_blocks_set:
                        block_to_files_map[lbr_block_name] = []
                    elif lbr_block_name not in ignore_blocks_set:
                        file_location = {'full_path': full_path,
                                         'directory': dir_path,
                                         'subdirectory_within_trunk': subdir}
                        block_to_files_map.setdefault(lbr_block_name, []).append(file_location)

    for block in non_hardware_blocks_set:
        if block in block_to_files_map:
            print('ERROR: Block %s appears in non HW blocks list but is found in a hardware LBR' % block)
        block_to_files_map[block] = []

    return block_to_files_map

def copy_lbr_files_from_design(block_to_files_map, sdk_lbr_dir_path, dry_run, verbose):
    for block, files in block_to_files_map.items():
        assert len(files) <= 1
        if len(files) == 1:
            full_src_path = files[0]['full_path']
            full_src_dir_path, _ = os.path.split(full_src_path)
            base_dir_path = os.path.join(files[0]['directory'])
            relative_path_within_design_dir = os.path.relpath(full_src_dir_path, base_dir_path)
            copy_with_path(full_src_path, relative_path_within_design_dir, sdk_lbr_dir_path, dry_run, verbose)

def check_duplicate_blocks(block_to_files_map):
    has_duplicates = False

    for block_name, files in block_to_files_map.items():
        if len(files) > 1:
            file_paths = [f['full_path'] for f in files]
            print('ERROR: Duplicate LBR Blocks for block %s found in files %s' % (block_name, ','.join(file_paths)))
            has_duplicates = True

    return has_duplicates


def main():
    arg_parser = argparse.ArgumentParser(description='Copies .lbr files from design to device directories and analyzes them')
    arg_parser.add_argument("--design-trunk", type=str, required=True, help='Path to design trunk directory')
    arg_parser.add_argument("--design-subdirs", type=str, required=True, help='Design subdirectories containing LBRs, comma delimited e.g. graphene,shared')
    arg_parser.add_argument("--device", type=str, required=True, help='Path to device directory. e.g ./devices/akpg/graphene')
    arg_parser.add_argument("--lbr-dir", type=str, required=True, help='Name of LBR directory within device directory. e.g. lbr')
    arg_parser.add_argument("--dry-run", action="store_true", help='Do not copy LBRs, only perform checks for duplicate and unused blocks')
    arg_parser.add_argument("-v", "--verbosity", action="count", default=0, help="Verbose. Can use multiple times to increase verbosity")
    args = arg_parser.parse_args()



    design_trunk_path = args.design_trunk
    design_subdirectories = args.design_subdirs.split(',')
    device_dir_path = args.device
    lbr_dir_relative_path = args.lbr_dir
    dry_run = args.dry_run

    if (not design_trunk_path.endswith('trunk/')) and (not design_trunk_path.endswith('trunk')):
        print('WARNING: --design directory should end with trunk/')

    lbr_ignore_path = os.path.join(device_dir_path, ".lbr_ignore")
    ignore_blocks_set, ignore_files_set, non_hardware_blocks_set, no_update_blocks_set, ignore_unmapped_blocks_set = get_ignore_sets(lbr_ignore_path, design_trunk_path)

    print('PHASE: Doing pre checks on LBRs in **design** directory')
    block_to_files_map = get_block_to_files_map(design_trunk_path, design_subdirectories, ignore_blocks_set, ignore_files_set, non_hardware_blocks_set, no_update_blocks_set)
    json_file_path = os.path.join(device_dir_path, "block_info/block_to_sw_path.json")
    check_unmapped_blocks(json_file_path, block_to_files_map, ignore_unmapped_blocks_set)
    has_duplicates = check_duplicate_blocks(block_to_files_map)

    if has_duplicates:
        print('ERROR: Duplicate blocks found. Cannot proceed. Add irrelevant files to .lbr_ignore file')
        sys.exit(1)

    sdk_lbr_dir_path = os.path.join(device_dir_path, lbr_dir_relative_path)

    print('PHASE: Copying files from design to SDK%s' % (' (dry run)' if dry_run else ''))
    copy_lbr_files_from_design(block_to_files_map, sdk_lbr_dir_path, dry_run, args.verbosity > 0)

    # post checks: check unmapped and duplicates in SDK directory
    print('PHASE: Doing post checks on LBRs in **sdk** directory')
    sdk_block_to_files_map = get_block_to_files_map(sdk_lbr_dir_path, non_hardware_blocks_set=non_hardware_blocks_set)
    check_unmapped_blocks(json_file_path, sdk_block_to_files_map, ignore_unmapped_blocks_set)
    sdk_has_duplicates = check_duplicate_blocks(sdk_block_to_files_map)
    if sdk_has_duplicates:
        print('ERROR: Duplicate blocks found in %s' % sdk_lbr_dir_path)
        sys.exit(1)


if __name__ == '__main__':
    main()

