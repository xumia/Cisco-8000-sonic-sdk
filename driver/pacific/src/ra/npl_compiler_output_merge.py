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

import sys
import json
import argparse
import logging
import glob
import os


def read_json_file(file_name):
    fd = open(file_name, 'r')
    tables = json.load(fd)
    fd.close()
    return tables


def read_tables(npl_tables, database_resources_map, ret):
    internal_cnt = 0
    external_cnt = 0
    for table in npl_tables:
        # Read internal table
        if npl_tables[table]['location'] == "internal":
            ret[table] = npl_tables[table]
            internal_cnt += 1
        else:
            # Read external table
            db = npl_tables[table]["database"]
            if db not in database_resources_map:
                logging.info(
                    "Database %s does not exist in databases Json file. Ignoring table %s. Please update 'database_resources_map.json'." %
                    (db, table))
                continue

            table_data = get_external_tables_data(npl_tables[table], database_resources_map[db])
            ret[table] = table_data
            external_cnt += 1

    # Manually add application_specific_fields_width for mac_forwarding_table
    ret['mac_forwarding_table']['application_specific_fields_width'] = 12

    return internal_cnt, external_cnt


def ext_table_has_placements(db):
    return "placements" in db


# Updating external tables data from generated npl file
def get_external_tables_data(npl_table, db):
    table_fields = {}
    table_has_placements = ext_table_has_placements(db)

    # Field for update
    # Update fields from NPL compiled file
    for field in [
        'accessed_from_contexts',
        'translated_key_width',
        'translated_payload_width',
        'match_type',
        'database',
        'location',
        'logical_table_id_value',
        'logical_table_id_width',
            'key_consts_per_opt']:
        table_fields[field] = npl_table[field]
    if 'via_interfaces' in npl_table:
        table_fields['via_interfaces'] = npl_table['via_interfaces']

    # Update fields from database file
    table_fields['allocation'] = db['allocation']
    table_fields['translation_type'] = db['translation_type']
    if table_has_placements:
        table_fields['placements'] = db['placements']

    return table_fields


def read_microcode_file(microcode_mode, file_name):
    logging.info("Reading microcode from %s" % (file_name))
    fd = open(file_name, 'r')
    ret = json.load(fd)
    fd.close()

    entry_count = 0

    for version in ret:
        for block in ret[version]:
            for resource in ret[version][block]:
                if 'comments' in resource.keys():
                    del(resource['comments'])

                if 'entries' in resource.keys():
                    for entry in resource['entries']:
                        entry_count += 1
                        if 'comments' in entry.keys():
                            del(entry['comments'])
                else:
                    entry_count += 1

    logging.info("Done microcode for mode %s. Read %d entries." % (microcode_mode, entry_count))

    return ret


# 1. Parse arguments
parser = argparse.ArgumentParser(
    description="Merges NPL compiler metadata files into single file.",
    add_help=True)
req_group = parser.add_argument_group(title='required arguments')
req_group.add_argument('-i', '--nplapi-tables', required=True, help='input JSON file, containing npl tables definitions.')
req_group.add_argument('-d', '--databases', required=True, help='input JSON file, containing databases information.')
req_group.add_argument('-m', '--microcode-dir', required=True, help='director, containing microcode files in JSON format.')
req_group.add_argument('-o', '--output', required=True, help='output file')

parsed_args = parser.parse_args()
logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='-I- %(message)s')

# 2. Read and parse tables. Then, merge all tables data into a single data structure
tables = {}

nplapi_tables = read_json_file(parsed_args.nplapi_tables)
database_resources_map = read_json_file(parsed_args.databases)

int_table_count, ext_table_count = read_tables(nplapi_tables, database_resources_map, tables)

logging.info("Done reading tables. Internal %d. External %d" % (int_table_count, ext_table_count))

# 3. Read and merge microcode data into a single data structure
microcode = {}

microcode_file_suffix = "_microcode.json"
for microcode_file in glob.glob(parsed_args.microcode_dir + "/*" + microcode_file_suffix):
    microcode_file_basename = os.path.basename(microcode_file)
    microcode_context = microcode_file_basename[:- len(microcode_file_suffix)]
    microcode_context_data = read_microcode_file(microcode_context, microcode_file)

    microcode[microcode_context] = microcode_context_data

# 4. Create merged output dictionary
result = {'tables': tables,
          'microcode': microcode}

# 5. Dump to output file
logging.info("Writing output file %s" % parsed_args.output)

outfd = open(parsed_args.output, 'w')
json.dump(result, outfd, indent=4)
outfd.close()
