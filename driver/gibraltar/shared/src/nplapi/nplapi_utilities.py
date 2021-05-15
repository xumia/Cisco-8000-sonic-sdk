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

import os.path
import re
import logging
import sys
import json
import textwrap
import csv
import datetime

#######################################################
# CLASS: file_utils
# @brief Utilities manage input/output files for nplapi python scripts
#######################################################


class file_utils:

    def open_input_file(file_name):
        try:
            opened_file = open(file_name, 'r')
        except BaseException:
            exception_message = "Could not open input file %s." % file_name
            raise Exception(exception_message)

        return opened_file

    def open_output_header_file(dir_name, base_file_name):
        header_macro_template = '''#ifndef __%(macro)s__\n#define __%(macro)s__\n'''

        opened_file = file_utils.open_output_file(dir_name, base_file_name)

        params = {'macro': base_file_name.replace('.', '_').upper()}
        print(header_macro_template % params, file=opened_file)

        return opened_file

    def open_output_file(dir_name, base_file_name):
        autogen_notice_template = '// This file has been automatically generated in nplapi package. Do not edit it manually.\n'
        autogen_notice_template += '// Generated by %s at %s\n' % (
            os.path.basename(__file__), datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        file_name = '%s/%s' % (dir_name, base_file_name)

        try:
            opened_file = open(file_name, 'w')
        except BaseException:
            exception_message = "Could not open output file %s." % file_name
            raise Exception(exception_message)

        print(autogen_notice_template, file=opened_file)

        return opened_file

    def close_output_header_file(opened_file):
        print("#endif", file=opened_file)
        opened_file.close()

    def reindent_file(filename):
        lines = open(filename, 'r').readlines()
        special_lines = ['public:', 'private:', 'protected:', 'namespace']
        indented_lines = []

        indentation = 0
        for line in lines:
            line = textwrap.dedent(line)

            line_indentation = indentation
            if line.startswith('}'):
                line_indentation -= 1

            special_line = [keyword for keyword in special_lines if line.startswith(keyword)]
            if special_line != []:
                line_indentation -= 1
                indentation -= 1

            line = '    ' * line_indentation + line
            indented_lines.append(line)

            indentation += line.count('{') - line.count('}')

        open(filename, 'w').writelines(indented_lines)

    def generate_header_file(dir_name, base_file_name, lines):
        logging.info("Generating file %s/%s" % (dir_name, base_file_name))

        opened_file = file_utils.open_output_header_file(dir_name, base_file_name)

        for line in lines:
            print(line, file=opened_file)

        file_utils.close_output_header_file(opened_file)
        file_utils.reindent_file("%s/%s" % (dir_name, base_file_name))

    def generate_source_file(dir_name, base_file_name, lines):
        logging.info("Generating file %s/%s" % (dir_name, base_file_name))

        opened_file = file_utils.open_output_file(dir_name, base_file_name)

        for line in lines:
            print(line, file=opened_file)

        opened_file.close()
        file_utils.reindent_file("%s/%s" % (dir_name, base_file_name))


#######################################################
# CLASS: npl_names
# @brief Utilities to translate to enum/class names
#######################################################


class npl_names:

    def table_type_enum(match_type):
        return 'TABLE_TYPE_%s' % match_type.upper()

    def table_trait(table):
        return 'npl_%s_functional_traits_t' % table

#######################################################
# CLASS: nplapi_table_json_reader
# @brief Read NPL metadata file and makes sure the format is as expected.
#######################################################


class nplapi_table_json_reader:

    def __init__(self, metadata_file_name):
        self.metadata_file_name = metadata_file_name

        # sorted list of tables
        self.table_list = []

        # table tree divided by location and type
        self.locations = ['internal', 'external']
        self.match_types = ['direct', 'em', 'ternary', 'lpm']
        self.table_collection = {}
        for loc in self.locations:
            self.table_collection[loc] = {}
            for type in self.match_types:
                self.table_collection[loc][type] = {}

        # JSON data
        self.metadata = {}

    def _create_table_list(self):
        logging.info("Creating table list...")

        table_count = 0
        for loc in self.locations:
            loc_count = 0
            for type in self.match_types:
                type_count = 0
                for table in sorted(self.table_collection[loc][type].keys()):
                    self.table_list.append(self.table_collection[loc][type][table])
                    loc_count = loc_count + 1
                    type_count = type_count + 1
                    table_count = table_count + 1
                logging.info("Found %d tables of type %s/%s." % (type_count, loc, type))
            logging.info("Found %d tables of location %s." % (loc_count, loc))

        logging.info("Found %d table definitions." % table_count)

    def _parse_metadata_file(self):
        logging.info("Parsing metadata file %s" % self.metadata_file_name)
        metadata_file = file_utils.open_input_file(self.metadata_file_name)

        metadata = metadata_file.read()
        # in order to load as json, each backslash should be escaped (by another backslash)
        metadata = re.sub(r'\\', r'\\\\', metadata)

        try:
            self.metadata = json.loads(metadata)
        except BaseException:
            exception_message = "Could not parse JSON file %s." % self.metadata_file_name
            raise Exception(exception_message)

        for table in self.metadata:
            logging.debug("Found table %s." % table)

            table_data = self.metadata[table]
            table_data['name'] = table

            location = table_data['location']
            type = table_data['match_type']

            # type / functional table
            if (type == 'direct' or type == 'em'):
                table_data['functional_table'] = 'npl_table'
            elif (type == 'ternary'):
                table_data['functional_table'] = 'npl_ternary_table'
            else:
                table_data['functional_table'] = 'npl_lpm_table'

            table_data['block'] = ''
            if 'database' not in table_data.keys():
                table_data['database'] = 'internal_npe'
                table_data['block'] = 'NPE'

            table_data['context'] = ':'.join(table_data['placements'].keys()) if table_data['placements'] else 'device'

            # enums
            table_data['table_enum'] = table_data['table_id']

            self.table_collection[location][type][table] = table_data

        logging.info("Done parsing metadata file %s. Found %s tables." % (self.metadata_file_name, len(self.metadata)))

    # interface
    def read(self):
        self._parse_metadata_file()
        self._create_table_list()

        return self.table_list

    def dump_csv(self, filename, keys):
        ofile = open(filename, 'w')
        writer = csv.writer(ofile, delimiter=',', quotechar='"', quoting=csv.QUOTE_NONE)

        writer.writerow(keys)
        for table in self.table_list:
            values = [table[key] for key in keys]
            writer.writerow(values)

        ofile.close()
