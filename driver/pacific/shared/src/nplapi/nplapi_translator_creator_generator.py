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
import logging
import sys
import argparse

from nplapi_utilities import file_utils
from nplapi_utilities import nplapi_table_json_reader


#######################################################
# CLASS: nplapi_translator_creator_file_template
# @brief Generates translator_creator header file for given package
#######################################################


class nplapi_translator_creator_file_template:

    def __init__(self, file_name, package, num_slices):
        self.file_name = file_name
        self.package = package
        self.num_slices = num_slices

    prefix = '''
        // nplapi compiled headers
        #define NPLAPI_NUM_SLICES %(num_slices)d
        #include "nplapi/nplapi_tables.h"

        #include "nplapi/translator_creator.h"
        #include "%(package)s_translators_serialize_struct_helpers.h"

        namespace silicon_one {

            namespace %(package)s {

            /// @brief Helper functions to initialize functional tables with translators.
            /// The functions should be implemented in one of the flow creation packages
            ///
            /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
            ///             LA_STATUS_ENOTIMPLEMENTED   Specific type is not supported yet.
            ///
            template <class _Table>
            static la_status init_table(_Table& table, translator_creator& creator, const std::vector<size_t>& indices);

            /// @brief Automatically generated class that implements interface to initialize NPL functional tables with corresponding translators.
            ///
            class translator_creator_impl : public translator_creator {
            public:

            translator_creator_impl(ll_device_sptr lld, const std::vector<npl_context_e>& npl_context_slices): translator_creator(lld, npl_context_slices)
            {
            }

            translator_creator_impl() {} // For serialization purposes only.

            /// @brief Provides separate calls to template a function for each npl_table_type
            /// allowing convenient implementation of each option by template specializations.
            ///
            virtual la_status initialize_table(void* table, npl_tables_e table_type, const std::vector<size_t>& indices)
            {
                la_status ret = LA_STATUS_ENOTIMPLEMENTED;

                switch (table_type) {\
    '''

    file_line = '''
                    // table: %(name)s
                    case %(table_enum)s:
                        ret = init_table(*(static_cast<npl_%(name)s_t*>(table)), *this, indices);
                        return ret;\
    '''

    main_function_suffix = '''
                    default:
                        return LA_STATUS_ENOTIMPLEMENTED;
                }

                return LA_STATUS_ENOTIMPLEMENTED;
            }
            }; // class translator_creator_impl
    '''

    serialize_struct_prefix = '''
            struct translators_serialization_s {

    '''

    serialize_struct_line = '''
                %(translator_type)s<npl_%(name)s_functional_traits_t> npl_%(name)s_%(translator_type)s;
    '''

    suffix = '''
            }; // struct translators_serialization_s
            } // namespace %(package)s

        } // namespace silicon_one
    '''

    def generate_file(self, dir_name, data):

        lines = []

        cls = self.__class__
        global_params = {'package': self.package,
                         'num_slices': self.num_slices}

        lines.append(cls.prefix % global_params)

        for params in data:
            lines.append(cls.file_line % params)

        lines.append(cls.main_function_suffix)

        lines.append(cls.serialize_struct_prefix % global_params)

        # TODO this is a temporary solution, we need to design a better solution
        translator_types = {
            'ra': {
                'direct': ['ra_direct_translator', 'ra_empty_direct_translator'],
                'em': ['ra_em_translator', 'ra_empty_direct_translator'],
                'lpm': ['ra_lpm_translator'],
                'ternary': ['ra_ternary_translator', 'ra_empty_ternary_translator'],
                'trap': ['ra_trap_ternary_translator', 'ra_empty_ternary_translator']
            },
            'simulator': {
                'direct': ['nsim_translator'],
                'em': ['nsim_translator'],
                'lpm': ['nsim_lpm_translator'],
                'ternary': ['nsim_ternary_translator'],
                'trap': ['nsim_ternary_translator']
            }
        }

        for params in data:
            table_type = params['match_type']
            if len(params['reads']) == 2 and params['reads'][0] == 'traps' and params['reads'][1] == 'trap_conditions':
                table_type = 'trap'
            for translator_type in translator_types[self.package][table_type]:
                translator_lines_params = {'name': params['name'], 'translator_type': translator_type}
                lines.append(cls.serialize_struct_line % translator_lines_params)

        lines.append(cls.suffix % global_params)

        file_utils.generate_header_file(dir_name, self.file_name, lines)


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
        description="Generate translator_creator implementation, based on NPL compiler inputs",
        add_help=True)

    req_group = parser.add_argument_group(title='required arguments')
    req_group.add_argument('-d', '--device', required=True, help='input device for which to generate')
    req_group.add_argument('-m', '--metadata_file', required=True, help='input JSON file generated by NPL compiler')
    req_group.add_argument('-p', '--package', required=True, help='package name, where translator_creator will be used')
    req_group.add_argument('-o', '--output_file', required=True, help='output file name')
    parser.add_argument('-v', '--verbose', required=False, action='store_true', help='verbose/debug mode')

    # parse arguments
    parsed_args = parser.parse_args()

    # enable debugging if verbose argument is enable
    if parsed_args.verbose:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG, format='%(funcName)-20s:%(lineno)3s: %(message)s')
    else:
        logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='-I- %(message)s')

    logging.debug("Output file = %s" % parsed_args.output_file)
    logging.debug("Metadata file = %s" % parsed_args.metadata_file)
    return parsed_args


if __name__ == '__main__':
    parsed_args = parse_arguments()

    output_dir = os.path.dirname(parsed_args.output_file)

    os.makedirs(output_dir, exist_ok=True)

    # Parse input file
    table_def_generator = nplapi_table_json_reader(parsed_args.metadata_file)
    table_params = table_def_generator.read()

    # generate translator_creator.h
    num_slices = device_to_slice_count(parsed_args.device)
    file_creator = nplapi_translator_creator_file_template(
        os.path.basename(parsed_args.output_file), parsed_args.package, num_slices)
    file_creator.generate_file(output_dir, table_params)
