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

# Generate C++ code for configuration of the resolution macro decoding tables

import sys
import re

STATE_LOOK_FOR_FUNCTION = 0
STATE_INSIDE_FUNCTION = 1

function_pattern = re.compile('^function void configure_([a-z0-9_]+)_table')
random_number_assignment_pattern = re.compile(' *(.*) = \$random;')
dec_number_assignment_pattern = re.compile(' *(.*) = [0-9]+\'d([0-9]+);')
bin_number_assignment_pattern = re.compile(' *(.*) = [0-9]+\'b([01]+);')
drop_list = [re.compile('.*key *= *new;'), re.compile('.*value *= *new;')]
modify_list = {'table_key_c': 'table_key_t', 'table_value_c': 'table_value_t', 'key.type_i': 'key.type'}

func_header = '''
la_status
%s(la_device_impl* device)
{
    la_status status = LA_STATUS_SUCCESS;
    npl_%s_table_entry_t* dummy_entry = nullptr;
    std::shared_ptr<npl_%s_table_t> table(device->m_tables.%s_table);

'''

func_footer = '''
    return LA_STATUS_SUCCESS;
}
'''

table_insert = '''
    status = table->insert(key, value, dummy_entry);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }
'''

global_func = '''
la_status
configure_decoding_tables(la_device_impl* device)
{
    la_status status;

%s

    return LA_STATUS_SUCCESS;
}
'''

call_table_func = '''
    status = %s(device);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }
'''

file_header = '''
#include "common/defines.h"

#include "%s"

namespace silicon_one {

'''

file_footer = '''
} // namespace silicon_one
'''


def is_empty_line(line):
    return len(line) == 0


def is_comment_line(line):
    return len(line) > 1 and line[0] == '/' and line[1] == '/'


def parse_sv_file(infile, outfile):

    ifd = open(infile)
    ofd = open(outfile, 'w')

    headername = outfile[outfile.rfind('/') + 1:].replace('.cpp', '.h')
    ofd.write(file_header % headername)

    functions = []

    state = STATE_LOOK_FOR_FUNCTION
    lineno = 0
    for l in ifd:
        lineno += 1
        line = l.strip()

        if is_comment_line(line) or is_empty_line(line):
            ofd.write('%s\n' % line)

        else:

            if state == STATE_LOOK_FOR_FUNCTION:
                m = function_pattern.match(line)
                if m:
                    table_name = m.group(1)
                    func_name = 'configure_%s_table' % table_name
                    functions.append(func_name)

                    ofd.write(func_header % (func_name, table_name, table_name, table_name))

                    state = STATE_INSIDE_FUNCTION

            elif state == STATE_INSIDE_FUNCTION:

                if line.find('_table(key') >= 0:
                    ofd.write(table_insert)

                elif line.find('endfunction') == 0:

                    ofd.write(func_footer)
                    state = STATE_LOOK_FOR_FUNCTION

                else:

                    do_drop = False
                    for d in drop_list:
                        m = d.match(line)
                        if m:
                            do_drop = True
                            break

                    if do_drop:
                        continue

                    for m in modify_list:
                        line = line.replace(m, modify_list[m])

                    fixed_num = False
                    m = dec_number_assignment_pattern.match(line)
                    if m:
                        line = '%s = %s;' % (m.group(1), m.group(2))
                        fixed_num = True

                    if not fixed_num:
                        m = bin_number_assignment_pattern.match(line)
                        if m:
                            num = int(m.group(2), 2)
                            line = '%s = %d;' % (m.group(1), num)
                            fixed_num = True

                    if not fixed_num:
                        m = random_number_assignment_pattern.match(line)
                        if m:
                            line = '%s = 0; // don\'t care' % m.group(1)

                    ofd.write('\t%s\n' % line)

    # The input file is no longer needed
    ifd.close()

    # Add the function that calls all table-specific functions
    call_table_funcs_code = []
    for f in functions:
        call_table_funcs_code.append(call_table_func % f)
    ofd.write(global_func % '\n'.join(call_table_funcs_code))

    ofd.write(file_footer)

    ofd.close()


def main(argv):
    if len(argv) < 3:
        print('Usage: %s <input sv file> <output c++ name>')
        sys.exit(2)

    parse_sv_file(argv[1], argv[2])


if __name__ == '__main__':
    main(sys.argv)
