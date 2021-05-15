#!/common/pkgs/python/3.6.10/bin/python3.6
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
import argparse
import sys
import gzip
import lpm_test_utils

# Global_list
no_recognize_format = []


def get_new_line(instruction):
    key_value, total_width = instruction.get_key_and_width()
    payload = instruction.payload
    new_line = "lpm_insert {} {} {} {}".format(hex(key_value)[2:], total_width, hex(payload)[2:], instruction.latency_sensitive)
    return new_line


def get_max_instruction_format(candidate_instructions, file_format_option):
    max_number_of_instructions = 0
    instructions = None
    format = None
    for i in range(len(candidate_instructions)):
        current_number_of_instructions = len(candidate_instructions[i])
        if current_number_of_instructions > max_number_of_instructions:
            max_number_of_instructions = current_number_of_instructions
            format = file_format_option[i]
            instructions = candidate_instructions[i]

    return (instructions, format)


def convert_file(filepath):
    file_format_option = ['CEF', 'CODES', 'XR_OVER_JUPYTER', 'OLD_FORMAT', 'IP_TABLE', 'BGP_TABLE', 'LPM_LOG']
    print('Starting convertion of file: {}'.format(filepath))
    dirpath, filename = os.path.split(filepath)
    name, ext = os.path.splitext(filepath)
    candidate_instructions = []
    for current_file_format in file_format_option:
        try:
            current_instructions = lpm_test_utils.parse_lpm_input(
                filepath, current_file_format, max_entries=-1, filter_full_addresses=False)
        except AttributeError:
            print("Failed to parse with %s, skipping into next format..." % current_file_format)
            current_instructions = []

        candidate_instructions.append(current_instructions)

    instructions, file_format = get_max_instruction_format(candidate_instructions, file_format_option)
    if not instructions:
        no_recognize_format.append(filepath)
        return

    print("the format is: " + file_format)
    instructions = lpm_test_utils.add_unique_payloads_to_lpm_instructions(instructions)
    new_dirpath = '/'.join(dirpath.split('/')[:-1]) + "/"
    filename = filename.split('.')
    if len(filename) >= 2 and filename[-2] == 'txt':
        filename = '.'.join(filename[:-2]) + ".txt.gz"
    else:
        filename = '.'.join(filename[:-1]) + ".txt.gz"
    new_filename = "{}lpm_data.{}".format(new_dirpath if ext in ['.txt', '.gz'] else filename, filename).replace(' ', '_')
    with gzip.open(new_filename, 'w') as fout:
        for instruction in instructions:
            new_line = get_new_line(instruction)
            fout.write(str.encode(new_line) + b"\n")


def main():
    parser = argparse.ArgumentParser(description='Convert raw customer tables input into lpm_data format.')
    parser.add_argument('--directory-mode', action='store_true')
    parser.add_argument('path', type=str)
    args = parser.parse_args()

    # Single file mode used.
    if not args.directory_mode:
        filepath = args.path
        print('Single file mode used with file %s' % filepath)
        convert_file(filepath)
        return

    # Directory mode used.
    directory = args.path
    print('directory mode used with directory %s' % directory)
    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            convert_file(filepath)

    if (no_recognize_format != []):
        print("Files that have not been converted: ")
        for name in no_recognize_format:
            print(name)

    else:
        print("All the files have been converted")
        print("Done")


if __name__ == '__main__':
    main()
