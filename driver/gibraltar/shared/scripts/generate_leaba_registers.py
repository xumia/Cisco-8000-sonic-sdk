#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

# Example useage:
# step 1:  cd driver/asic4
# step 2:  setenv PYTHONPATH out/noopt-debug/pylib
# step 3:  /auto/asic-tools/sw/python/3.6.0/bin/python3
#          ../shared/scripts/generate_leaba_registers.py --asic ASIC4
#          --outfile ../shared/src/kernel/asic4_leaba_registers.h

import os
import re
import sys
import lldcli
import argparse


LEGAL_NOTE = \
    '// BEGIN_' + '''LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
//
// This file and all technical concepts, proprietary knowledge, algorithms and
// intellectual property rights it contains (collectively the "Confidential Information"),
// are the sole propriety information of Cisco and shall remain at Cisco's ownership.
// You shall not disclose the Confidential Information to any third party and you
// shall use it solely in connection with operating and/or maintaining of Cisco's
// products and pursuant to the terms and conditions of the license agreement you
// entered into with Cisco.
//
// THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
// IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// END_''' + '''LEGAL

'''


def define_compile_once(header_filename):
    header_filename = os.path.basename(header_filename)
    return '__' + header_filename.upper().replace('.', '_') + '__'


def define_reg_mem(reg_mem, asic):
    desc = reg_mem.get_desc()
    if desc.instances == 1:
        text = '#define {}_{} {}\n'.format(asic, desc.name, hex(desc.addr))
    else:
        # convert sbif.acc_eng_go_reg[7] to LLD_REGISTER_SBIF_ACC_ENG_GO_REG_7
        i = re.search(r'\[(\d+)\]$', reg_mem.get_name()).group(1)
        text = '#define {}_{}_{} {}\n'.format(asic, desc.name, i, hex(desc.addr))

    return text


def main(args):
    # SBIF LBR is identical between REV_1 and REV2
    if args.asic == 'PACIFIC':
        device_tree = lldcli.pacific_tree.create(lldcli.la_device_revision_e_PACIFIC_A0)
    elif args.asic == 'GIBRALTAR':
        device_tree = lldcli.gibraltar_tree.create(lldcli.la_device_revision_e_GIBRALTAR_A0)
    elif args.asic == 'ASIC4':
        device_tree = lldcli.asic4_tree.create(lldcli.la_device_revision_e_ASIC4_A0)
    elif args.asic == 'ASIC3':
        device_tree = lldcli.asic3_tree.create(lldcli.la_device_revision_e_ASIC3_A0)
    elif args.asic == 'ASIC5':
        device_tree = lldcli.asic5_tree.create(lldcli.la_device_revision_e_ASIC5_A0)
    else:
        print('Unknown asic={}'.format(args.asic))
        return 1

    text = LEGAL_NOTE
    text += '#ifndef {}\n'.format(define_compile_once(args.outfile))
    text += '#define {}\n\n'.format(define_compile_once(args.outfile))
    for mem in device_tree.sbif.get_memories():
        text += define_reg_mem(mem, args.asic)
    text += '\n'
    for reg in device_tree.sbif.get_registers():
        text += define_reg_mem(reg, args.asic)
    text += '\n'
    text += '#endif // {}\n'.format(define_compile_once(args.outfile))

    with open(args.outfile, 'w') as f:
        f.write(text)

    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='''
  Create a C header file with the SBIF register addresses
  for use by the leaba kernel module.''')
    parser.add_argument('--outfile', required=True, help='Output file name')
    parser.add_argument('--asic', required=True, help='Device code name')
    args = parser.parse_args()
    sys.exit(main(args))
