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

# How to run:

# setenv SDK_VER /cad/leaba/sdk/eng/current
# setenv DRIVER $SDK_VER/driver
# setenv NPL $SDK_VER/npl/pacific
# setenv NPLAPI_METADATA_FILE $DRIVER/build/src/ra/npl_tables.json
# setenv NSIM_SOURCE_PATH $SDK_VER/npl/cisco_router
# setenv NSIM_LEABA_DEFINED_FOLDER=$NPL/leaba_defined
# setenv LD_LIBRARY_PATH $DRIVER/lib
# setenv PYTHONPATH $DRIVER/lib:$DRIVER/test/hld
#
# /common/pkgs/python/3.6.10/bin/python3.6 ./example_rtl_access.py --port_rw 45454 --port_int 54545

import argparse
import sys
import lldcli
import sim_utils
from leaba import sdk as sdk

# Command line options --port_rw <port number> --port_int <port number>
parser = argparse.ArgumentParser()
parser.add_argument("--port_rw", type=int, default=7474, help="TCP port for read/write")
parser.add_argument("--port_int", type=int, default=7575, help="TCP port for interrupt")
args = parser.parse_args()

port_rw = args.port_rw
port_int = args.port_int
device_name = '/dev/testdev/rtl/socket:localhost:%d,%d' % (port_rw, port_int)
device_id = 1

# turn on LLD:DEBUG prints for device_id==1 and for 'unknown device'
for dev_id in [device_id, 288]:
    lld_components = [
        sdk.la_logger_component_e_LLD,
        sdk.la_logger_component_e_ACCESS,
        sdk.la_logger_component_e_SBIF]
    for component in lld_components:
        sdk.la_set_logging_level(dev_id, component, sdk.la_logger_level_e_ERROR)

# Connect to RTL
# --------------------
(rc, device) = sim_utils.create_rtl_device(device_name, 1, simulation_mode=lldcli.ll_device.simulation_mode_e_SBIF)

if (rc):
    print("ERROR: create_rtl_device", rc)
    sys.exit(rc)

ll_device = device.get_ll_device()
pacific_tree = ll_device.get_pacific_tree()

# w/r SBIF register
# --------------------
reg = pacific_tree.sbif.misc_output_reg
val_w = 0x2d

rc1 = ll_device.write_register(reg, val_w)
(rc2, val_r) = ll_device.read_register(reg)

err = "OK" if (val_r != val_w) else "ERROR"
print("%s: r/w register, %s %x" % (err, reg.get_desc().name, reg.get_desc().addr))

# w/r non-SBIF register
# --------------------
reg = pacific_tree.slice[0].ifg[0].sch.ecc_1b_err_interrupt_register_mask
val_w = 0x12345678

rc1 = ll_device.write_register(reg, val_w)
(rc2, val_r) = ll_device.read_register(reg)

err = "OK" if (val_r != val_w) else "ERROR"
print("%s: r/w register, %s %x" % (err, reg.get_desc().name, reg.get_desc().addr))

# w/r memory
# --------------------
mem = pacific_tree.slice[0].ifg[1].ifgb.tc_lut_mem[7]
line = 9
val_w = 0x29

rc1 = ll_device.write_memory(mem, line, val_w)
(rc2, val_r) = ll_device.read_memory(mem, line)

err = "OK" if (val_r != val_w) else "ERROR"
print("%s: r/w memory, %s %x" % (err, mem.get_desc().name, mem.get_desc().addr))

# w/r X-Y TCAM
# --------------------
tcam = pacific_tree.npuh.fi.fi_core_tcam
tcam_line = 2
key_w = 0x0800
mask_w = 0x1800

rc = ll_device.write_tcam(tcam, tcam_line, key_w, mask_w)
(rc, key_r, mask_r, valid_r) = ll_device.read_tcam(tcam, tcam_line)

err = "OK" if (key_r != key_w) else "ERROR"
print(err, ': write', key_w, mask_w, ', read', key_r, mask_r)

# w/r REG TCAM
# --------------------
tcam = pacific_tree.slice[0].npu.txpp.txpp.npe_mid_res_tcam

rc = ll_device.write_tcam(tcam, tcam_line, key_w, mask_w)
(rc, key_r, mask_r, valid_r) = ll_device.read_tcam(tcam, tcam_line)

err = "OK" if (key_r != key_w) else "ERROR"
print(err, ': write', key_w, mask_w, ', read', key_r, mask_r)

# Disconnect from RTL, the RTL will go down
# --------------------
device.tearDown()
