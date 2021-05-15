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

from leaba import sdk
import lldcli

verbose = False
if verbose:
    sdk.la_set_logging_level(0, sdk.la_logger_component_e_ACCESS, sdk.la_logger_level_e_DEBUG)
    sdk.la_set_logging_level(0, sdk.la_logger_component_e_SBIF, sdk.la_logger_level_e_DEBUG)

ldev = lldcli.ll_device_create(0, '/dev/uio0')
gb = ldev.get_gibraltar_tree()

ldev.reset()
ldev.reset_access_engines()

val = ldev.read_register(gb.sbif.acc_eng_status_reg[7])
print('acc_eng_status = %#x' % val)

reg_i = gb.slice.ifg.mac_pool8.rx_link_status_down
reg_t = gb.slice.ifg.mac_pool8.rx_link_status_down_test

# Test interrupt test bits
ldev.write_register(reg_t, 0x0)             # clear test register
val_before = ldev.read_register(reg_i)      # read current value of interrupt register
ldev.write_register(reg_t, 0xaa)            # write to test register, this triggers interrupts
val_after = ldev.read_register(reg_i)       # read the new value of interrupt register
ldev.write_register(reg_i, 0xff)            # clear the interrupt register
print('mac_pool8.rx_link_status_down = %#x, %#x' % (val_before, val_after))
