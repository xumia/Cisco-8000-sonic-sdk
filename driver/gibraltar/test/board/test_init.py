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

import lldcli
from leaba import sdk
from leaba import debug

devid = 0
sdk.la_set_logging_level(devid, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)

dev = sdk.la_create_device('/dev/uio0', devid)
ldev = dev.get_ll_device()
gb = ldev.get_gibraltar_tree()
dd = debug.debug_device(dev)

dev.set_bool_property(sdk.la_device_property_e_IGNORE_MBIST_ERRORS, True)
dev.initialize(dev.init_phase_e_DEVICE)
for i in range(6):
    dev.set_slice_mode(i, sdk.la_slice_mode_e_NETWORK)
dev.initialize(dev.init_phase_e_TOPOLOGY)
