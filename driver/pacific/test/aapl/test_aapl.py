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

import lldcli
import aaplcli

# @brief Print all registers of the SBIF block


def upload_fw(dev_ctx, sbm_id, sbus_dev, file_path):
    # Initialize connection to the SBus Master ID
    sb = aaplcli.la_aapl_init(dev_ctx, sbm_id)

    # Upload FW from the specified file_path without running memory BIST
    aaplcli.avago_spico_upload_file(sb, sbus_dev, 0, file_path)


#######################################################
# Tests
#######################################################
# @brief Upload firmware on specific SerDes in the device
def test_fw_upload(dev_ctx):
        # Upload FW from the specified file_path to SERDES_POOL, SerDes 2
    upload_fw(dev_ctx, lldcli.LA_BLOCK_ID_SERDES_POOL_SBUS, 2, "test/aapl/serdes.0x105B_2000.rom")
