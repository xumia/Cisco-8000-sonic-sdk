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

from leaba import sdk
dev_id = 200
dev = sdk.la_create_device('/dev/uio0', dev_id)
sdk.la_set_logging_level(288, sdk.la_logger_component_e_RA, sdk.la_logger_level_e_DEBUG)
sdk.la_set_logging_level(288, sdk.la_logger_component_e_API, sdk.la_logger_level_e_DEBUG)
sdk.la_set_logging_level(dev_id, sdk.la_logger_component_e_API, sdk.la_logger_level_e_DEBUG)
rc = dev.reconnect()

mac_ports = dev.get_objects(sdk.la_object.object_type_e_MAC_PORT)
fabric_ports = dev.get_objects(sdk.la_object.object_type_e_FABRIC_PORT)
