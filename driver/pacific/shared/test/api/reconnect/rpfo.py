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

from leaba import sdk


def rpfo(uut_device, topology_objects_to_destroy, la_objects_to_destroy):
    print('---- RPFO start ----')

    dev_id = uut_device.get_id()

    # Stop HW access, stop interrupt handling, pollers and state machines
    uut_device.device.disconnect()

    if uut_device.crit_fd and uut_device.norm_fd:
        uut_device.device.close_notification_fds()

    # Destroy objects, avoid memory leaks
    for obj in topology_objects_to_destroy:
        obj.destroy()
    for obj in la_objects_to_destroy:
        uut_device.device.destroy(obj)

    # Destroy la_device
    sdk.la_destroy_device(uut_device.device)

    print('---- RPFO device destroyed, creating new device ----')

    uut_device.device = sdk.la_create_device(uut_device.device_path, dev_id)
    uut_device.ll_device = uut_device.device.get_ll_device()
    uut_device.crit_fd, uut_device.norm_fd = uut_device.device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)

    # Reconnect
    uut_device.set_bool_property(sdk.la_device_property_e_RECONNECT_IGNORE_IN_FLIGHT, True)
    uut_device.device.reconnect()

    print('---- RPFO done ----')
