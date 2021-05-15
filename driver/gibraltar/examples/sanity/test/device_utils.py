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

###
# Device related utilities and constants
###

from binascii import hexlify

from leaba import sdk
try:
    import test_nsim_providercli as nsim
except BaseException:
    import test_packet_provider as nsim
import rtl_test_utils
import sim_utils

STANDALONE_DEV = [sdk.la_slice_mode_e_NETWORK] * 6
LINECARD_4N_2F_DEV = [sdk.la_slice_mode_e_NETWORK] * 4 + [sdk.la_slice_mode_e_CARRIER_FABRIC] * 2
LINECARD_3N_3F_DEV = [sdk.la_slice_mode_e_NETWORK] * 3 + [sdk.la_slice_mode_e_CARRIER_FABRIC] * 3
FABRIC_ELEMENT_DEV = [sdk.la_slice_mode_e_CARRIER_FABRIC] * 6

DEVICE_TYPE_NSIM = 1
DEVICE_TYPE_HW = 2


def initialize_device(la_dev, slice_modes):
    status = la_dev.initialize(sdk.la_device.init_phase_e_DEVICE)

    if status != sdk.LA_STATUS_SUCCESS:
        print('la_dev.initialize failed. status=%d' % status)
        return status

    # Configure slice modes
    for sid in range(len(slice_modes)):
        status = la_dev.set_slice_mode(sid, slice_modes[sid])
        if status != sdk.LA_STATUS_SUCCESS:
            print('la_dev.set_slice_mode failed. status=%d' % status)
            return status

    status = la_dev.initialize(sdk.la_device.init_phase_e_TOPOLOGY)

    return status


def destroy_device(la_dev):
    # Ensure la_dev interaction with hardware/simulator is done before exiting
    la_dev.flush()

    # Wrap-up
    status = sdk.la_destroy_device(la_dev)

    return status


class hw_device:
    def __init__(self, device_id):
        device_path = '/dev/uio0'
        (status, self.la_dev) = sdk.la_create_device(device_path, device_id)
        if status != sdk.LA_STATUS_SUCCESS:
            raise Exception('la_create_device failed status=%d' % status)

        status = initialize_device(self.la_dev, STANDALONE_DEV)
        if status != sdk.LA_STATUS_SUCCESS:
            raise Exception('la_create_device failed status=%d' % status)

    def teardown(self):
        status = destroy_device(self.la_dev)
        self.la_dev = None
        if status != sdk.LA_STATUS_SUCCESS:
            raise Exception('la_destroy_device failed status=%d' % status)


class hw_device_with_npu_host:

    def __init__(self, device_id):
        device_path = '/dev/uio0'
        (status, self.la_dev, self.sim) = hw_device_with_npu_host.create_test_device(device_path, device_id)
        assert(status == sdk.LA_STATUS_SUCCESS)

    @staticmethod
    def create_test_device(device_path, dev_id, initialize=True, slice_modes=STANDALONE_DEV):

        (status, la_dev) = sdk.la_create_device(device_path, dev_id)
        if status != sdk.LA_STATUS_SUCCESS:
            return (status, None, None)

        # Initialize device
        if initialize:
            status = initialize_device(la_dev, slice_modes)
            if status != sdk.LA_STATUS_SUCCESS:
                return (status, None, None)

        sim_provider = rtl_test_utils.ra_npuh_sim_provider(la_dev, True)

        return (status, la_dev, sim_provider)

    def teardown(self):
        status = destroy_device(self.la_dev)
        assert(status == sdk.LA_STATUS_SUCCESS)

    def inject(self, packet, entry_slice, entry_ifg, entry_pif, num_of_replications):
        assert num_of_replications >= 0 and num_of_replications < 256, 'Illegal num_of_replications'
        ipacket = nsim.sim_packet_info_desc()
        ipacket.packet = hexlify(bytes(packet)).decode('ascii')
        ipacket.slice = entry_slice
        ipacket.ifg = entry_ifg
        ipacket.pif = entry_pif
        is_success = self.sim.inject_packet(ipacket, num_of_replications)
        assert is_success

    def run(self):
        is_success = self.sim.step_packet()
        assert is_success

    def get_output_packet(self):
        egress_packet = self.sim.get_packet()
        return (egress_packet.packet, egress_packet.slice, egress_packet.ifg, egress_packet.pif)


class nsim_device:

    def __init__(self, device_id):
        device_path = '/dev/testdev'
        (status, self.la_dev, self.nsim) = nsim_device.create_test_device(device_path, device_id)
        assert(status == sdk.LA_STATUS_SUCCESS)

    @staticmethod
    def create_test_device(device_path, dev_id, initialize=True, slice_modes=STANDALONE_DEV):
        nsim.nsim.set_nsim_flow_debug(False)
        nsim_provider = nsim.nsim.create_and_run_simulator_server(None, 0, device_path)
        new_path = nsim_provider.get_connection_handle()
        (status, la_dev) = sdk.la_create_device(new_path, dev_id)
        if status != sdk.LA_STATUS_SUCCESS:
            return (status, None, None)

        nsim_provider.set_logging(True)

        # Initialize device
        if initialize:
            status = initialize_device(la_dev, slice_modes)
            if status != sdk.LA_STATUS_SUCCESS:
                return (status, None, None)

        return (status, la_dev, nsim_provider)

    def teardown(self):
        status = destroy_device(self.la_dev)
        assert(status == sdk.LA_STATUS_SUCCESS)

    def inject(self, packet, entry_slice, entry_ifg, entry_pif, num_of_replications):
        assert (num_of_replications == 1), 'Error: nsim_device num_of_replications>1 not supported'
        ipacket = nsim.sim_packet_info_desc()
        ipacket.packet = hexlify(bytes(packet)).decode('ascii')
        ipacket.slice = entry_slice
        ipacket.ifg = entry_ifg
        ipacket.pif = entry_pif
        is_success = self.nsim.inject_packet(ipacket)
        assert is_success

    def run(self):
        is_success = self.nsim.step_packet()
        assert is_success

    def get_output_packet(self):
        egress_packet = self.nsim.get_packet()
        return (egress_packet.packet, egress_packet.slice, egress_packet.ifg, egress_packet.pif)
