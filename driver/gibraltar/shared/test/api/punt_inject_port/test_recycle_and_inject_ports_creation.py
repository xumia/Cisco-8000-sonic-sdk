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


from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
from sdk_test_case_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_recycle_and_inject_ports_creation(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1, slice_modes=sim_utils.STANDALONE_DEV, device_config_func=None)
        self.topology = T.topology(self, self.device, create_default_topology=False)
        self.inject_ports = []

    def tearDown(self):
        self.topology.reset(self.device, keep_inject_ports=False)
        self.topology = None
        self.device.clear_device()
        self.device.tearDown()
        self.device = None

    @unittest.skipIf(decor.is_pacific(), "This test is not for pacific.")
    def test_rcycle_and_punt_port_creation_all_slices(self):
        # This is for ASICs other than Pacific
        # Test to see we can create rcycle ports on each and every slice
        # Test to see we can create the punt inject port when we have an rcy port on both slices
        # in the pair, and the punt inject chooses it's own slice

        self._create_rcy_ports_helper(self._get_used_slices())

        pci_ports = self.device.get_objects(sdk.la_object.object_type_e_PCI_PORT)
        self.assertTrue(not any(pci_ports))
        self.inject_ports = []
        for slice in self._get_used_slices():
            pi_port = self._create_punt_inject_ports_helper(slice)
            self.assertIsNotNone(pi_port)

    @unittest.skipIf(decor.is_pacific(), "This test is not for pacific.")
    def test_punt_port_creation_even_slices_1(self):

        # Test to see we can create the punt inject port when we have an rcy port on even slices.

        recycle_port_slices = self._create_rcy_ports_helper([0, 2, 4])

        pci_ports = self.device.get_objects(sdk.la_object.object_type_e_PCI_PORT)
        self.assertTrue(not any(pci_ports))
        self.inject_ports = []
        for slice_pair in self._get_used_slice_pairs():
            slice = slice_pair * 2 + 1
            if slice - 1 not in recycle_port_slices:
                continue
            if slice in self._get_used_slices():
                # try to create port on the slice
                pi_port = self._create_punt_inject_ports_helper(slice)
                self.assertIsNotNone(pi_port)

    @unittest.skipIf(decor.is_pacific(), "This test is not for pacific.")
    def test_punt_port_creation_even_slices_1(self):
        # This is for ASICs other than Pacific
        # Test to see we can create the punt inject port when we have an rcy port on even slices.

        recycle_port_slices = self._create_rcy_ports_helper([0, 2, 4])

        pci_ports = self.device.get_objects(sdk.la_object.object_type_e_PCI_PORT)
        self.assertTrue(not any(pci_ports))
        self.inject_ports = []
        for slice_pair in self._get_used_slice_pairs():
            slice = slice_pair * 2
            if slice not in recycle_port_slices:
                continue
            if slice in self._get_used_slices():
                # try to create port on the slice
                pi_port = self._create_punt_inject_ports_helper(slice)
                self.assertIsNotNone(pi_port)

    def test_punt_port_creation_odd_slices_1(self):
        # This is for all the ASICs -- including Pacific
        # Test to see we can create the punt inject port when we have an rcy port on odd slices.

        recycle_port_slices = self._create_rcy_ports_helper([1, 3, 5])

        pci_ports = self.device.get_objects(sdk.la_object.object_type_e_PCI_PORT)
        self.assertTrue(not any(pci_ports))
        self.inject_ports = []
        for slice_pair in self._get_used_slice_pairs():
            slice = slice_pair * 2
            if slice + 1 not in recycle_port_slices:
                continue
            if slice in self._get_used_slices():
                # try to create port on the slice
                pi_port = self._create_punt_inject_ports_helper(slice)
                self.assertIsNotNone(pi_port)

    @unittest.skipIf(decor.is_pacific(), "This test is not for pacific.")
    @unittest.skipIf(decor.is_asic5(), "This test is not applicable to AR.")
    def test_punt_port_creation_odd_slices_2(self):
        # This is for ASICs other than Pacific
        # Test to see we can create the punt inject port when we have an rcy port on odd slices.

        recycle_port_slices = self._create_rcy_ports_helper([1, 3, 5])

        pci_ports = self.device.get_objects(sdk.la_object.object_type_e_PCI_PORT)
        self.assertTrue(not any(pci_ports))
        self.inject_ports = []
        for slice_pair in self._get_used_slice_pairs():
            slice = slice_pair * 2 + 1
            if slice not in recycle_port_slices:
                continue
            if slice in self._get_used_slices():
                # try to create port on the slice
                pi_port = self._create_punt_inject_ports_helper(slice)
                self.assertIsNotNone(pi_port)

    def test_punt_inject_port_without_recycle_port(self):
        # Test that if there is no recycle prot,
        #   For pacific and gibraltar, a punt inject cannot be created
        #   For AKPG, a punt inject port can be created.
        rcy_ports = self.device.get_objects(sdk.la_object.object_type_e_RECYCLE_PORT)
        self.assertTrue(not any(rcy_ports))

        for slice in self._get_used_slices():
            err_msg = "When trying to create a punt inject port without a recycle port on the slice pair, expected a NotFoundException."
            expected_exception = sdk.NotFoundException
            with self.assertRaises(expected_exception, msg=err_msg) as context:
                pi_port = self._create_punt_inject_ports_helper(slice)

    # helper functions
    def _create_punt_inject_ports_helper(self, slice):
        print("_create_punt_inject_ports_helper: ", slice, T.PI_IFG)
        pi_port = T.punt_inject_pci_port(
            self,
            self.device,
            slice,
            T.PI_IFG,
            T.INJECT_PORT_BASE_GID + slice,
            T.INJECT_PORT_MAC_ADDR)
        self.inject_ports.append(pi_port)
        return pi_port

    def _create_rcy_ports_helper(self, choosen_slices):
        rcy_ports = self.device.get_objects(sdk.la_object.object_type_e_RECYCLE_PORT)
        self.assertTrue(not any(rcy_ports))
        self.recycle_ports = []
        recycle_port_slices = []
        for slice in self._get_used_slices():
            # RCY ports can be configured on all slices
            rcy_port = None
            if slice in choosen_slices:
                rcy_port = T.recycle_sys_port(self, self.device, slice, T.PI_IFG, T.RCY_SYS_PORT_GID_BASE - slice)
                recycle_port_slices.append(slice)
            self.recycle_ports.append(rcy_port)
        return recycle_port_slices

    def _get_used_slices(self):
        return self.device.get_used_slices()
        # return range(NUM_SLICES_PER_DEVICE)

    def _get_used_slice_pairs(self):
        return self.device.get_used_slice_pairs()
        # return range(NUM_SLICE_PAIRS_PER_DEVICE)


if __name__ == '__main__':
    unittest.main()
