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

from copy import deepcopy
import sys
import unittest
from leaba import sdk
from scapy.all import *
import topology as T
import packet_test_utils as U
import sim_utils


class sdk_test_case_base(unittest.TestCase):
    device = None

    @classmethod
    def setUpClass(
            cls,
            *,
            device_id=1,
            slice_modes=sim_utils.STANDALONE_DEV,
            device_config_func=None):
        cls.maxDiff = None  # Show whole strings on failures (unittest variable)
        cls.device = sim_utils.create_device(device_id, slice_modes=slice_modes, device_config_func=device_config_func)

        # MATILDA_SAVE -- need review
        if sdk.la_slice_mode_e_CARRIER_FABRIC in slice_modes:
            # Fabric or linecard mode, but this device can only be used in standalone mode - skip test
            if not T.can_be_used_as_fabric(cls.device):
                raise unittest.SkipTest("This device cannot be used in Line-card mode. Thus, this test is irrelevant.")

        cls._traps_configuration = dict()
        for e in range(sdk.LA_EVENT_APP_LAST + 1):
            try:
                props = cls.device.get_trap_configuration(e)
                cls._traps_configuration[e] = props
            except BaseException:
                pass
        cls._objects_ids_to_keep = []

    @classmethod
    def tearDownClass(cls):
        sdk_test_case_base.tearDownTopology()
        cls.device.tearDown()

    @staticmethod
    def tearDownTopology():
        T.topology.inject_ports = []
        T.topology.recycle_ports = []
        T.topology.voq_allocators = {}
        T.topology.persistent_voq_allocators = {}

    def setUp(self, create_default_topology=True):
        for e, props in self._traps_configuration.items():
            self.device.set_trap_configuration(e, *props)
        self.topology = T.topology(self, self.device, create_default_topology=create_default_topology)
        if create_default_topology and not self.__class__._objects_ids_to_keep:
            self._add_objects_to_keep()

    def tearDown(self, keep_objs=True):
        if (keep_objs):
            self.device.clear_device(objects_to_keep=self.__class__._objects_ids_to_keep)
            self.topology.reset(self.device, keep_inject_ports=True)
        else:
            self.topology.reset(self.device, keep_inject_ports=False)
            self.device.clear_device()
        self.topology = None

    def _add_objects_to_keep(self):
        self._add_topology_inject_ports()
        self._add_topology_recycle_ports()

    def _add_topology_inject_ports(self):
        for pi_port in self.topology.inject_ports:
            if pi_port is None:
                continue
            self.__class__._objects_ids_to_keep.append(pi_port.hld_obj.oid())
            self.__class__._objects_ids_to_keep.append(pi_port.sys_port.hld_obj.oid())
            self.__class__._objects_ids_to_keep.append(pi_port.sys_port.voq_set.oid())
            self.__class__._objects_ids_to_keep.append(pi_port.pci_port.hld_obj.oid())

    def _add_topology_recycle_ports(self):
        for rcy_port in self.topology.recycle_ports:
            if rcy_port is None:
                continue
            self.__class__._objects_ids_to_keep.append(rcy_port.sys_port.hld_obj.oid())
            self.__class__._objects_ids_to_keep.append(rcy_port.sys_port.voq_set.oid())
            self.__class__._objects_ids_to_keep.append(rcy_port.rcy_port.hld_obj.oid())

    def remove_topology_inject_port(self, slice_id):
        pi_port = self.topology.inject_ports[slice_id]
        if pi_port is None:
            return

        pi_port_oid     = pi_port.hld_obj.oid()
        pi_sys_port_oid = pi_port.sys_port.hld_obj.oid()
        pi_voq_oid      = pi_port.sys_port.voq_set.oid()
        pi_pci_port_oid = pi_port.pci_port.hld_obj.oid()

        for oid in [pi_port_oid, pi_sys_port_oid, pi_voq_oid, pi_pci_port_oid]:
            self.__class__._objects_ids_to_keep.remove(oid)

        pi_port.destroy()
        self.topology.inject_ports[slice_id] = None

    def add_topology_inject_port(self, slice_id):
        assert self.topology.inject_ports[slice_id] is None

        pi_port = self.topology.create_single_inject_port(self, self.device, slice_id)

        pi_port_oid     = pi_port.hld_obj.oid()
        pi_sys_port_oid = pi_port.sys_port.hld_obj.oid()
        pi_voq_oid      = pi_port.sys_port.voq_set.oid()
        pi_pci_port_oid = pi_port.pci_port.hld_obj.oid()

        for oid in [pi_port_oid, pi_sys_port_oid, pi_voq_oid, pi_pci_port_oid]:
            self.__class__._objects_ids_to_keep.append(oid)

        self.topology.inject_ports[slice_id] = pi_port
