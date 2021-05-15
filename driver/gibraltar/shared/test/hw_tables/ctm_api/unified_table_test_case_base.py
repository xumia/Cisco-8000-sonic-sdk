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


import random
from leaba import sdk
from unified_table_factory import unified_table_factory as table_factory
from table_entry_generator_factory import table_entry_generator_factory as gen_factory
import ip_test_base
import unittest
import sim_utils
import topology as T
import logging
from ctm_system_test_utils import measure_time

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210

# RX_SLICE2 = T.get_device_slice(2)

# RX_SYS_PORT_GID2 = 0x501

RX_L3_AC_MAC2 = T.mac_addr('30:35:39:3b:31:30')
RX_L3_AC_GID2 = T.RX_L3_AC_GID + 102


PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xA13

SYS_PORT_GID_BASE = 23
# IN_SP_GID = SYS_PORT_GID_BASE
# OUT_SP_GID = SYS_PORT_GID_BASE + 1
PUNT_SP_GID = SYS_PORT_GID_BASE + 2

PUNT_SLICE = 1  # must be odd numbered slice due to bug in Pacific that RCY port can't be on the same slice as PCI port
PUNT_IFG = 1
PUNT_PIF_FIRST = 8

#OUT_PUNT_PIF = T.PI_PIF + 1


DIP_ipv6 = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')

narrow_table_names = [
    "EGRESS_IPV4_SEC_TABLE",
    "INGRESS_IPV4_SEC_TABLE",
]

wide_table_names = [
    "EGRESS_IPV6_SEC_TABLE",
    "INGRESS_IPV6_SEC_TABLE",
]


class unified_table_test_case_base(unittest.TestCase):

    slice_modes = sim_utils.STANDALONE_DEV

    def setUp(self, device_id=1,
              device_config_func=None):
        super().setUp()
        self.device = sim_utils.create_device(device_id,
                                              slice_modes=unified_table_test_case_base.slice_modes,
                                              device_config_func=device_config_func)
        self.topology = T.topology(self, self.device, create_default_topology=True)
        self.set_random_seed()
        # everything created during the initialization that is needed by the entry
        # generator or the table wrapper will be stored here.
        unified_table_test_case_base.config_data = {}
        # ingress and egress ipv4 sec, lpts
        self.add_default_route_bothgress_ipv4_acl_lpts()
        self.do_lpts_config()

        # ingress ipv6
        self.ipv6_impl = ip_test_base.ipv6_test_base()
        self.add_default_route_bothgress_ipv6_acl()

        # pbr
        self.do_pbr_config()

        #self.topology.rx2_eth_port = T.ethernet_port(self.topology.testcase, self.device, RX_SLICE2, T.RX_IFG, RX_SYS_PORT_GID2, T.FIRST_SERDES, T.LAST_SERDES)
        self.topology.rx2_l3_ac = T.l3_ac_port(self.topology.testcase, self.device,
                                               RX_L3_AC_GID2,
                                               self.topology.tx_l3_ac_eth_port_def,
                                               self.topology.vrf,
                                               RX_L3_AC_MAC2,
                                               T.RX_L3_AC_PORT_VID1,
                                               T.RX_L3_AC_PORT_VID2)

        self.topology.rx2_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.rx2_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        self.topology.rx2_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)

    def tearDown(self):
        T.topology.inject_ports = []
        T.topology.recycle_ports = []
        T.topology.voq_allocators = {}
        T.topology.persistent_voq_allocators = {}
        self.device.tearDown()

    def add_default_route_bothgress_ipv4_acl_lpts(self):
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = 0x0
        prefix.length = 0
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.topology.nh_l3_ac_def.hld_obj, PRIVATE_DATA_DEFAULT, False)

    def add_default_route_bothgress_ipv6_acl(self):
        prefix = self.ipv6_impl.build_prefix(DIP_ipv6, length=0)
        self.topology.vrf.hld_obj.add_ipv6_route(prefix, self.topology.nh_l3_ac_def.hld_obj, PRIVATE_DATA_DEFAULT, False)

    def add_default_pbr_routes(self):
        prefix = unified_table_test_case_base.config_data["pbripv4"]["ip_impl"].get_default_prefix()
        unified_table_test_case_base.config_data["pbripv4"]["ip_impl"].add_route(
            self.topology.vrf, prefix, unified_table_test_case_base.config_data["pbripvall"]["l3_port_impl"].reg_nh, PRIVATE_DATA_DEFAULT)

        prefix = unified_table_test_case_base.config_data["pbripv6"]["ip_impl"].get_default_prefix()
        unified_table_test_case_base.config_data["pbripv6"]["ip_impl"].add_route(
            self.topology.vrf, prefix, unified_table_test_case_base.config_data["pbripvall"]["l3_port_impl"].reg_nh, PRIVATE_DATA_DEFAULT)

    def do_lpts_config(self):
        pi_port = T.punt_inject_port(
            self,
            self.device,
            PUNT_SLICE,
            PUNT_IFG,
            PUNT_SP_GID,
            PUNT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        self.punt_dest1 = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION1_GID,
            pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)
        self.device.set_trap_configuration(
            sdk.LA_EVENT_L3_TTL_OR_HOP_LIMIT_IS_ONE,
            1,
            None,
            self.punt_dest1,
            False,
            False,
            True, 0)

        self.punt_dest2 = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)

        # enable mc traffic on l3 ac
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        self.device.set_trap_configuration(
            sdk.LA_EVENT_L3_TTL_OR_HOP_LIMIT_IS_ONE,
            1,
            None,
            self.punt_dest2,
            False,
            False,
            True, 0)

        self.stat_meter = T.create_meter_set(self, self.device, is_statistical=True, set_size=1)

    # Do the PBR or BGP config
    def do_pbr_config(self):
        unified_table_test_case_base.config_data["pbripv4"] = {}
        unified_table_test_case_base.config_data["pbripv6"] = {}
        unified_table_test_case_base.config_data["pbripvall"] = {}

        unified_table_test_case_base.config_data["pbripvall"]["l3_port_impl"] = T.ip_l3_ac_base(self.topology)
        unified_table_test_case_base.config_data["pbripvall"]["rx_port"] = unified_table_test_case_base.config_data["pbripvall"]["l3_port_impl"].rx_port

        unified_table_test_case_base.config_data["pbripv4"]["ip_impl"] = ip_test_base.ipv4_test_base
        unified_table_test_case_base.config_data["pbripv4"]["PBR_ACL_FIELDS"] = [
            'ALL', 'SIP', 'DIP', 'SPORT', 'DPORT', 'PROTOCOL', 'TOS', 'IPV4_FLAGS']
        unified_table_test_case_base.config_data["pbripv6"]["ip_impl"] = ip_test_base.ipv6_test_base
        unified_table_test_case_base.config_data["pbripv6"]["PBR_ACL_FIELDS"] = ['ALL', 'SIP', 'DIP', 'SPORT', 'DPORT', 'PROTOCOL']

        unified_table_test_case_base.config_data["pbripv4"]["key_profile"] = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_IPV4, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_PBR_IPV4, 0)
        unified_table_test_case_base.config_data["pbripv4"]["command_profile"] = self.device.create_acl_command_profile(
            sdk.LA_ACL_COMMAND)

        unified_table_test_case_base.config_data["pbripv6"]["acl_key_profile"] = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_IPV6, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_IPV6, 0)
        unified_table_test_case_base.config_data["pbripv6"]["command_profile"] = self.device.create_acl_command_profile(
            sdk.LA_ACL_COMMAND)

    @staticmethod
    def ingress_ipv4_udf_160_device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            udk = []
            udf1 = sdk.la_acl_field_def()
            udf1.type = sdk.la_acl_field_type_e_IPV4_SIP
            udk.append(udf1)
            udf2 = sdk.la_acl_field_def()
            udf2.type = sdk.la_acl_field_type_e_IPV4_DIP
            udk.append(udf2)
            udf3 = sdk.la_acl_field_def()
            udf3.type = sdk.la_acl_field_type_e_PROTOCOL
            udk.append(udf3)
            udf4 = sdk.la_acl_field_def()
            udf4.type = sdk.la_acl_field_type_e_IPV4_FLAGS
            udk.append(udf4)
            udf6 = sdk.la_acl_field_def()
            udf6.type = sdk.la_acl_field_type_e_TCP_FLAGS
            udk.append(udf6)
            udf7 = sdk.la_acl_field_def()
            udf7.type = sdk.la_acl_field_type_e_SPORT
            udk.append(udf7)
            udf8 = sdk.la_acl_field_def()
            udf8.type = sdk.la_acl_field_type_e_DPORT
            udk.append(udf8)
            udf9 = sdk.la_acl_field_def()
            udf9.type = sdk.la_acl_field_type_e_MSG_TYPE
            udk.append(udf9)
            udf10 = sdk.la_acl_field_def()
            udf10.type = sdk.la_acl_field_type_e_MSG_CODE
            udk.append(udf10)
            udf11 = sdk.la_acl_field_def()
            udf11.type = sdk.la_acl_field_type_e_TOS
            udk.append(udf11)
            key_size, ingress_ipv4_udf_160_table_wrapper.acl_profile_ipv4_160_udk = device.create_acl_profile(
                sdk.la_acl_key_type_e_IPV4_UDK, udk)

    @staticmethod
    def ingress_ipv4_udf_320_device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            udk = []
            udf1 = sdk.la_acl_field_def()
            udf1.type = sdk.la_acl_field_type_e_IPV4_SIP
            udk.append(udf1)
            udf2 = sdk.la_acl_field_def()
            udf2.type = sdk.la_acl_field_type_e_IPV4_DIP
            udk.append(udf2)
            udf3 = sdk.la_acl_field_def()
            udf3.type = sdk.la_acl_field_type_e_PROTOCOL
            udk.append(udf3)
            udf4 = sdk.la_acl_field_def()
            udf4.type = sdk.la_acl_field_type_e_TTL
            udk.append(udf4)
            udf5 = sdk.la_acl_field_def()
            udf5.type = sdk.la_acl_field_type_e_IPV4_FLAGS
            udk.append(udf5)
            udf6 = sdk.la_acl_field_def()
            udf6.type = sdk.la_acl_field_type_e_TCP_FLAGS
            udk.append(udf6)
            udf7 = sdk.la_acl_field_def()
            udf7.type = sdk.la_acl_field_type_e_SPORT
            udk.append(udf7)
            udf8 = sdk.la_acl_field_def()
            udf8.type = sdk.la_acl_field_type_e_DPORT
            udk.append(udf8)
            udf9 = sdk.la_acl_field_def()
            udf9.type = sdk.la_acl_field_type_e_MSG_TYPE
            udk.append(udf9)
            udf10 = sdk.la_acl_field_def()
            udf10.type = sdk.la_acl_field_type_e_MSG_CODE
            udk.append(udf10)
            udf11 = sdk.la_acl_field_def()
            udf11.type = sdk.la_acl_field_type_e_UDF
            udf11.udf_desc.index = 1
            udf11.udf_desc.protocol_layer = 0
            udf11.udf_desc.header = 0
            udf11.udf_desc.offset = 20
            udf11.udf_desc.width = 16
            udf11.udf_desc.is_relative = True
            udk.append(udf11)
            key_size, self.acl_profile_ipv4_320_udk = device.create_acl_profile(
                sdk.la_acl_key_type_e_IPV4_UDK, udk)

    @staticmethod
    def ingress_ipv6_udf_320_device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            udk = []
            udf1 = sdk.la_acl_field_def()
            udf1.type = sdk.la_acl_field_type_e_IPV6_SIP
            udk.append(udf1)
            udf2 = sdk.la_acl_field_def()
            udf2.type = sdk.la_acl_field_type_e_IPV6_DIP
            udk.append(udf2)
            udf3 = sdk.la_acl_field_def()
            udf3.type = sdk.la_acl_field_type_e_SPORT
            udk.append(udf3)
            udf4 = sdk.la_acl_field_def()
            udf4.type = sdk.la_acl_field_type_e_IPV6_FRAGMENT
            udk.append(udf4)
            # Below fields are left commented pending optimization on Library side not to consume space in key for
            # mutually exclusive fields.
            #udf9 = sdk.la_acl_field_def()
            #udf9.type = sdk.la_acl_field_type_e_MSG_TYPE
           # udk.append(udf9)
            #udf10 = sdk.la_acl_field_def()
            #udf10.type = sdk.la_acl_field_type_e_MSG_CODE
            # udk.append(udf10)
            udf11 = sdk.la_acl_field_def()
            udf11.type = sdk.la_acl_field_type_e_TOS
            udk.append(udf11)
            key_size, self.acl_profile_ipv6_320_udk = device.create_acl_profile(
                sdk.la_acl_key_type_e_IPV6_UDK, udk)

    # \brief Sets default random seed.
    # Use this function to make sure any subsequent test execution will
    # use the same pseudorandom numbers every time the test is run.
    # \param self
    # \param seed  Value of the seed (integer).
    def set_random_seed(self, seed=123456):
        logging.debug("Setting random seed to " + str(seed))
        random.seed(seed)

    # \brief Gets one of narrow table names.
    # \param self
    def get_random_narrow_table_name(self):
        table_name = random.choice(narrow_table_names)
        logging.info("Choosing random narrow table " + table_name)
        return table_name

    # \brief Gets one of wide table names.
    # \param self
    def get_random_wide_table_name(self):
        table_name = random.choice(wide_table_names)
        logging.info("Choosing random wide table " + table_name)
        return table_name

    # \brief Inserts specified number of entries to the given table.
    # Returns the number of actually inserted entries.
    # \param self
    # \param table_name Table name.
    # \param table      Table object refference.
    # \param generator  Table's generator object reference.
    # \param count      Number of entries that should be inserted.
    def insert_entries(self, table_name, table, generator, count):
        before_insert_count = table.do_get_count()
        logging.info("Inserting " + str(count) + " entries into " + table_name +
                     " - entry count before: " + str(before_insert_count))

        for i in range(count):
            entry = generator.generate_next_entry()
            try:
                table.do_append(entry)
            except BaseException:
                logging.info("Exception at entry: " + str(i))
                break

        after_insert_count = table.do_get_count()
        logging.info("Inserted " + str(after_insert_count - before_insert_count) +
                     " entries.")

        return after_insert_count - before_insert_count

    # \brief Inserts entries to the given table until it is filled.
    # \param self
    # \param table_name Table name.
    # \param table      Table object refference.
    # \param generator  Table's generator object reference.
    # \return the number of actually inserted entries.
    @measure_time
    def fill_table(self, table_name, table, generator, start_priority=None):
        before_insert_count = table.do_get_count()
        logging.info("Filling: " + table_name + " - entry count before: " + str(before_insert_count))
        number_of_inserts = 12500
        for i in range(number_of_inserts):
            if(i % 500 == 0):
                logging.info("Inserting line at index " + str(i))
            entry = generator.generate_next_entry()

            try:
                if start_priority is None:
                    table.do_append(entry)
                else:
                    table.do_insert(i + start_priority, entry)
            except BaseException:
                logging.info("Exception at entry: " + str(i))
                break

        after_insert_count = table.do_get_count()

        logging.info("Filled by inserting " + str(after_insert_count - before_insert_count) +
                     " entries.")

        return after_insert_count - before_insert_count

    # \brief Erases entries at given places.
    # \param self
    # \param table  Table object reference.
    # \param indices List of indices of erased entries.
    @measure_time
    def erase_entries_at_indices(self, table, indices):
        num_entries_to_erase = len(indices)
        self.assertTrue(num_entries_to_erase <= table.do_get_count())
        before_erase_count = table.do_get_count()
        for idx in indices:
            table.do_erase(idx)
        after_erase_count = table.do_get_count()
        self.assertEqual(before_erase_count - after_erase_count, num_entries_to_erase)
        logging.info("Erased " + str(num_entries_to_erase) + " entries.")

    # \brief Erases entries beginning at specific index using specific step.
    # \param self
    # \param table_name Table name.
    # \param table      Table object reference.
    # \param start      Starting index
    # \param step       Step of erasing
    # \param count      Number of entries to be erased
    def erase_entries_regular(self, table_name, table, start, step, count):
        logging.info(
            "Erasing " +
            str(count) +
            " entries, starting at " +
            str(start) +
            ", using step " +
            str(step) +
            ", in " +
            table_name)
        if step == 1:
            erase_indices = [start] * count
        else:
            erase_indices = list(range(start, start + count * (step - 1), step - 1))
        self.erase_entries_at_indices(table, erase_indices)

    # \brief Erases given number of entries at random indexes within a certain range.
    # \param self
    # \param table_name Table name.
    # \param table      Table object reference.
    # \param count      Number of entries to be erased
    # \param begin      Start of the range (included)
    # \param end        Stop of the range (not included)
    def erase_entries_random(self, table_name, table, count, begin=0, end=None):
        table_size = table.do_get_count()
        self.assertTrue(count <= table_size and begin < table_size)
        if end is not None:
            self.assertTrue(end <= table_size)

        logging.info(
            "Erasing randomly " +
            str(count) +
            " entries, in " +
            table_name)

        erase_indices = []
        for i in range(count):
            stop = table_size if (end is None or end > table_size) else end
            idx = random.randrange(start=begin, stop=stop)
            erase_indices.append(idx)
            table_size -= 1
        self.erase_entries_at_indices(table, erase_indices)
