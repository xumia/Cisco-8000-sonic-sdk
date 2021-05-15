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

import pytest
import os
import sai_test_base as st_base
import time
import sai_test_utils as st_utils
from saicli import *


'''
For HW testing, set BOARD_TYPE=gb_alt_board_p2_attr_test_case. Then, run each test case by itself.
Test expects all links-up during port_attr_setup()
'''


@pytest.fixture(scope="class")
def port_attr_setup(request):
    print("\n")    # for better debug log.

    tb = st_base.sai_test_base()

    # === Setup the SAI_SWITCH_ATTR_FIRMWARE_PATH_NAME ===
    # save and remove the BASE_OUTPUT_DIR from env
    env_name = "BASE_OUTPUT_DIR"
    env_path = os.getenv(env_name, None)

    tb.log("getenv -> {} = {}".format(env_name, env_path))
    os.unsetenv(env_name)
    os.environ.pop(env_name, None)

    # check if env paths removed
    assert os.getenv(env_name, None) is None

    # setup fw_path_name for SAI_SWITCH_ATTR_FIRMWARE_PATH_NAME attribute.
    tb.fw_path_name = env_path

    # In tb.setUp(), SAI_SWITCH_ATTR_FIRMWARE_PATH_NAME attribute will be set and used during create_sai_switch().
    # === End of Setup SAI_SWITCH_ATTR_FIRMWARE_PATH_NAME ===

    # this sherman_p5_attr_test_case.json has pointer to port_mix file
    # and, tb.setUp will create ports with admin_state set to false (specified by port_mix file).
    test_case_defined_board_type = "sherman_p5_attr_test_case"

    asic_name = os.getenv('ASIC')
    if asic_name is not None:
        if asic_name.lower().startswith('gibraltar'):
            test_case_defined_board_type = "blacktip_1_attr_test_case"

    test_case_defined_board_type = os.getenv('BOARD_TYPE', test_case_defined_board_type)

    tb.setUp(board_type=test_case_defined_board_type)

    # build the tb.ports_config for cross check port_mix configuration
    SDK_ROOT = os.getenv('SDK_ROOT', os.getcwd() + "/../")
    port_config_pathname = SDK_ROOT + "/sai/test/python/attr/"
    if tb.is_gb:
        PORT_CFG_FILE = port_config_pathname + "sai_test_attr_port_config_gb.json"
    else:
        PORT_CFG_FILE = port_config_pathname + "sai_test_attr_port_config.json"
    tb.ports_config = st_utils.load_ports_from_json(PORT_CFG_FILE)
    st_utils.print_ports_config(tb.ports_config)

    # do not create ports. all ports are created using port_mix in config file.
    # check all port and back annotate sai_port_obj_id to tb.ports[]
    st_utils.list_active_ports(tb)

    all_ports = tb.ports_config['real_ports']
    if 'preemp_test_port' in tb.ports_config:
        all_ports = all_ports + tb.ports_config['preemp_test_port']

    for port in all_ports:
        tb.link_state_check(port['pif'], is_up=True, polls=30)

    yield tb
    tb.tearDown()


#@pytest.mark.usefixtures("port_attr_setup")
class Test_port_attr():
    def check_ports(self, link_up, ports_config):
        for port in ports_config:
            self.tb.link_state_check(port['pif'], is_up=link_up, polls=30)

    def test_admin_state(self, port_attr_setup):
        self.tb = port_attr_setup
        all_ports = self.tb.ports_config['real_ports']

        if 'preemp_test_port' in self.tb.ports_config:
            all_ports = all_ports + self.tb.ports_config['preemp_test_port']

        self.tb.set_all_ports_admin_state(False)
        self.check_ports(False, all_ports)

        # check all active port with json port configurations.
        st_utils.check_active_ports(self.tb, all_ports)
        self.tb.check_ports_state_callback([port_cfg['pif'] for port_cfg in all_ports])

        for port_cfg in all_ports:
            down_msg = self.tb.port_state_down_msg_counts(port_cfg['pif'])
            up_msg = self.tb.port_state_up_msg_counts(port_cfg['pif'])
            assert down_msg == 1, "Link Down message doesn't match: PIF({}), message_cnt({}), expected(1)".format(
                port_cfg['pif'], down_msg)
            assert up_msg == 1, "Link Up message doesn't match: PIF({}), message_cnt({}), expected(1)".format(
                port_cfg['pif'], up_msg)

        # restore admin state for all ports
        self.tb.set_all_ports_admin_state(True)
        self.check_ports(True, all_ports)

        # check switch temp attribute
        s32_list = sai_s32_list_t([])
        attr = sai_attribute_t(SAI_SWITCH_ATTR_TEMP_LIST, s32_list)
        with st_utils.expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
            self.tb.apis[SAI_API_SWITCH].get_switch_attribute(self.tb.switch_id, 1, attr)

        total_sensors = 6   # pacific sensors numbers
        if (self.tb.is_gb):
            total_sensors = 12

        assert attr.value.s32list.count == total_sensors

        # check average and max temperature
        temp_values = self.tb.get_object_attr(self.tb.switch_id, SAI_SWITCH_ATTR_TEMP_LIST)

        max_value = max(temp_values)
        avg_value = 0
        counts = 0

        for value in temp_values:
            if value > int(INVALID_CACHED_TEMPERATURE):
                avg_value += value
                counts += 1

        assert counts > 0, "Valid Temperature counter is {}".format(counts)
        avg_value /= counts

        allowance = 1   # error allowance for avg and max calculation since they sample at a different time.
        hw_max_value = self.tb.get_object_attr(self.tb.switch_id, SAI_SWITCH_ATTR_MAX_TEMP)
        self.tb.log("MAX: L({}) <= {} <=  H({})".format(max_value - allowance, hw_max_value, max_value + allowance))
        assert ((max_value - allowance <= hw_max_value) and (max_value + allowance >= hw_max_value))

        hw_avg_value = self.tb.get_object_attr(self.tb.switch_id, SAI_SWITCH_ATTR_AVERAGE_TEMP)
        self.tb.log("AVG: L({}) <= {} <=  H({})".format(avg_value - allowance, hw_avg_value, avg_value + allowance))
        assert ((avg_value - allowance <= hw_avg_value) and (avg_value + allowance >= hw_avg_value))

    def test_serdes_preemphasis_config(self, port_attr_setup):
        self.tb = port_attr_setup
        st_utils.skipIf(not self.tb.is_gb)
        test_port_cfg = self.tb.ports_config['preemp_test_port'][0]

        # this is the pre-define port in test_case.json. Because it is connected to Sprient.
        port_obj_id = self.tb.ports[test_port_cfg['pif']]
        # create a new port with new serdes parameters value.
        port_srds_cfg = {}
        port_srds_cfg[SAI_PORT_SERDES_ATTR_PORT_ID] = port_obj_id
        # create and get the port_serdes_id for this port, also verify the attributes
        port_srds_id = self.tb.create_port_serdes(port_srds_cfg, verify=[True, False])

        is_lpbk = False

        for lpbk_mode in [
                SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE,
                SAI_PORT_INTERNAL_LOOPBACK_MODE_PHY,
                SAI_PORT_INTERNAL_LOOPBACK_MODE_MAC]:
            test_port_cfg['mac_lpbk'] = lpbk_mode
            is_lpbk = lpbk_mode != SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE

            # Update Loopback Mode
            self.tb.log("Changing loopback mode({}) ...".format(test_port_cfg['mac_lpbk']))
            self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE, test_port_cfg['mac_lpbk'], verify=True)

            self.tb.link_state_check(
                test_port_cfg['pif'], msg="Fail: admin_state(True), preemp(Default), is_lpbk({})... check 1.0".format(is_lpbk))
            self.tb.log("Passed check 1.0.  admin_state(True), preemp(Default), is_lpbk({})".format(is_lpbk))

            # check default serdes pre-emp value.
            preemp = [50, 50, 50, 50]
            out_list = self.tb.get_object_attr(port_srds_id, SAI_PORT_SERDES_ATTR_PREEMPHASIS)
            assert out_list == preemp
            self.tb.link_state_check(
                test_port_cfg['pif'], msg="Fail: admin_state(True), preemp(+ve), is_lpbk({})... check 2.0".format(is_lpbk))
            self.tb.log("Passed check 2.0.  admin_state(True), preemp(+ve), is_lpbk({})".format(is_lpbk))

            # check buffer overflow condition with nullptr
            u32_list = sai_u32_list_t([])
            attr = sai_attribute_t(SAI_PORT_ATTR_SERDES_PREEMPHASIS, u32_list)
            with st_utils.expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
                self.tb.apis[SAI_API_PORT].get_port_attribute(port_obj_id, 1, attr)
            if (attr.value.u32list.count == 0):
                raise

            # check write when admin_state is true
            preemp = [5, 6, 0, 8]
            self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_SERDES_PREEMPHASIS, preemp, verify=True)
            self.tb.link_state_check(
                test_port_cfg['pif'],
                is_up=(
                    False | is_lpbk),
                msg="Fail: admin_state(True), preemp(0), is_lpbk({})... check 2.1".format(is_lpbk))
            self.tb.log("Passed check 2.1.  admin_state(True), preemp(0), is_lpbk({})".format(is_lpbk))

            # check write when admin_state is false
            self.tb.set_port_admin_state(test_port_cfg['pif'], False)
            self.tb.link_state_check(
                test_port_cfg['pif'],
                is_up=False,
                msg="Fail: admin_state(False), preemp(0), is_lpbk({})... check 3.0".format(is_lpbk))
            self.tb.log("Passed check 3.0.  admin_state(False), preemp(0), is_lpbk({})".format(is_lpbk))

            preemp = [21, 22, 23, 24]
            self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_SERDES_PREEMPHASIS, preemp, verify=True)
            self.tb.link_state_check(
                test_port_cfg['pif'],
                is_up=False,
                msg="Fail: admin_state(False), preemp(+ve), is_lpbk({})... check 3.1".format(is_lpbk))
            self.tb.log("Passed check 3.1.  admin_state(False), preemp(+ve), is_lpbk({})".format(is_lpbk))

            preemp = [15, 0, 18, 18]
            self.tb.set_object_attr(port_srds_id, SAI_PORT_SERDES_ATTR_PREEMPHASIS, preemp, verify=True)
            self.tb.link_state_check(
                test_port_cfg['pif'],
                is_up=False,
                msg="Fail: admin_state(False), preemp(0), is_lpbk({})... check 3.2".format(is_lpbk))
            self.tb.log("Passed check 3.2.  admin_state(False), preemp(0), is_lpbk({})".format(is_lpbk))

            # change admin_state to true and values should be correct.
            self.tb.set_port_admin_state(test_port_cfg['pif'], True)

            out_list = self.tb.get_object_attr(port_obj_id, SAI_PORT_ATTR_SERDES_PREEMPHASIS)
            assert out_list == preemp
            self.tb.link_state_check(
                test_port_cfg['pif'],
                is_up = (
                    False | is_lpbk),
                msg="Fail: admin_state(True), preemp(0), is_lpbk({})... check 4.0".format(is_lpbk))
            self.tb.log("Passed check 4.0.  admin_state(True), preemp(0), is_lpbk({})".format(is_lpbk))

            # resume back
            preemp = [75, 76, 77, 78]
            self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_SERDES_PREEMPHASIS, preemp, verify=True)
            self.tb.link_state_check(
                test_port_cfg['pif'], msg="Fail: admin_state(True), preemp(+ve), is_lpbk({})... check 4.1".format(is_lpbk))
            self.tb.log("Passed check 4.1.  admin_state(True), preemp(+ve), is_lpbk({})".format(is_lpbk))

            # set back the default value
            preemp = [50, 50, 50, 50]
            self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_SERDES_PREEMPHASIS, preemp, verify=True)

        # Now, changing the loopback_mode and check the behavior.

        # First, Loopback=None, admin-state=up, preemp=50
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_SERDES_PREEMPHASIS, [50, 50, 50, 50], verify=True)
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE,
                                SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE, verify=True)
        self.tb.set_port_admin_state(test_port_cfg['pif'], True)

        # We start with (preemp = [50, 50, 50, 50]), !lpbk_mode, and admin_state=True
        self.tb.link_state_check(test_port_cfg['pif'], msg="Fail: admin_state(True), preemp(50s), is_lpbk(False)... check 5.0")
        self.tb.log("Passed check 5.0.  admin_state(True), preemp(50s), is_lpbk(False)")

        # set preemphasis to 0
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_SERDES_PREEMPHASIS, [50, 50, 0, 50], verify=True)
        self.tb.link_state_check(
            test_port_cfg['pif'],
            is_up=False,
            msg="Fail: admin_state(True), preemp(0), is_lpbk(False)... check 5.1")
        self.tb.log("Passed check 5.1.  admin_state(True), preemp(0), is_lpbk(False)")

        # Change to Loopback Mode
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE, SAI_PORT_INTERNAL_LOOPBACK_MODE_PHY, verify=True)
        self.tb.link_state_check(test_port_cfg['pif'], msg="Fail: admin_state(True), preemp(0), is_lpbk(True)... check 5.2")
        self.tb.log("Passed check 5.2.  admin_state(True), preemp(0), is_lpbk(True)")

        # Change to non-Loopback Mode
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE,
                                SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE, verify=True)
        self.tb.link_state_check(
            test_port_cfg['pif'],
            is_up=False,
            msg="Fail: admin_state(True), preemp(0), is_lpbk(False)... check 5.3")
        self.tb.log("Passed check 5.3.  admin_state(True), preemp(0), is_lpbk(False)")

        # create new port and check pre-set value ...
        test_port_cfg['pif'] = 0xa04
        test_port_cfg['mac_lpbk'] = SAI_PORT_INTERNAL_LOOPBACK_MODE_PHY
        self.tb.configure_ports([test_port_cfg])
        port_obj_id = self.tb.ports[test_port_cfg['pif']]
        preemp = test_port_cfg['serdes_preemp']
        out_list = self.tb.get_object_attr(port_obj_id, SAI_PORT_ATTR_SERDES_PREEMPHASIS)
        assert out_list == preemp
        self.tb.link_state_check(
            test_port_cfg['pif'], msg="Fail: admin_state(True), preemp(Create Value), is_lpbk(False)... check 7.0")
        self.tb.log("Passed check 7.0.  admin_state(True), preemp(Create Value), is_lpbk(False)")

        self.tb.remove_port_serdes(port_srds_id)
        self.tb.remove_port(test_port_cfg['pif'])

    def test_serdes_parameters(self, port_attr_setup):
        self.tb = port_attr_setup
        st_utils.skipIf(not self.tb.is_gb)
        test_port_cfg = self.tb.ports_config['preemp_test_port'][0]

        # create new port
        test_port_cfg['pif'] = 0xa04
        test_port_cfg['admin_state'] = True
        self.tb.configure_ports([test_port_cfg])

        port_info = {}
        port_info['oid'] = self.tb.ports[test_port_cfg['pif']]
        st_utils.read_sai_port_info(self.tb, port_info)

        self.tb.log("Print created SAI Port: {}".format(port_info))

        # create a new port with new serdes parameters value.
        port_srds_cfg = {}
        port_srds_cfg[SAI_PORT_SERDES_ATTR_PORT_ID] = port_info['oid']
        port_srds_cfg[SAI_PORT_SERDES_ATTR_EXT_CTLE_TUNE] = [0, 1, 0, 1]
        port_srds_cfg[SAI_PORT_SERDES_ATTR_EXT_TX_PRE1] = [1, 2, 3, 4]
        port_srds_cfg[SAI_PORT_SERDES_ATTR_EXT_TX_POST3] = [-1, -2, -3, -4]
        port_srds_cfg[SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE2] = [1000, 2000, 0, -1000]
        signed_tx_main = [44, -43, -42, 41]
        unsigned_tx_main = st_utils.int_to_uint(signed_tx_main)
        port_srds_cfg[SAI_PORT_SERDES_ATTR_TX_FIR_MAIN] = unsigned_tx_main

        # create and get the port_serdes_id for this port, also verify the attributes
        port_srds_id = self.tb.create_port_serdes(port_srds_cfg, verify=[True, False])

        # check SDK default values
        out_list = self.tb.get_object_attr(port_srds_id, SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE1)
        assert out_list == [1000, 1000, 1000, 1000]
        out_list = self.tb.get_object_attr(port_srds_id, SAI_PORT_SERDES_ATTR_EXT_RX_AC_COUPLING_BYPASS)
        assert out_list == [1, 1, 1, 1]

        # check FIR MAIN and EXT MAIN value casting
        out_list = self.tb.get_object_attr(port_srds_id, SAI_PORT_SERDES_ATTR_TX_FIR_MAIN)
        assert out_list == unsigned_tx_main

        out_list = self.tb.get_object_attr(port_srds_id, SAI_PORT_SERDES_ATTR_EXT_TX_MAIN)
        assert out_list == signed_tx_main

        # Now, test the runtime udpate...
        self.tb.set_object_attr(port_srds_id, SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE1, [1001, 1002, 1003, 1004], verify=True)
        self.tb.set_object_attr(port_srds_id, SAI_PORT_SERDES_ATTR_EXT_CTLE_TUNE, [1, 0, 1, 0], verify=True)

        # check serdes attribute buffer overflow with nullptr list
        s32_list = sai_s32_list_t([])
        attr = sai_attribute_t(SAI_PORT_SERDES_ATTR_EXT_TX_PRE1, s32_list)
        with st_utils.expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
            self.tb.apis[SAI_API_PORT].get_port_serdes_attribute(port_srds_id, 1, attr)
        assert (attr.value.objlist.count == 4)

        s32_list = sai_s32_list_t([])
        attr2 = sai_attribute_t(SAI_PORT_SERDES_ATTR_EXT_TX_POST3, s32_list)
        with st_utils.expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
            self.tb.apis[SAI_API_PORT].get_port_serdes_attribute(port_srds_id, 1, attr2)
        assert (attr2.value.objlist.count == 4)

        s32_list = sai_s32_list_t([])
        attr3 = sai_attribute_t(SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE1, s32_list)
        with st_utils.expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
            self.tb.apis[SAI_API_PORT].get_port_serdes_attribute(port_srds_id, 1, attr3)
        assert (attr3.value.objlist.count == 4)

        s32_list = sai_s32_list_t([])
        attr4 = sai_attribute_t(SAI_PORT_SERDES_ATTR_EXT_TX_MAIN, s32_list)
        with st_utils.expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
            self.tb.apis[SAI_API_PORT].get_port_serdes_attribute(port_srds_id, 1, attr4)
        assert (attr4.value.objlist.count == 4)

        u32_list = sai_u32_list_t([])
        attr5 = sai_attribute_t(SAI_PORT_SERDES_ATTR_TX_FIR_MAIN, u32_list)
        with st_utils.expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
            self.tb.apis[SAI_API_PORT].get_port_serdes_attribute(port_srds_id, 1, attr5)
        assert (attr5.value.objlist.count == 4)

        # test access during port "shut-down"
        self.tb.set_port_admin_state(test_port_cfg['pif'], False)

        self.tb.set_object_attr(port_srds_id, SAI_PORT_SERDES_ATTR_EXT_RX_AC_COUPLING_BYPASS, [1, 0, 1, 0], verify=True)

        # check value of updated attributes, it should be remain the same
        out_list = self.tb.get_object_attr(port_srds_id, SAI_PORT_SERDES_ATTR_EXT_TX_POST3)
        assert out_list == port_srds_cfg[SAI_PORT_SERDES_ATTR_EXT_TX_POST3]

        # Remove the port_serdes and port
        self.tb.remove_port_serdes(port_srds_id)
        self.tb.remove_port(test_port_cfg['pif'])

        # create new port and check pre-set value ...
        test_port_cfg['pif'] = 0xa04
        port_obj_id = self.tb.create_port(test_port_cfg)
        self.tb.ports[test_port_cfg['pif']] = port_obj_id
        preemp = sai_u32_list_t(test_port_cfg['serdes_preemp'])
        out_list = sai_u32_list_t(range(0, 8))
        out_attr = sai_attribute_t(SAI_PORT_ATTR_SERDES_PREEMPHASIS, out_list)
        self.tb.apis[SAI_API_PORT].get_port_attribute(port_obj_id, 1, out_attr)
        assert preemp.to_pylist() == out_attr.value.u32list.to_pylist()

        # Remove the port
        self.tb.remove_port(test_port_cfg['pif'])

    def test_port_fec_speed_config(self, port_attr_setup):
        self.tb = port_attr_setup

        # Get the 1st real_ports and find its SAI ID.
        test_port_cfg = self.tb.ports_config['real_ports'][0]
        port_obj_id = self.tb.ports[test_port_cfg['pif']]

        # Save the SPEED and FEC attributes
        saved_speed = self.tb.get_object_attr(port_obj_id, SAI_PORT_ATTR_SPEED)
        saved_mode = self.tb.get_object_attr(port_obj_id, SAI_PORT_ATTR_FEC_MODE)

        # change to 40G
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_SPEED, 40000, verify=True)

        # change to FC FEC
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_FEC_MODE, SAI_PORT_FEC_MODE_FC, verify=True)

        # change to 100G
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_SPEED, 100000, verify=True)

        # change to RS FEC
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_FEC_MODE, SAI_PORT_FEC_MODE_RS, verify=True)

        # restore the port setting
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_SPEED, saved_speed, verify=True)
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_FEC_MODE, saved_mode, verify=True)

    def test_port_pfc_config(self, port_attr_setup):
        self.tb = port_attr_setup

        # Get the 1st real_ports and find its SAI ID.
        test_port_cfg = self.tb.ports_config['real_ports'][0]
        port_obj_id = self.tb.ports[test_port_cfg['pif']]

        # Can set verify=True and skip the get, assert checks below
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE,
                                SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_COMBINED,
                                verify=True)

        # enable pfc by setting its mode - pfc may not be initialized
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE,
                                SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_COMBINED)

        # check if the mode is combined mode
        # expect None as the test fails when PFC is not initialized
        # expect_sai_error() does not work on "get". Works only on set
        pfc_mode = self.tb.get_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE)
        assert (pfc_mode == SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_COMBINED), "pfc_mode on get: {0}".format(pfc_mode)

        # only COMBINED mode supported
        with st_utils.expect_sai_error(SAI_STATUS_NOT_SUPPORTED):
            self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE,
                                    SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_SEPARATE)

    def test_port_pfc_queue_map(self, port_attr_setup):
        # this feature is not supported in sai yet. The test case
        # below with key/value [0,2] is a fake validation as key 0 will pass.
        # There is a -ve scenario below, which is the primary test for now
        self.tb = port_attr_setup

        # Get the 1st real_ports and find its SAI ID.
        test_port_cfg = self.tb.ports_config['real_ports'][0]
        port_obj_id = self.tb.ports[test_port_cfg['pif']]

        map_type = SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_QUEUE
        map_attr = SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_QUEUE_MAP
        map_key_value = [(0, 2)]

        # create new qos map, and verify qos map set type attributes work
        qos_map_obj_id = self.tb.create_qos_map(map_type, map_key_value)

        # TODO: Once the mapping is supported by SDK, uncomment the following line
        # self.tb.set_object_attr(port_obj_id, map_attr, qos_map_obj_id, verify=true)
        with st_utils.expect_sai_error(SAI_STATUS_NOT_IMPLEMENTED):
            self.tb.set_object_attr(port_obj_id, map_attr, SAI_NULL_OBJECT_ID)

        self.tb.remove_object(qos_map_obj_id)

    def test_port_pfc_rx_quanta(self, port_attr_setup):
        self.tb = port_attr_setup

        # Get the 1st real_ports and find its SAI ID.
        test_port_cfg = self.tb.ports_config['real_ports'][0]
        port_obj_id = self.tb.ports[test_port_cfg['pif']]

        portIds = portStatVec(1)
        portIds[0] = SAI_PORT_STAT_PFC_0_RX_PAUSE_DURATION
        # SAI_PORT_STAT_PFC_0_RX_PAUSE_DURATION
        # TODO swig layer does not return status code - so not a valid test yet
        counters = getPortCountersExt(port_obj_id, portIds, False)

    def test_port_pfc_quanta(self, port_attr_setup):
        self.tb = port_attr_setup

        # Get the 1st real_ports and find its SAI ID.
        test_port_cfg = self.tb.ports_config['real_ports'][0]
        port_obj_id = self.tb.ports[test_port_cfg['pif']]

        saved_speed = self.tb.get_object_attr(port_obj_id, SAI_PORT_ATTR_SPEED)
        assert saved_speed == 100000, "At port[{}], speed({})".format(hex(port_obj_id), saved_speed)

        # 53 ==> SAI_PORT_STAT_PFC_0_TX_PAUSE_DURATION
        # sdk sets default tx pause duration on port based on speed
        # speed is in terms of 10, 25, 40, 50, 100 gbps not 100000 mbps
        counters = self.tb.get_port_stats(port_obj_id)
        assert counters[53] == int(
            (0xffff * 512 * 1000) / saved_speed), "At port[{}], before PFC config, Tx Pause duration({})".format(hex(port_obj_id), counters[53])

        # enable pfc on port and check again
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0x10, verify=True)
        counters = self.tb.get_port_stats(port_obj_id)
        # TBD: sdk changes 0xffff to 0xfffe - so we set to 0xfffe. update SDK api - then fix here
        dev_quanta_max = 0xfffe
        assert counters[53] == int((dev_quanta_max * 512 * 1000) /
                                   saved_speed), "At port[{}], post PFC config, Tx Pause duration({})".format(hex(port_obj_id), counters[53])

        # disable PFC
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0, verify=True)

    def test_port_pfc_enable(self, port_attr_setup):
        self.tb = port_attr_setup

        # Get the 1st real_ports and find its SAI ID.
        test_port_cfg = self.tb.ports_config['real_ports'][0]
        port_obj_id = self.tb.ports[test_port_cfg['pif']]

        # enable PFC priority 1, 3, 5, 7
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0xaa)
        fc_val = self.tb.get_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL)

        # enable PFC priority 1, 3 and disable 5, 7
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0xa, verify=True)

        # Check that setting same bits works
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0xa, verify=True)

        # disable PFC
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0, verify=True)

    def test_port_pfc_speed_config(self, port_attr_setup):
        self.tb = port_attr_setup

        # Get the 1st real_ports and find its SAI ID.
        test_port_cfg = self.tb.ports_config['real_ports'][0]
        port_obj_id = self.tb.ports[test_port_cfg['pif']]

        # Save the SPEED attribute
        saved_speed = self.tb.get_object_attr(port_obj_id, SAI_PORT_ATTR_SPEED)

        # enable pfc on port
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0xa, verify=True)

        # change to 100G
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_SPEED, 100000, verify=True)

        # change to 40G - pfc is not supported for < 100G
        with st_utils.expect_sai_error(SAI_STATUS_INVALID_PARAMETER):
            self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_SPEED, 40000)

        # restore the port setting
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_SPEED, saved_speed, verify=True)

        # disable pfc on port
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0x0, verify=True)

    def test_port_pfc_queue_map_not_implemented(self, port_attr_setup):
        self.tb = port_attr_setup

        test_port_cfg = self.tb.ports_config['real_ports'][0]
        port_obj_id = self.tb.ports[test_port_cfg['pif']]

        with st_utils.expect_sai_error(SAI_STATUS_NOT_IMPLEMENTED):
            self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_QUEUE_MAP, SAI_NULL_OBJECT_ID)

        assert self.tb.get_object_attr(port_obj_id, SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_QUEUE_MAP) == SAI_NULL_OBJECT_ID

    def test_port_pfc_fc_caching(self, port_attr_setup):
        self.tb = port_attr_setup

        test_port_cfg = self.tb.ports_config['real_ports'][0]
        port_obj_id = self.tb.ports[test_port_cfg['pif']]

        # Set fc to PAUSE in both directions
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE, SAI_PORT_FLOW_CONTROL_MODE_BOTH_ENABLE)

        # Verify both enabled
        fc = self.tb.get_object_attr(port_obj_id, SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE)
        assert fc == SAI_PORT_FLOW_CONTROL_MODE_BOTH_ENABLE

        # Enable PFC
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0xa0, verify=True)

        # Verify FC is not PAUSE anymore
        fc = self.tb.get_object_attr(port_obj_id, SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE)
        assert fc == SAI_PORT_FLOW_CONTROL_MODE_DISABLE

        # Disable PFC
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0, verify=True)

        # Verify PFC restored the original state
        fc = self.tb.get_object_attr(port_obj_id, SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE)
        assert fc == SAI_PORT_FLOW_CONTROL_MODE_BOTH_ENABLE

    def test_port_pfc_mac_state_preservation(self, port_attr_setup):
        # PFC must currently have its port down in order to change its
        # SQ group, e.g. from lossy to lossless. To accomadate this,
        # the PFC implementation flaps the port if it is already up
        # during the change of SQ group when PFC is activated on any
        # traffic class.
        #
        # Test that the mac state is preserved during PFC TC
        # enablement.
        self.tb = port_attr_setup

        # Get the 1st real_ports and find its SAI ID.
        test_port_cfg = self.tb.ports_config['real_ports'][0]
        port_pif = test_port_cfg['pif']
        port_obj_id = self.tb.ports[port_pif]

        # Set port down
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_ADMIN_STATE, False, verify=True)
        self.tb.link_state_check(port_pif, False)

        # Verify port stays down during PFC changes
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0xa, verify=True)
        self.tb.link_state_check(port_pif, False)
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0xa1, verify=True)
        self.tb.link_state_check(port_pif, False)

        # Bring port up
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_ADMIN_STATE, True, verify=True)
        self.tb.link_state_check(port_pif, True)

        # Verify port comes up after PFC changes.
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0xa2, verify=True)
        self.tb.link_state_check(port_pif, True)
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0xa3, verify=True)
        self.tb.link_state_check(port_pif, True)

        # Bring port back down
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_ADMIN_STATE, False, verify=True)
        self.tb.link_state_check(port_pif, False)

        # Disable PFC
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0, verify=True)

    def test_port_pfc_flap_conditions(self, port_attr_setup):
        self.tb = port_attr_setup

        # Get the 1st real_ports and find its SAI ID.
        test_port_cfg = self.tb.ports_config['real_ports'][0]
        port_pif = test_port_cfg['pif']
        port_obj_id = self.tb.ports[port_pif]

        # Port down
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_ADMIN_STATE, False, verify=True)
        self.tb.link_state_check(port_pif, False)

        # Expect no flap while port already down
        down_msg_cnt = self.tb.port_state_down_msg_counts(port_pif)
        up_msg_cnt = self.tb.port_state_up_msg_counts(port_pif)
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0xa, verify=True)
        st_utils.expect_value(lambda: self.tb.port_state_down_msg_counts(port_pif), down_msg_cnt)
        st_utils.expect_value(lambda: self.tb.port_state_up_msg_counts(port_pif), up_msg_cnt)

        # Bring port up
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_ADMIN_STATE, True, verify=True)
        self.tb.link_state_check(port_pif, True)

        # Enable PFC
        down_msg_cnt = self.tb.port_state_down_msg_counts(port_pif)
        up_msg_cnt = self.tb.port_state_up_msg_counts(port_pif)
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0xa1, verify=True)
        st_utils.expect_value(lambda: self.tb.port_state_down_msg_counts(port_pif), down_msg_cnt + 1)
        st_utils.expect_value(lambda: self.tb.port_state_up_msg_counts(port_pif), up_msg_cnt + 1)

        # Change PFC
        down_msg_cnt = self.tb.port_state_down_msg_counts(port_pif)
        up_msg_cnt = self.tb.port_state_up_msg_counts(port_pif)
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0xa2, verify=True)
        st_utils.expect_value(lambda: self.tb.port_state_down_msg_counts(port_pif), down_msg_cnt + 1)
        st_utils.expect_value(lambda: self.tb.port_state_up_msg_counts(port_pif), up_msg_cnt + 1)

        # Disable PFC
        down_msg_cnt = self.tb.port_state_down_msg_counts(port_pif)
        up_msg_cnt = self.tb.port_state_up_msg_counts(port_pif)
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0, verify=True)
        st_utils.expect_value(lambda: self.tb.port_state_down_msg_counts(port_pif), down_msg_cnt + 1)
        st_utils.expect_value(lambda: self.tb.port_state_up_msg_counts(port_pif), up_msg_cnt + 1)

    def test_port_list_getters(self, port_attr_setup):
        self.tb = port_attr_setup
        # test port list buffer overfloe
        port_obj_id_list = sai_object_list_t(range(0))
        attr = sai_attribute_t(SAI_SWITCH_ATTR_PORT_LIST, port_obj_id_list)
        with st_utils.expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
            self.tb.apis[SAI_API_SWITCH].get_switch_attribute(self.tb.switch_id, 1, attr)

        # Get number of active ports and a list of the sai_port_obj_id.
        num_of_active_port = self.tb.get_switch_attribute(SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS)
        port_obj_id_list = self.tb.get_switch_attribute(SAI_SWITCH_ATTR_PORT_LIST)
        assert len(port_obj_id_list) == num_of_active_port
        sai_port_obj_id = port_obj_id_list[0]

        # check hw lane buffer overflow
        lane = sai_u32_list_t([])
        attr = sai_attribute_t(SAI_PORT_ATTR_HW_LANE_LIST, lane)
        with st_utils.expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
            self.tb.apis[SAI_API_PORT].get_port_attribute(sai_port_obj_id, 1, attr)
        if attr.value.u32list.count == 0:
            raise

        lanes = sai_u32_list_t(range(0, attr.value.u32list.count))
        attr = sai_attribute_t(SAI_PORT_ATTR_HW_LANE_LIST, lanes)
        self.tb.apis[SAI_API_PORT].get_port_attribute(sai_port_obj_id, 1, attr)

        # check supported speed and half duplex speed buffer overflow
        u32_list = sai_u32_list_t([])
        attr2 = sai_attribute_t(SAI_PORT_ATTR_SUPPORTED_SPEED, u32_list)
        with st_utils.expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
            self.tb.apis[SAI_API_PORT].get_port_attribute(sai_port_obj_id, 1, attr2)
        if attr2.value.u32list.count == 0:
            raise

    def __test_all_port_messages(self, port_attr_setup):
        self.tb = port_attr_setup

        # destroy all created ports from default.
        self.tb.log("Removing all ports that created by fixtures ...")
        self.tb.remove_ports()
        # clear all counters
        self.tb.clear_all_port_state_msg_counts()

        # rebuild the tb.ports_config with all ports in 100G
        backup_config = self.tb.ports_config
        self.tb.ports_config = {}
        SDK_ROOT = os.getenv('SDK_ROOT', os.getcwd() + "/../")
        port_config_pathname = SDK_ROOT + "/sai/test/python/attr/"
        if self.tb.is_gb:
            PORT_CFG_FILE = port_config_pathname + "sai_test_attr_all_ports_gb.json"
        else:
            PORT_CFG_FILE = port_config_pathname + "sai_test_attr_all_ports.json"
        self.tb.ports_config = st_utils.load_ports_from_json(PORT_CFG_FILE)

        self.tb.configure_ports(self.tb.ports_config['all_ports_100G'])

        # check all port and back annotate sai_port_obj_id to tb.ports[]
        st_utils.list_active_ports(self.tb)

        all_ports = self.tb.ports_config['all_ports_100G']

        msg_count = 2
        for loop in range(msg_count):
            self.tb.set_all_ports_admin_state(True)
            self.check_ports(True, all_ports)
            self.tb.set_all_ports_admin_state(False)
            self.check_ports(False, all_ports)

        # check all active port with json port configurations.
        st_utils.check_active_ports(self.tb, all_ports)
        self.tb.check_ports_state_callback([port_cfg['pif'] for port_cfg in all_ports])

        for port_cfg in all_ports:
            down_msg = self.tb.port_state_down_msg_counts(port_cfg['pif'])
            up_msg = self.tb.port_state_up_msg_counts(port_cfg['pif'])
            assert down_msg == msg_count, "Link Down message doesn't match: PIF({}), message_cnt({}), expected({})".format(
                port_cfg['pif'], down_msg, msg_count)
            assert up_msg == msg_count, "Link Up message doesn't match: PIF({}), message_cnt({}), expected({})".format(
                port_cfg['pif'], up_msg, msg_count)

        # restore to default setup, since we removed all test case port and create all 100G ports.
        self.tb.remove_ports()
        self.tb.ports_config = backup_config
        self.tb.configure_ports(self.tb.ports_config['real_ports'])

    def __test_port_pfc_watchdog(self, port_attr_setup):
        self.tb = port_attr_setup

        # Set and verify the DLR packet action to FORWARD
        self.tb.set_object_attr(self.tb.switch_id, SAI_SWITCH_ATTR_PFC_DLR_PACKET_ACTION, SAI_PACKET_ACTION_FORWARD, verify=True)
        packet_action = self.tb.get_object_attr(self.tb.switch_id, SAI_SWITCH_ATTR_PFC_DLR_PACKET_ACTION)
        assert packet_action == SAI_PACKET_ACTION_FORWARD

        # Set and verify the packet action to Drop
        self.tb.set_object_attr(self.tb.switch_id, SAI_SWITCH_ATTR_PFC_DLR_PACKET_ACTION, SAI_PACKET_ACTION_DROP, verify=True)
        packet_action = self.tb.get_object_attr(self.tb.switch_id, SAI_SWITCH_ATTR_PFC_DLR_PACKET_ACTION)
        assert packet_action == SAI_PACKET_ACTION_DROP

        # Set the DLD interval for TC 0-7
        map_key_value = [[0, 1, 2, 3, 4, 5, 6, 7], [500, 600, 700, 800, 900, 1000, 1100, 1200]]
        self.tb.set_object_attr(self.tb.switch_id, SAI_SWITCH_ATTR_PFC_TC_DLD_INTERVAL, map_key_value, verify=True)

        # Get and verify DLD interval to TC 4
        map_list = self.tb.get_object_attr(self.tb.switch_id, SAI_SWITCH_ATTR_PFC_TC_DLD_INTERVAL)
        key_list = map_list[0]
        val_list = map_list[1]
        assert key_list[4] == 4
        assert val_list[4] == 900

        # Set the DLR interval for TC 0-7
        map_key_value = [[0, 1, 2, 3, 4, 5, 6, 7], [600, 700, 800, 900, 1000, 1100, 1200, 1300]]
        self.tb.set_object_attr(self.tb.switch_id, SAI_SWITCH_ATTR_PFC_TC_DLR_INTERVAL, map_key_value, verify=True)

        # Get and verify DLR interval to TC 3
        map_list = self.tb.get_object_attr(self.tb.switch_id, SAI_SWITCH_ATTR_PFC_TC_DLR_INTERVAL)
        key_list = map_list[0]
        val_list = map_list[1]
        assert key_list[3] == 3
        assert val_list[3] == 900

        # Get and verify DLD interval range
        min, max = self.tb.get_object_attr(self.tb.switch_id, SAI_SWITCH_ATTR_PFC_TC_DLD_INTERVAL_RANGE)
        assert min == 500
        assert max == 1200

        # Get and verify DLR interval range
        min, max = self.tb.get_object_attr(self.tb.switch_id, SAI_SWITCH_ATTR_PFC_TC_DLR_INTERVAL_RANGE)
        assert min == 600
        assert max == 1300

        # Get the 1st real_ports and find its SAI ID.
        test_port_cfg = self.tb.ports_config['real_ports'][0]
        port_obj_id = self.tb.ports[test_port_cfg['pif']]

        # enable PFC priority 1, 3, 5, 7
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0xaa, verify=True)
        fc_val = self.tb.get_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL)

        # enable PFC priority 1, 3, 5 and 7
        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0xaa, verify=True)

        queue_list = self.tb.get_object_attr(port_obj_id, SAI_PORT_ATTR_QOS_QUEUE_LIST)
        self.tb.set_object_attr(queue_list[1], SAI_QUEUE_ATTR_ENABLE_PFC_DLDR, True, verify=True)
        self.tb.set_object_attr(queue_list[3], SAI_QUEUE_ATTR_ENABLE_PFC_DLDR, True, verify=True)
        self.tb.set_object_attr(queue_list[5], SAI_QUEUE_ATTR_ENABLE_PFC_DLDR, True, verify=True)
        self.tb.set_object_attr(queue_list[7], SAI_QUEUE_ATTR_ENABLE_PFC_DLDR, True, verify=True)

        # Set the DLD interval for TC 0-7
        map_key_value = [[0, 1, 2, 3, 4, 5, 6, 7], [1500, 1600, 1700, 1800, 1900, 2000, 2100, 2200]]
        self.tb.set_object_attr(self.tb.switch_id, SAI_SWITCH_ATTR_PFC_TC_DLD_INTERVAL, map_key_value, verify=True)

        # Set the DLR interval for TC 0-7
        map_key_value = [[0, 1, 2, 3, 4, 5, 6, 7], [1600, 1700, 1800, 1900, 2000, 2100, 2200, 2300]]
        self.tb.set_object_attr(self.tb.switch_id, SAI_SWITCH_ATTR_PFC_TC_DLR_INTERVAL, map_key_value, verify=True)

        # Get and verify DLD interval range
        min, max = self.tb.get_object_attr(self.tb.switch_id, SAI_SWITCH_ATTR_PFC_TC_DLD_INTERVAL_RANGE)
        assert min == 1500
        assert max == 2200

        # Get and verify DLR interval range
        min, max = self.tb.get_object_attr(self.tb.switch_id, SAI_SWITCH_ATTR_PFC_TC_DLR_INTERVAL_RANGE)
        assert min == 1600
        assert max == 2300

        pfc_enabled = self.tb.get_object_attr(queue_list[1], SAI_QUEUE_ATTR_ENABLE_PFC_DLDR)
        assert pfc_enabled
        pfc_enabled = self.tb.get_object_attr(queue_list[3], SAI_QUEUE_ATTR_ENABLE_PFC_DLDR)
        assert pfc_enabled

        pfc_enabled = self.tb.get_object_attr(queue_list[5], SAI_QUEUE_ATTR_ENABLE_PFC_DLDR)
        assert pfc_enabled
        pfc_enabled = self.tb.get_object_attr(queue_list[7], SAI_QUEUE_ATTR_ENABLE_PFC_DLDR)
        assert pfc_enabled

        self.tb.set_object_attr(queue_list[1], SAI_QUEUE_ATTR_ENABLE_PFC_DLDR, False, verify=True)
        self.tb.set_object_attr(queue_list[3], SAI_QUEUE_ATTR_ENABLE_PFC_DLDR, False, verify=True)
        self.tb.set_object_attr(queue_list[5], SAI_QUEUE_ATTR_ENABLE_PFC_DLDR, False, verify=True)
        self.tb.set_object_attr(queue_list[7], SAI_QUEUE_ATTR_ENABLE_PFC_DLDR, False, verify=True)

        self.tb.set_object_attr(port_obj_id, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0, verify=True)
