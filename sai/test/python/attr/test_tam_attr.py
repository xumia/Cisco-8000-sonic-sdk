#!/usr/bin/env python3
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

import pytest
import time
from leaba import sdk
from leaba.debug import debug_device
import lldcli
from saicli import *
from sai_test_utils import *
import sai_test_utils as st_utils


@pytest.mark.usefixtures("base_v4_topology")
class Test_TAM_attr():
    # TAM objects
    tam_id = 0
    tam_event_id = 0
    tam_eventact_id = 0
    tam_report_id = 0

    def generate_ecc_mbe(self, dd, idx):
        '''
        we will use hw initiate 2b ecc error function and read the memory to generate a 2bit ecc error notification.
        '''
        # register bit definition.
        # ene_macro_memory_ecc_2b_err_initiate [0:0] = 0x0
        # rmep_last_time_ecc_2b_err_initiate [1:1] = 0x0
        # rmep_state_table_ecc_2b_err_initiate [2:2] = 0x0
        # mp_data_table_ecc_2b_err_initiate [3:3] = 0x0
        # aux_data_table_ecc_2b_err_initiate [4:4] = 0x0
        # event_queue_ecc_2b_err_initiate [5:5] = 0x0
        # packet_data_table_ecc_2b_err_initiate [6:6] = 0x0
        # eth_mp_em_verifier0_ecc_2b_err_initiate [7:7] = 0x0
        # eth_mp_em_verifier1_ecc_2b_err_initiate [8:8] = 0x0
        # eth_mp_em_verifier2_ecc_2b_err_initiate [9:9] = 0x0
        # eth_mp_em_verifier3_ecc_2b_err_initiate [10:10] = 0x0
        reg = dd.read_register(dd.device_tree.npuh.host.ecc_2b_err_initiate_register)

        reg.mp_data_table_ecc_2b_err_initiate = 1
        dd.write_register(dd.device_tree.npuh.host.ecc_2b_err_initiate_register, reg)

        mem_line = idx % 8
        mp_table_entry = dd.read_memory(dd.device_tree.npuh.host.mp_data_table, mem_line)

        reg.mp_data_table_ecc_2b_err_initiate = 0
        dd.write_register(dd.device_tree.npuh.host.ecc_2b_err_initiate_register, reg)

        pytest.tb.log('generate_ecc_error, mp_date_table 2b error initiated.')

    def generate_ecc_sbe(self, dd, idx):
        '''
        we will use hw initiate 1b ecc error function and read the memory to generate a 2bit ecc error notification.
        '''
        # register bit definition.
        reg = dd.read_register(dd.device_tree.npuh.host.ecc_1b_err_initiate_register)

        reg.mp_data_table_ecc_1b_err_initiate = 1
        dd.write_register(dd.device_tree.npuh.host.ecc_1b_err_initiate_register, reg)

        mem_line = idx % 8
        mp_table_entry = dd.read_memory(dd.device_tree.npuh.host.mp_data_table, mem_line)

        reg.mp_data_table_ecc_1b_err_initiate = 0
        dd.write_register(dd.device_tree.npuh.host.ecc_1b_err_initiate_register, reg)

        pytest.tb.log('generate_ecc_error, mp_date_table 1b error initiated.')

    def generate_mem_protect_error_using_bypass(self, block, mem, mem_entry, bad_bits):
        ldev = self.ldev
        block_id = mem.get_block_id()
        addr = mem.get_desc().addr + mem_entry
        width_total_bits = mem.get_desc().width_total_bits

        # For CONFIG memories, reads are terminated in shadow and do not reach the HW.
        # For DYNAMIC memories, reads bypass the shadow and go directly to HW.
        #
        # Since mem_protect error is generated on HW read, we use read_memory_raw() to reach the HW both
        # for CONFIG and DYNAMIC memories

        # Read the initial value with ECC/Parity
        val_initial = ldev.read_memory_raw(block_id, addr, width_total_bits)
        pytest.tb.log('generate_mem_protect_error_using_bypass: val_initial=%x' % val_initial)

        # Write a value with known good ECC/Parity and a payload with deliberately corrupted 'bad_bits' bits
        # Set/clear CifProtGenBypass bit to disable/enable HW ECC/Parity generation - ECC/Parity and payload are written by host
        ldev.write_register(block.memory_prot_bypass, 0x2)
        ldev.write_memory_raw(block_id, addr, width_total_bits, val_initial ^ ((1 << bad_bits) - 1))
        ldev.write_register(block.memory_prot_bypass, 0x0)

        pytest.tb.log('generate_mem_protect_error_using_bypass: val_corrupted=%x' % (val_initial ^ ((1 << bad_bits) - 1)))

        # The 1st read_memory_raw should generate a mem_protect error, which is expected to be fixed by SDK if the memory is CONFIG
        # The 2nd read_memory_raw should only generate a mem_protect error for non-CONFIG memory

        val_read_1 = None
        val_read_2 = None
        err_1 = sdk.la_status_e_SUCCESS
        err_2 = sdk.la_status_e_SUCCESS

        try:
            val_read_1 = ldev.read_memory_raw(block_id, addr, width_total_bits)
        except sdk.BaseException as e:
            err_1 = int(str(e))
        time.sleep(0.01)

        try:
            val_read_2 = ldev.read_memory_raw(block_id, addr, width_total_bits)
        except sdk.BaseException as e:
            err_2 = int(str(e))

        time.sleep(0.01)

        return {'initial': val_initial, 'err_1': err_1, 'read_1': val_read_1, 'err_2': err_2, 'read_2': val_read_2}

    def check_and_clear_ref_counters(self, total_msg, sbe, mbe, parity, decode_err):
        tam_event_msg = get_sai_tam_event_msg_counts(self.tam_id)
        pytest.tb.log("message counts for tam_id ({}) = {}, expected ({})".format(self.tam_id, tam_event_msg, total_msg))
        pytest.tb.log(
            "Total SBE Counts({}), MBE Counts({}), Parrity Counts({}), Decode Error({})".format(
                cvar.sai_tam_event_ecc_cor_counter,
                cvar.sai_tam_event_ecc_uncor_counter,
                cvar.sai_tam_event_parity_counter,
                cvar.sai_tam_event_decode_error))

        assert (tam_event_msg == total_msg)
        assert (cvar.sai_tam_event_ecc_cor_counter == sbe)
        assert (cvar.sai_tam_event_ecc_uncor_counter == mbe)
        assert (cvar.sai_tam_event_parity_counter == parity)
        assert (cvar.sai_tam_event_decode_error == decode_err)

        # clear and check total
        set_sai_tam_event_msg_counts(self.tam_id, 0)
        assert (get_sai_tam_event_msg_total_counts() == 0)
        clear_sai_tam_event_msg_counts()
        cvar.sai_tam_event_ecc_cor_counter = 0
        cvar.sai_tam_event_ecc_uncor_counter = 0
        cvar.sai_tam_event_parity_counter = 0
        cvar.sai_tam_event_decode_error = 0

    def setup_tam_objects(self):
        pytest.tb.log('****setup_tam_objects: Started')

        # setup report
        attrs = []
        attrs.append([SAI_TAM_REPORT_ATTR_TYPE, SAI_TAM_REPORT_TYPE_VENDOR_EXTN])
        attrs.append([SAI_TAM_REPORT_ATTR_REPORT_MODE, SAI_TAM_REPORT_MODE_ALL])

        self.tam_report_id = pytest.tb.obj_wrapper.create_object(
            SAI_OBJECT_TYPE_TAM_REPORT, pytest.tb.switch_id, attrs, [True, False])

        # setup event_action
        attrs = []
        attrs.append([SAI_TAM_EVENT_ACTION_ATTR_REPORT_TYPE, self.tam_report_id])
        self.tam_eventact_id = pytest.tb.obj_wrapper.create_object(
            SAI_OBJECT_TYPE_TAM_EVENT_ACTION, pytest.tb.switch_id, attrs, [True, False])

        # setup event
        attrs = []
        # SAI_TAM_EVENT_TYPE_SWITCH is 12... (new attribute)
        attrs.append([SAI_TAM_EVENT_ATTR_TYPE, 12])

        event_type_list = [SAI_SWITCH_EVENT_TYPE_PARITY_ERROR, SAI_SWITCH_EVENT_TYPE_STABLE_FULL]
        attrs.append([SAI_TAM_EVENT_ATTR_SWITCH_EVENT_TYPE, event_type_list])

        event_action_list = [self.tam_eventact_id]
        attrs.append([SAI_TAM_EVENT_ATTR_ACTION_LIST, event_action_list])

        event_collector_list = []
        attrs.append([SAI_TAM_EVENT_ATTR_COLLECTOR_LIST, event_collector_list])

        self.tam_event_id = pytest.tb.obj_wrapper.create_object(
            SAI_OBJECT_TYPE_TAM_EVENT, pytest.tb.switch_id, attrs, [True, False])

        # setup tam
        attrs = []

        event_list = [self.tam_event_id]
        attrs.append([SAI_TAM_ATTR_EVENT_OBJECTS_LIST, event_list])

        bind_point_list = [SAI_TAM_BIND_POINT_TYPE_SWITCH]
        attrs.append([SAI_TAM_ATTR_TAM_BIND_POINT_TYPE_LIST, bind_point_list])

        self.tam_id = pytest.tb.obj_wrapper.create_object(SAI_OBJECT_TYPE_TAM, pytest.tb.switch_id, attrs, [True, False])

        # register tam in Switch
        tam_list = [self.tam_id]
        pytest.tb.set_object_attr(pytest.tb.switch_id, SAI_SWITCH_ATTR_TAM_OBJECT_ID, tam_list, True)

        pytest.tb.log('****setup_tam_objects: Ended')

    def destroy_tam_objects(self):
        pytest.tb.log('****destroy_tam_objects: Started')
        # removed tam object from registry (remove from switch)
        pytest.tb.set_object_attr(pytest.tb.switch_id, SAI_SWITCH_ATTR_TAM_OBJECT_ID, [], False)
        pytest.tb.obj_wrapper.remove_object(self.tam_id)
        pytest.tb.obj_wrapper.remove_object(self.tam_event_id)
        pytest.tb.obj_wrapper.remove_object(self.tam_eventact_id)
        pytest.tb.obj_wrapper.remove_object(self.tam_report_id)
        pytest.tb.log('****destroy_tam_objects: Ended')

    def test_tam_bind(self):
        self.setup_tam_objects()
        # run WB 2 times.
        pytest.tb.do_warm_boot()
        pytest.tb.do_warm_boot()
        pytest.tb.log('****test_tam_attr: Started')

        # check default value
        assert 1000 == pytest.tb.get_object_attr(self.tam_report_id, SAI_TAM_REPORT_ATTR_REPORT_INTERVAL)

        # check report get/set
        pytest.tb.set_object_attr(self.tam_report_id, SAI_TAM_REPORT_ATTR_TYPE, SAI_TAM_REPORT_TYPE_VENDOR_EXTN, True)

        int_time = 2500
        pytest.tb.set_object_attr(self.tam_report_id, SAI_TAM_REPORT_ATTR_REPORT_INTERVAL, int_time, True)

        # event_action bind/unbind, destory reporter
        attrs = []
        attrs.append([SAI_TAM_REPORT_ATTR_TYPE, SAI_TAM_REPORT_TYPE_VENDOR_EXTN])
        attrs.append([SAI_TAM_REPORT_ATTR_REPORT_MODE, SAI_TAM_REPORT_MODE_ALL])
        new_report_id = pytest.tb.obj_wrapper.create_object(SAI_OBJECT_TYPE_TAM_REPORT, pytest.tb.switch_id, attrs, [True, False])

        # bind to new reporter
        pytest.tb.set_object_attr(self.tam_eventact_id, SAI_TAM_EVENT_ACTION_ATTR_REPORT_TYPE, new_report_id, True)

        # bind to original report
        pytest.tb.set_object_attr(self.tam_eventact_id, SAI_TAM_EVENT_ACTION_ATTR_REPORT_TYPE, self.tam_report_id, True)

        # remove the new_reporter
        pytest.tb.obj_wrapper.remove_object(new_report_id)

        # check event object get/set
        event_type_list = [SAI_SWITCH_EVENT_TYPE_NONE]
        pytest.tb.set_object_attr(self.tam_event_id, SAI_TAM_EVENT_ATTR_SWITCH_EVENT_TYPE, event_type_list, True)

        event_type_list = [SAI_SWITCH_EVENT_TYPE_PARITY_ERROR, SAI_SWITCH_EVENT_TYPE_UNCONTROLLED_SHUTDOWN]
        pytest.tb.set_object_attr(self.tam_event_id, SAI_TAM_EVENT_ATTR_SWITCH_EVENT_TYPE, event_type_list, True)

        # check tam get/set
        event_list = [self.tam_event_id]
        pytest.tb.set_object_attr(self.tam_id, SAI_TAM_ATTR_EVENT_OBJECTS_LIST, event_list, True)

        pytest.tb.log('****test_tam_attr: Ended')
        self.destroy_tam_objects()

    @pytest.mark.skipif(not is_hw_device(), reason="The test applicable only in HW devices.")
    def test_parity_notification(self):
        # only test ecc notification in hw since we can't generate ecc error in nsim.
        st_utils.skipIf(not pytest.tb.is_hw())

        self.setup_tam_objects()
        pytest.tb.log('****test_parity_notification: Started')

        self.ldev = pytest.tb.la_device.get_ll_device()
        if self.ldev.is_gibraltar():
            pt = self.ldev.get_gibraltar_tree()
        else:
            pt = self.ldev.get_pacific_tree()

        # memory is CONFIG and ECC protected
        block = pt.slice[0].pdoq.top
        mem = block.oq_ifc_mapping
        mem_entry = 0

        # threshold = 100
        # times_to_cross = 3
        total_err = 7
        mbe_count = 0
        for i in range(total_err):
            if (i % 2):
                self.generate_mem_protect_error_using_bypass(block, mem, mem_entry, 2)
                mbe_count += 1
            else:
                self.generate_mem_protect_error_using_bypass(block, mem, mem_entry, 1)
            time.sleep(0.05)

        # clear and check total
        self.check_and_clear_ref_counters(total_err, (total_err - mbe_count), mbe_count, 0, 0)

        pytest.tb.log('****test_parity_notification: Ended')
        self.destroy_tam_objects()

    @pytest.mark.skipif(not is_hw_device(), reason="The test applicable only in HW devices.")
    def test_ecc_notification(self):
        # only test ecc notification in hw since we can't generate ecc error in nsim.
        st_utils.skipIf(not pytest.tb.is_hw())

        self.setup_tam_objects()
        pytest.tb.log('****test_ecc_notification: Started')

        dd = debug_device(pytest.tb.la_device)

        # threshold = 100
        # times_to_cross = 3
        total_err = 5
        mbe_count = 0
        for i in range(total_err):
            if (i % 2):
                self.generate_ecc_mbe(dd, i)
                mbe_count += 1
            else:
                self.generate_ecc_sbe(dd, i)
            time.sleep(0.05)

        # clear and check total
        self.check_and_clear_ref_counters(total_err, (total_err - mbe_count), mbe_count, 0, 0)

        pytest.tb.log('****test_ecc_notification: Ended')
        self.destroy_tam_objects()

    @pytest.mark.skipif(not is_hw_device(), reason="The test applicable only in HW devices.")
    def test_ecc_inject_attr(self):
        # only test ecc notification in hw since we can't generate ecc error in nsim.
        st_utils.skipIf(not pytest.tb.is_hw())

        self.setup_tam_objects()

        # test SAI_SWITCH_EVENT_TYPE_ALL attribute.
        event_type_list = [SAI_SWITCH_EVENT_TYPE_ALL]
        pytest.tb.set_object_attr(self.tam_event_id, SAI_TAM_EVENT_ATTR_SWITCH_EVENT_TYPE, event_type_list, True)
        pytest.tb.log('**** Changed SAI_SWITCH_EVENT_TYPE to ALL.')

        pytest.tb.log('****test_ecc_inject_attr: Started')

        # inject ecc error
        total_err = 5
        mbe_count = 0
        for i in range(total_err):
            if (i % 2):
                pytest.tb.set_object_attr(pytest.tb.switch_id, SAI_SWITCH_ATTR_EXT_HW_ECC_ERROR_INITIATE, 2, False)
                mbe_count += 1
            else:
                pytest.tb.set_object_attr(pytest.tb.switch_id, SAI_SWITCH_ATTR_EXT_HW_ECC_ERROR_INITIATE, 1, False)
            time.sleep(1)

        # clear and check total
        self.check_and_clear_ref_counters(total_err, (total_err - mbe_count), mbe_count, 0, 0)

        pytest.tb.log('****test_ecc_inject_attr: Ended')
        self.destroy_tam_objects()

    def test_switch_remove(self):
        '''
        only setup the tam objects.
        And exit the test. lsai_device::clean() should be called and all tam should be destroyed
        '''
        self.setup_tam_objects()
