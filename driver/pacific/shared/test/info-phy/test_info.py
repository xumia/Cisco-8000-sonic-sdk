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

import unittest
from leaba import sdk
import info_phycli
import lldcli
import os
import decor
from time import sleep
import time
from leaba import debug

PLL_RETRIES = 10


class info_phy_test(unittest.TestCase):

    def setUp(self):
        pass

    def test_info_create_and_write(self):
        os.environ['ASIC'] = 'ASIC3_A0'
        dev_id = 0
        dev_path = os.getenv('SDK_DEVICE_NAME')
        self.ldev = sdk.la_create_device("/dev/uio0", 0)

        self.ldev.set_bool_property(sdk.la_device_property_e_IGNORE_MBIST_ERRORS, True)
        self.ldev.set_bool_property(sdk.la_device_property_e_PROCESS_INTERRUPTS, False)

        self.dd = debug.debug_device(self.ldev)

        ll_dev = self.ldev.get_ll_device()
        self.ll_dev = ll_dev
        ll_dev.set_shadow_read_enabled(False)

        ll_dev.reset()
        ll_dev.reset_access_engines()
        ll_dev.set_flush_after_write(True)

        d2d = lldcli.d2d_iface_create(ll_dev)
        d2d.initialize()

        tree = ll_dev.get_asic3_tree()
        self.tree = tree

        sid = 0
        self.info_dev = info_phycli.info_create(ll_dev)
        self.all_bricks = []
        self.all_bricks_regs = []
        self.main_bricks = []
        self.asic7_bricks = []
        self.main_bricks_regs = []
        self.asic7_bricks_regs = []
        for sid in range(8):
            slice_bricks = []
            main_bricks = []
            asic7_bricks = []
            slice_bricks_regs = []
            main_bricks_regs = []
            asic7_bricks_regs = []
            NUM_BRICKS = 4
            ll_dev.write_register(tree.slice[sid].info_pool.cfg.soft_reset_configuration, 1)
            ll_dev.write_register(tree.slice[sid].asic7.info_pool_cfg.soft_reset_configuration, 1)

            time.sleep(1)

            for i in range(NUM_BRICKS):
                main_bricks.append(self.info_dev.get_info_brick_handler(sid * 4 + i))
                asic7_bricks.append(self.info_dev.get_info_brick_handler(32 + sid * 4 + i))
                slice_bricks.append(main_bricks[i])
                slice_bricks.append(asic7_bricks[i])
                main_bricks_regs.append(tree.slice[sid].info_pool.brick[i])
                asic7_bricks_regs.append(tree.slice[sid].asic7.brick[i])
                slice_bricks_regs.append(main_bricks_regs[i])
                slice_bricks_regs.append(asic7_bricks_regs[i])

                ll_dev.write_register(tree.slice[sid].info_pool.brick[i].top.soft_reset_configuration, 1)
                ll_dev.write_register(tree.slice[sid].asic7.brick[i].top.soft_reset_configuration, 1)

            time.sleep(1)
            self.main_bricks.append(main_bricks)
            self.asic7_bricks.append(asic7_bricks)
            self.main_bricks_regs.append(main_bricks_regs)
            self.asic7_bricks_regs.append(asic7_bricks_regs)
            self.all_bricks.append(slice_bricks)
            self.all_bricks_regs.append(slice_bricks_regs)

        NUM_OF_SLICE = 8
        for sid in range(NUM_OF_SLICE):
            self.initialize_pll(self.all_bricks[sid])
            time.sleep(1)
            self.initialize_bricks(self.all_bricks[sid])
            self.check_clocks(self.all_bricks_regs[sid], True)

            self.calibrate_bricks(self.all_bricks[sid], sdk.la_info_phy_brick_handler.FULL_CAL)

        for sid in range(NUM_OF_SLICE):
            self.activate_bricks(self.all_bricks[sid])

    def initialize_pll(self, bricks):
        for brick in bricks:
            brick.initialize_pll(6500)

        done = self.check_pll(bricks)
        self.assertTrue(done)

    def _check_pll(self, bricks):
        done = True
        for i in range(PLL_RETRIES):
            for brick in bricks:
                done = done and brick.get_pll_locked()
            if done:
                break
            sleep(0.01)
        if not done:
            for brick in bricks:
                lock = brick.get_pll_locked()
                if not lock:
                    print("Brick ID={} has no PLL Lock".format(brick.get_brick_id()))
        return done

    def check_pll(self, bricks):
        done = True
        if isinstance(bricks[0], list):
            for bb in bricks:
                done = done and self._check_pll(bb)
        else:
            done = self._check_pll(bricks)
        return done

    def initialize_bricks(self, bricks):
        tt = 0.1

        for brick in bricks:
            brick.initialize_analog(sdk.la_info_phy_brick_handler.info_lane_direction_e_TX)
        sleep(tt)
        for brick in bricks:
            brick.enable_clocks(sdk.la_info_phy_brick_handler.info_lane_direction_e_TX)
        sleep(tt)

        for brick in bricks:
            brick.initialize_analog(sdk.la_info_phy_brick_handler.info_lane_direction_e_RX)
        sleep(tt)
        for brick in bricks:
            brick.enable_clocks(sdk.la_info_phy_brick_handler.info_lane_direction_e_RX)
        sleep(tt)

        for brick in bricks:
            brick.enable_synchronization_chain(sdk.la_info_phy_brick_handler.info_lane_direction_e_TX, True)
            brick.enable_synchronization_chain(sdk.la_info_phy_brick_handler.info_lane_direction_e_RX, True)

        sleep(tt)
        for brick in bricks:
            brick.enable_synchronization_chain(sdk.la_info_phy_brick_handler.info_lane_direction_e_TX, False)
            brick.enable_synchronization_chain(sdk.la_info_phy_brick_handler.info_lane_direction_e_RX, False)

        for brick in bricks:
            brick.initialize_digital(sdk.la_info_phy_brick_handler.info_lane_direction_e_TX)
        sleep(tt)

        for brick in bricks:
            brick.initialize_digital(sdk.la_info_phy_brick_handler.info_lane_direction_e_RX)
        sleep(tt)

    def _check_clocks(self, regs):

        for i in range(len(regs)):
            self.ll_dev.write_register(regs[i].top.info_pmd_clock_counter_fsm, 2000000)
            self.ll_dev.write_register(regs[i].top.info_pmd_clock_counter_fsm, 2000001)
            time.sleep(0.1)
            cnt = self.ll_dev.read_register(regs[i].top.info_pmd_clock_counters)
            clock_count_ifg = cnt & 0xffffffff
            clock_count_rx = (cnt >> 32) & 0xffffffff
            clock_count_tx = (cnt >> 64) & 0xffffffff

            print("Brick={} clock_count_ifg={} clock_count_rx={} clock_count_tx={}".format(
                regs[i].top.info_pmd_clock_counters.get_name(), clock_count_ifg, clock_count_rx, clock_count_tx))

    def _check_regs(self, regs):
        for i in range(len(regs)):
            print(
                "{} = {}".format(
                    regs[i].rx.info_pmd_link0_status_reg[0].get_name(), hex(
                        self.ll_dev.read_register(
                            regs[i].rx.info_pmd_link0_status_reg[0]))))
            print(
                "{} = {}".format(
                    regs[i].tx.info_pmd_tx_link_interrupt_reg.get_name(), hex(
                        self.ll_dev.read_register(
                            regs[i].tx.info_pmd_tx_link_interrupt_reg))))

    def check_clocks(self, regs, check_regs=False):
        if isinstance(regs[0], list):
            for rr in regs:
                self._check_clocks(rr)
        else:
            self._check_clocks(regs)

        if check_regs:
            if isinstance(regs[0], list):
                for rr in regs:
                    self._check_regs(regs)
            else:
                self._check_regs(regs)

    def calibrate_bricks(self, bricks, mode = sdk.la_info_phy_brick_handler.SINGLE_LANE_CAL):
        if isinstance(bricks[0], list):
            for bb in bricks:
                self._calibrate_bricks(bb, mode)
        else:
            self._calibrate_bricks(bricks, mode)

    def _calibrate_bricks(self, bricks, mode = sdk.la_info_phy_brick_handler.SINGLE_LANE_CAL):
        for brick in bricks:
            brick.set_comparator_voltage_offset(0)

        for brick in bricks:
            # brick.calibrate_phase_rotator_iq()
            brick.set_iq_control(95)

        for brick in bricks:
            brick.set_link_mode(sdk.la_info_phy_brick_handler.info_lane_direction_e_TX,
                                sdk.la_info_phy_brick_handler.PRBS)
            brick.set_link_mode(sdk.la_info_phy_brick_handler.info_lane_direction_e_RX,
                                sdk.la_info_phy_brick_handler.PRBS)

        for brick in bricks:
            brick.set_tx_lane_prbs_mode(sdk.la_info_phy_brick_handler.PRBS15, 0xffff)
            brick.set_rx_lane_prbs_mode(sdk.la_info_phy_brick_handler.PRBS15, 0x0)

        for brick in bricks:
            brick.calibrate_phase_rotator_position(mode)

    def activate_bricks(self, bricks):
        if isinstance(bricks[0], list):
            for bb in bricks:
                self._activate_bricks(bb)
        else:
            self._activate_bricks(bricks)

    def _activate_bricks(self, bricks):
        for brick in bricks:
            brick.set_link_mode(sdk.la_info_phy_brick_handler.info_lane_direction_e_TX,
                                sdk.la_info_phy_brick_handler.LANE_TRAINING)
            brick.set_link_mode(sdk.la_info_phy_brick_handler.info_lane_direction_e_RX,
                                sdk.la_info_phy_brick_handler.LANE_TRAINING)

        for brick in bricks:
            brick.wait_for_word_lock()

        self._mission_mode(bricks)

    def mission_mode(self, bricks):
        if isinstance(bricks[0], list):
            for bb in bricks:
                self._mission_mode(bb)
        else:
            self._mission_mode(bricks)

    def _mission_mode(self, bricks):
        for brick in bricks:
            brick.set_mission_mode(sdk.la_info_phy_brick_handler.info_lane_direction_e_TX)
            brick.set_mission_mode(sdk.la_info_phy_brick_handler.info_lane_direction_e_RX)

    def read_prbs_counters(self, bricks):
        for brick in bricks:
            for link in range(2):
                counters = brick.read_rx_link_counters(link)
                print("brick={} link={}:".format(brick.get_brick_id(), link))
                print("link_prbs_err_cnt={} link_crc_err_cnt={} link_ecc2_err_cnt={} link_ecc1_err_cnt={}".format(
                    counters.link_prbs_err_cnt, counters.link_crc_err_cnt, counters.link_ecc2_err_cnt, counters.link_ecc1_err_cnt))

    def check_word_lock(self, bricks):
        for i in range(len(bricks)):
            for link in range(2):
                for lane in range(40):
                    lock = bricks[i].get_word_lock(link, lane)
                    if lock is False:
                        print("brick={} link={} lane={} is not locked".format(bricks[i].get_brick_id(), link, lane))


if __name__ == '__main__':
    # unittest.main()
    tc = info_phy_test()
    tc.setUp()
    tc.test_info_create_and_write()
