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
import srmcli
import apbcli
import lldcli
import os


def is_hw_device():
    return os.getenv('SDK_DEVICE_NAME') == '/dev/uio0'


class testcase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def create_key_payload_from_line(cls, line):
        pass

    def setUp(self):
        os.environ['ASIC'] = 'GIBRALTAR_A0'
        if is_hw_device():
            self.ldev = lldcli.ll_device_create(0, '/dev/uio0')
            self.ldev.reset()
            self.ldev.reset_access_engines()
        else:
            self.ldev = lldcli.ll_device_create(0, '/dev/testdev')
        self.apb_serdes = apbcli.apb_create(self.ldev, apbcli.apb_interface_type_e_SERDES)
        srmcli.srm_set_apb(self.apb_serdes)

    def tearDown(self):
        srmcli.srm_clear_apb(self.apb_serdes)
        self.apb_serdes = None
        self.ldev = None

    # srm_mcu_status_t contains two arrays of uint32_t and one 'const char*' string
    def test_mapping_of_srm_mcu_status_t(self):
        mcu_status = srmcli.srm_mcu_status_t()
        srmcli.srm_mcu_status_query(0, mcu_status, 1000)

        self.assertEqual(mcu_status.fw_mode, 0)
        self.assertEqual(mcu_status.fw_mode_str, 'UNKNOWN')
        self.assertEqual(len(mcu_status.loop_count), 2)
        self.assertEqual(len(mcu_status.pc_trace), 10)
        print('mcu_status.loop_count =', mcu_status.loop_count)
        print('mcu_status.pc_trace =', mcu_status.pc_trace)

    # srm_tx_rules_t contains one array of int16
    def test_mapping_of_srm_tx_rules_t(self):
        tx_rules = srmcli.srm_tx_rules_t()
        self.assertEqual(len(tx_rules.fir_tap), 7)

        cal_rules = srmcli.srm_pwrup_rules_t()
        self.assertEqual(len(cal_rules.srm_dies), srmcli.SRM_CAL_MAX_SRM_PER_ERU)

    # srm_anlt_bundle_t contains an array of structs
    def test_mapping_of_srm_anlt_bundle_t(self):
        anlt = srmcli.srm_anlt_bundle_t()
        # Test array boundaries
        n = anlt.lt_followers_items_n()
        for i in range(n):
            self.assertNotEqual(anlt.lt_followers_item(i), None)
        self.assertEqual(anlt.lt_followers_item(n), None)

        # Test that item 'i' can be modified
        item0 = anlt.lt_followers_item(2)
        item0.tx_die = 42
        item1 = anlt.lt_followers_item(2)
        self.assertEqual(item0.tx_die, item1.tx_die)

    # Test srm_mcu read and write calls
    def test_srm_mcu_rw(self):
        die = 0
        addr = 0x5ffa0000

        pif_buffer = [num for num in range(0, 16)]
        # Write data to buffer, then compare against written data
        srm_status = srmcli.srm_mcu_pif_write(die, addr, pif_buffer)
        buffer_out = srmcli.srm_mcu_pif_read(die, addr, len(pif_buffer))
        for i in range(0, 16):
            if is_hw_device():
                self.assertEqual(buffer_out[i], i)
            else:
                self.assertEqual(buffer_out[i], 0x0)

    # Test that all APIs are callable from Python
    def test_srm_api_without_apb_init(self):
        die = 0
        addr = 0
        channel = 0
        ffe_sub_channel = 0
        data = 0
        mask = 0
        enable = True
        squelch = True
        timeout_in_ms = 0
        timeout_in_usecs = 0
        path = ''
        num_entries = 0
        image_length = 0
        filter = 0
        ack_type = 0
        max_wait = 0
        max_wait_us = 0
        gap = 0
        duration = 0
        snr_val = 0
        fw_dwld_timeout = 1000
        fw_warn_if_mismatched = True
        wait_till_started = True
        verify = True
        tx_rules = srmcli.srm_tx_rules_t()
        rx_rules = srmcli.srm_rx_rules_t()
        pll_rules = srmcli.srm_pll_rules_t()
        cal_rules = srmcli.srm_pwrup_rules_t()
        inv_pol = True

        e_srm_hw_rev = srmcli.srm_hw_rev(die)
        srmcli.srm_reg_write(die, addr, data)
        u32 = srmcli.srm_reg_read(die, addr)
        u32 = srmcli.srm_reg_rmw(die, addr, data, mask)
        u32 = srmcli.srm_reg_channel_read(die, channel, addr)
        srmcli.srm_reg_channel_write(die, channel, addr, data)
        u32 = srmcli.srm_reg_channel_rmw(die, channel, addr, data, mask)
        u32 = srmcli.srm_reg_channel_addr(die, channel, addr)
        srm_status = srmcli.srm_mcu_reset_into_application(die, wait_till_started)
        fw_mode = srmcli.srm_mcu_fw_mode_query(die)
        ok = srmcli.srm_is_fw_running_ok(die)
        srm_status = srmcli.srm_mcu_block_application_mode(die, timeout_in_ms)
        srm_status = srmcli.srm_mcu_download_firmware(die, verify)
        u32 = srmcli.srm_mcu_get_inline_firmware_version()
        # TODO srm_status_t srmcli.srm_mcu_verify_image(die, const uint32_t* image, uint32_t image_length);
        srm_status = srmcli.srm_mcu_download_firmware_from_file(die, path, verify)
        mcu_status = srmcli.srm_mcu_status_t()
        srmcli.srm_mcu_status_query(die, mcu_status, 1000)
        srm_status = srmcli.srm_mcu_status_query_dump(die)
        # TODO srm_status = srmcli.srm_mcu_pc_log_query(die, uint32_t* entries, num_entries);
        srm_status = srmcli.srm_mcu_pc_log_query_dump(die, num_entries)
        srm_status = srmcli.srm_mcu_debug_log_dump(die, "hello")
        srm_status = srmcli.srm_mcu_debug_log_query_dump(die)
        # TODO srm_status = srmcli.srm_mcu_pc_log_query(die, uint32_t* entries, num_entries);
        u32 = srmcli.srm_mcu_debug_log_filter_get(die)
        srm_status = srmcli.srm_mcu_debug_log_filter_set(die, filter)
        srm_status = srmcli.srm_mcu_pc_log_query_dump(die, num_entries)
        srm_status = srmcli.srm_mcu_debug_log_query_dump(die)
        string = srmcli.srm_version()
        string = srmcli.srm_version_firmware(die)

        tx_rules.enable = True
        tx_rules.gray_mapping = True
        srm_status = srmcli.srm_tx_rules_set_default(tx_rules)
        srm_status = srmcli.srm_rx_rules_set_default(rx_rules)
        srm_status = srmcli.srm_pll_rules_set_default(pll_rules)
        srm_status = srmcli.srm_rules_set_default(pll_rules, tx_rules, rx_rules)
        srm_status = srmcli.srm_init(die)
        srm_status = srmcli.srm_init_pll(die, pll_rules)
        srm_status = srmcli.srm_init_tx(die, channel, tx_rules)
        srm_status = srmcli.srm_init_rx(die, channel, rx_rules)
        ok = srmcli.srm_is_ack_asserted(die, channel, srmcli.SRM_ACK_CHP_INIT)
        srm_status = srmcli.srm_wait_for_ack(die, channel, ack_type, max_wait_us)
        srm_status = srmcli.srm_pll_rules_query(die, pll_rules)
        srm_status = srmcli.srm_tx_rules_query(die, channel, tx_rules)
        srm_status = srmcli.srm_rx_rules_query(die, channel, rx_rules)
        srm_status = srmcli.srm_soft_reset(die)
        srmcli.srm_pll_rules_dump(die, pll_rules)
        srm_status = srmcli.srm_pll_rules_query_dump(die)
        srmcli.srm_tx_rules_dump(die, channel, tx_rules)
        srm_status = srmcli.srm_tx_rules_query_dump(die, channel)
        srmcli.srm_rx_rules_dump(die, channel, rx_rules)
        srm_status = srmcli.srm_rx_rules_query_dump(die, channel)
        srm_status = srmcli.srm_cal_rules_set_default(cal_rules)
        srm_status = srmcli.srm_cal_start(cal_rules)
        ok = srmcli.srm_cal_is_bias_ready(die)
        ok = srmcli.srm_cal_is_eru_ready(die)
        ok = srmcli.srm_cal_is_ready(cal_rules)
        srm_status = srmcli.srm_loopback_set(die, channel, srmcli.SRM_LOOPBACK_CORE_NEAR, enable)
        srm_status = srmcli.srm_wait_for_link_ready(die, channel, timeout_in_usecs)
        ok = srmcli.srm_is_link_ready(die, channel, srmcli.SRM_INTF_DIR_TX)
        ok = srmcli.srm_is_pll_locked(die)
        srm_status = srmcli.srm_wait_for_pll_locked(die, timeout_in_usecs)
        ok = srmcli.srm_is_tx_ready(die, channel)
        ok = srmcli.srm_tx_ready_get(die, channel)
        ok = srmcli.srm_is_rx_ready(die, channel)
        ok = srmcli.srm_rx_ready_get(die, channel)
        link_status = srmcli.srm_link_status_t()
        srm_status = srmcli.srm_link_status_query(die, channel, srmcli.SRM_INTF_DIR_TX, link_status)
        srm_status = srmcli.srm_link_status_print(die, channel, srmcli.SRM_INTF_DIR_TX, link_status)
        srm_status = srmcli.srm_link_status_query_dump(die, channel, srmcli.SRM_INTF_DIR_TX)
        srm_status = srmcli.srm_rx_encoding_set(die, channel, srmcli.SRM_SIGNAL_MODE_NRZ)
        srm_status = srmcli.srm_rx_polarity_set(die, channel, inv_pol)
        srm_status = srmcli.srm_rx_power_down_set(die, channel)
        srm_status = srmcli.srm_rx_equalization_set(die, channel, srmcli.SRM_DSP_MODE_DFE1_RC_DFE2)
        srm_status = srmcli.srm_rx_invert_toggle(die, channel)
        srm_status = srmcli.srm_dbg_force_dsp_relock(die, channel)
        srm_status = srmcli.srm_tx_fir_set_default(srmcli.srm_tx_fir_t())
        srm_status = srmcli.srm_tx_set(die, channel, tx_rules)
        srm_status = srmcli.srm_tx_encoding_set(die, channel, srmcli.SRM_SIGNAL_MODE_NRZ)
        srm_status = srmcli.srm_tx_polarity_set(die, channel, inv_pol)

        fir_tap = [0, 1, 2, 3, 4, 5, 6]
        srm_status = srmcli.srm_tx_equalization_set(die, channel, fir_tap)

        srm_status = srmcli.srm_tx_power_down_set(die, channel)

        fir = srmcli.srm_tx_fir_t()
        fir.set_fir_tap([0, 1, 2, 3, 4, 5, 6])
        srm_status = srmcli.srm_tx_fir_query(die, channel, fir)
        srm_status = srmcli.srm_tx_fir_set(die, channel, fir)

        srmcli.srm_tx_fir_tap_dump(srmcli.srm_tx_fir_t())
        srmcli.srm_tx_fir_7tap_lin_query_dump(die)
        srmcli.srm_tx_fir_3tap_lut_query_dump(die, channel)
        ok = srmcli.srm_tx_is_squelched(die, channel)
        srm_status = srmcli.srm_tx_squelch(die, channel, squelch)
        srm_status = srmcli.srm_tx_squelch_set(die, channel, enable)
        srm_status = srmcli.srm_tx_invert_toggle(die, channel)
        srm_status = srmcli.srm_prbs_gen_rules_set_default(srmcli.srm_prbs_gen_rules_t())
        srm_status = srmcli.srm_prbs_chk_rules_set_default(srmcli.srm_prbs_chk_rules_t())
        srm_status = srmcli.srm_prbs_gen_config(die, channel, srmcli.SRM_INTF_DIR_TX, srmcli.srm_prbs_gen_rules_t())
        srm_status = srmcli.srm_prbs_chk_config(die, channel, srmcli.SRM_INTF_DIR_TX, srmcli.srm_prbs_chk_rules_t())
        ok = srmcli.srm_prbs_chk_is_enabled(die, channel, srmcli.SRM_INTF_DIR_TX)

        chk_status = srmcli.srm_prbs_chk_status_t()
        srm_status = srmcli.srm_prbs_chk_status(die, channel, srmcli.SRM_INTF_DIR_TX, chk_status)

        ber = srmcli.srm_prbs_ber_t()
        srm_status = srmcli.srm_prbs_chk_ber(chk_status, ber)
        srm_status = srmcli.srm_prbs_chk_status_print(die, channel, srmcli.SRM_INTF_DIR_TX, chk_status)
        srm_status = srmcli.srm_prbs_chk_status_query_print(die, channel, srmcli.SRM_INTF_DIR_TX)
        srm_status = srmcli.srm_prbs_gen_error_inject(die,
                                                      channel,
                                                      enable,
                                                      srmcli.SRM_ERRINJ_PAT_WALK3,
                                                      gap,
                                                      duration)
        srmcli.srm_rx_dsp_snr_mon_en(die, channel, enable)
        ok = srmcli.srm_rx_dsp_snr_mon_enabled(die, channel)
        srmcli.srm_rx_dsp_snr_mon_cfg(die, channel, 0, 0)
        u16 = srmcli.srm_rx_dsp_snr_read_value(die, channel)
        u32 = srmcli.srm_rx_dsp_snr_read_db_fixp(die, channel)
        double = srmcli.srm_rx_dsp_snr_format(snr_val, srmcli.SRM_SIGNAL_MODE_NRZ)
        double = srmcli.srm_rx_dsp_snr_read_db(die, channel)

        ffe_taps = srmcli.ffe_taps_t()
        srm_status = srmcli.srm_rx_dsp_ffe_taps_query(die, channel, ffe_sub_channel, ffe_taps)
        string = srmcli.srm_rx_dsp_dbg_translate_ffe_tap_index(srmcli.SRM_FFE_TAP_POST_CURSOR_5)
        srm_status = srmcli.srm_rx_dsp_ffe_taps_print(die, channel, ffe_sub_channel, ffe_taps)

        hist = srmcli.hist_data_t()
        srm_status = srmcli.srm_rx_dsp_get_histogram(die, channel, 0, hist)
        srm_status = srmcli.srm_rx_dsp_get_histogram_bypass(die, channel, 0, hist)
        srm_status = srmcli.srm_mcu_msg_rx_hist_request(die, channel, 0, hist)
        srm_status = srmcli.srm_rx_dsp_hist_ascii_plot(die, channel, hist)

        srm_status = srmcli.srm_rx_dsp_hist_query_dump(die, channel, 0)
        srm_status = srmcli.srm_rx_dsp_hist_query_dump_to_file(die, channel, 0, path)
        srm_status = srmcli.srm_diags_register_dump(die)

        fw_info = srmcli.srm_fw_info_t()
        srm_status = srmcli.srm_mcu_fw_info_query(die, fw_info)

        addr = srmcli.srm_mcu_buffer_address_t()
        srm_status = srmcli.srm_mcu_get_buffer_address(die, 0, addr)
        srm_status = srmcli.srm_dbg_fsm_query_dump(die)

        string = srmcli.srm_dbg_translate_fw_mode(srmcli.SRM_FW_MODE_APPLICATION)
        string = srmcli.srm_dbg_translate_tx_pmd_state(srmcli.STATE_TX_PMD_READY_TO_TRAIN)
        string = srmcli.srm_dbg_translate_rx_pmd_state(0)
        string = srmcli.srm_dbg_translate_dsp_mode(0)
        string = srmcli.srm_dbg_translate_signalling(srmcli.SRM_SIGNAL_MODE_NRZ)
        string = srmcli.srm_dbg_translate_lut_mode(0)
        string = srmcli.srm_dbg_translate_tx_swing(0)
        string = srmcli.srm_dbg_translate_an_mode(0)
        string = srmcli.srm_dbg_translate_lt_clk_src(0)
        srmcli.srm_show_progress_enable(enable)
        ok = srmcli.srm_show_progress()
        srm_status = srmcli.srm_dwld_fw(die, fw_dwld_timeout, fw_warn_if_mismatched)
        srm_status = srmcli.srm_wait_for_pll_lock(die, max_wait)
        anlt_rules = srmcli.srm_anlt_rules_t()
        srm_status = srmcli.srm_anlt_rules_set_default(anlt_rules)
        bundle = srmcli.srm_anlt_bundle_t()
        srm_status = srmcli.srm_anlt_init(bundle, anlt_rules)
        srm_status = srmcli.srm_anlt_go(bundle, anlt_rules)
        e_srm_anlt_an_status = srmcli.srm_anlt_get_an_status(bundle)
        result = srmcli.srm_anlt_results_t()
        srm_status = srmcli.srm_anlt_get_an_results(bundle, result)
        srmcli.srm_anlt_bundle_dump(bundle, anlt_rules)
        srm_status = srmcli.srm_anlt_status_summary_query_dump(bundle)

    def test_srm_diags_temperature(self):
        die = 0
        low_legal_temperature = 15
        high_legal_temperature = 100
        temperature = srmcli.srm_diags_temperature_query(die)
        if is_hw_device():
            self.assertGreater(
                temperature,
                low_legal_temperature,
                'The temperature {} lower than the legal temperature {}'.format(
                    temperature,
                    low_legal_temperature))
            self.assertLess(temperature, high_legal_temperature,
                            'The temperature {} higher than the legal temperature {}'.format(temperature, high_legal_temperature))


if __name__ == '__main__':
    unittest.main()
