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

import os
import json
import sys
import datetime

ACTIVE_TRANS_IDX = 0


class gb_save_state_parse:
    def __init__(self, link_down_timeout = 90, directory="automate_test_runs"):
        self.link_down_timeout = link_down_timeout
        self.directory = directory

    def print_direct_info(self, filename, results):
        label, current_test_iteration, mode, portstr = self.extract_filename(filename)
        slice, ifg, serdes = portstr.split('_')

        jf = open(filename)
        jd = json.load(jf)
        pd = jd[list(jd)[0]]
        port = list(jd)[0].replace('mac_port_', '').replace('_', '/')

        mac_state_histro = pd["mac_state_histogram"]

        print(
            '{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {}'.format(
                mac_state_histro['bad_eye_retry'],
                mac_state_histro['PRE_INIT'],
                mac_state_histro['INACTIVE'],
                mac_state_histro['PCAL_STOP'],
                mac_state_histro['AN_BASE_PAGE'],
                mac_state_histro['AN_NEXT_PAGE'],
                mac_state_histro['AN_POLL'],
                mac_state_histro['LINK_TRAINING'],
                mac_state_histro['AN_COMPLETE'],
                mac_state_histro['ACTIVE'],
                mac_state_histro['WAITING_FOR_PEER'],
                mac_state_histro['TUNING'],
                mac_state_histro['TUNED'],
                mac_state_histro['PCS_LOCK'],
                mac_state_histro['PCS_STABLE'],
                mac_state_histro['LINK_UP']),
            end=', ',
            file=results)
        jf.close()

    def print_additional_info(self, filename, results, serdes_idx):
        label, current_test_iteration, mode, portstr = self.extract_filename(filename)
        slice, ifg, serdes = portstr.split('_')

        jf = open(filename)
        jd = json.load(jf)
        jf.close()
        pd = jd[list(jd)[0]]
        port = list(jd)[0].replace('mac_port_', '').replace('_', '/')

        mac_cfg = pd["mac_port_config"]
        mac_state_histro = pd["mac_state_histogram"]
        num_serdes = mac_cfg["num_of_serdes"]
        speed = mac_cfg["serdes_speed"].replace('E_', '')
        fec_mode = mac_cfg["fec_mode"]

        mac_status = pd['mac_port_status']
        link = mac_status['link_state']
        pcs = mac_status['pcs_status']

        mac_state = pd["mac_port_soft_state"]
        an_enabled = mac_state["an_enabled"]
        loopback = mac_state["loopback_mode"]

        serdes_status = pd['serdes_status']
        link_config = pd['link_config']
        try:
            anlt_spare9_fsm = pd["anlt_spare9_fsm"]
        except BaseException:
            anlt_spare9_fsm = None

        mcu_status = pd["mcu_status"]

        # FEC Mode None does not have fec_status in save_state
        # "NONE", "KR", "RS_KR4", "RS_KP4", "RS_KP4_FI"
        if fec_mode != 'NONE':
            fec = pd['fec_status']

            try:
                print(
                    '{}, {}, {}, {}'.format(
                        fec['correctable'],
                        fec['uncorrectable'],
                        fec['frame_loss_rate'],
                        fec['frame_loss_rate_accuracy']),
                    end=', ',
                    file=results)
            except BaseException:
                print('{}, {}, {}, {}'.format(fec['correctable'], fec['uncorrectable'], 0, 0), end=', ', file=results)

            if fec['is_rs_fec']:  # Exists in RS_KP4 and RS_KR4
                if (fec_mode == 'RS_KP4'):  # RS-KP4
                    # print('codeword :', fec['codeword'], end=', ', file=results)
                    # print(fec['codeword'], end=', ', file=results)
                    for cw_idx in range(len(fec['codeword'])):
                        print(fec['codeword'][cw_idx], end=', ', file=results)
                elif (fec_mode == 'RS_KR4'):  # RS-KR4
                    # print('codeword :', fec['codeword'], end=', ', file=results)
                    # print(fec['codeword'], end=', ', file=results)
                    for cw_idx in range(len(fec['codeword'])):
                        print(fec['codeword'][cw_idx], end=', ', file=results)
                    # Fill rest of codewords for consistent spacing
                    for i in range(8):
                        print("", end=', ', file=results)

                print('', fec['extrapolated_ber'], end=', ', file=results)

                print('', end=' ', file=results)
                num_serdes = len(fec['symbol_errors_per_lane'])
                if "SER" in fec["symbol_errors_per_lane"]["index_{}".format(serdes_idx)]:
                    print(fec["symbol_errors_per_lane"]["index_{}".format(serdes_idx)]["SER"], end=', ', file=results)
                else:
                    print("", end=', ', file=results)
            else:  # FEC is KR
                # Codewords (16)
                # Ext. BER (1)
                # Lane wise SER (1)
                for i in range(18):
                    print("", end=', ', file=results)
        else:  # FEC is NONE
            # FEC Correctable (1)
            # FEC Uncorrectable (1)
            # Codewords (16)
            # Ext. BER (1)
            # Lane wise SER (1)
            for i in range(20):
                print("", end=', ', file=results)
        rxdie = serdes_status['index_{}_RX'.format(serdes_idx)]['die']
        txdie = serdes_status['index_{}_TX'.format(serdes_idx)]['die']
        txch = serdes_status['index_{}_TX'.format(serdes_idx)]['channel']
        rxch = serdes_status['index_{}_RX'.format(serdes_idx)]['channel']
        sp9_exist = False
        if anlt_spare9_fsm is not None:
            sp9 = anlt_spare9_fsm['RX_DIE_{}_CH{}_TX_DIE_{}_CH{}'.format(rxdie, rxch, txdie, txch)]
            sp9_exist = True
        RX_ver = mcu_status['die_{}'.format(rxdie)]
        TX_ver = mcu_status['die_{}'.format(txdie)]
        # print(RX_FW_ver['APP_BLD_ID'])
        # print(sp9,sp9.split('  ')[0],sp9.split('  ')[0].split('-'))
        print('', end=' ', file=results)
        print("{}".format(serdes_status['index_{}_RX'.format(serdes_idx)]['die']), end=', ', file=results)
        print("{}".format(serdes_status['index_{}_RX'.format(serdes_idx)]['channel']), end=', ', file=results)
        print("{}".format(serdes_status['index_{}_TX'.format(serdes_idx)]['die']), end=', ', file=results)
        print("{}".format(serdes_status['index_{}_TX'.format(serdes_idx)]['channel']), end=', ', file=results)

        print("{}".format(link_config['index_{}_RX'.format(serdes_idx)]['CTLE']), end=', ', file=results)
        print("{}".format(link_config['index_{}_RX'.format(serdes_idx)]['AFE_TRIM']), end=', ', file=results)
        print("{}".format(link_config['index_{}_RX'.format(serdes_idx)]['VGA_TRACKING']), end=', ', file=results)
        print("{}".format(link_config['index_{}_RX'.format(serdes_idx)]['DSP_MODE'].strip()), end=', ', file=results)

        print("{}".format(link_config['index_{}_TX'.format(serdes_idx)]['LUT_MODE']), end=', ', file=results)
        print("{}".format(link_config['index_{}_TX'.format(serdes_idx)]['INNER_EYE1']), end=', ', file=results)
        print("{}".format(link_config['index_{}_TX'.format(serdes_idx)]['INNER_EYE2']), end=', ', file=results)
        try:
            print("{}".format(link_config['index_{}_TX'.format(serdes_idx)]['FIR_TAP0']), end=', ', file=results)
            print("{}".format(link_config['index_{}_TX'.format(serdes_idx)]['FIR_TAP1']), end=', ', file=results)
            print("{}".format(link_config['index_{}_TX'.format(serdes_idx)]['FIR_TAP2']), end=', ', file=results)
            print("{}".format(link_config['index_{}_TX'.format(serdes_idx)]['FIR_TAP3']), end=', ', file=results)
            print("{}".format(link_config['index_{}_TX'.format(serdes_idx)]['FIR_TAP4']), end=', ', file=results)
            print("{}".format(link_config['index_{}_TX'.format(serdes_idx)]['FIR_TAP5']), end=', ', file=results)
            print("{}".format(link_config['index_{}_TX'.format(serdes_idx)]['FIR_TAP6']), end=', ', file=results)
        except BaseException:
            for taps in range(4):
                print("", end=', ', file=results)
            print("{}".format(link_config['index_{}_TX'.format(serdes_idx)]['PRE1']), end=', ', file=results)
            print("{}".format(link_config['index_{}_TX'.format(serdes_idx)]['MAIN']), end=', ', file=results)
            print("{}".format(link_config['index_{}_TX'.format(serdes_idx)]['POST1']), end=', ', file=results)

        # for serdes_idx in range(len(serdes_status) // 3):  # Divide by three for PLL, TX, and RX
        print("{}".format(serdes_status['index_{}_RX'.format(serdes_idx)]
                          ['RX_FFE']['FFE_TAP_PRE_CURSOR_3']), end=', ', file=results)
        print("{}".format(serdes_status['index_{}_RX'.format(serdes_idx)]
                          ['RX_FFE']['FFE_TAP_PRE_CURSOR_2']), end=', ', file=results)
        print("{}".format(serdes_status['index_{}_RX'.format(serdes_idx)]
                          ['RX_FFE']['FFE_TAP_PRE_CURSOR_1']), end=', ', file=results)
        print("{}".format(serdes_status['index_{}_RX'.format(serdes_idx)]['RX_FFE']['FFE_TAP_MAIN_CURSOR']), end=', ', file=results)
        print("{}".format(serdes_status['index_{}_RX'.format(serdes_idx)]
                          ['RX_FFE']['FFE_TAP_POST_CURSOR_1']), end=', ', file=results)
        print("{}".format(serdes_status['index_{}_RX'.format(serdes_idx)]
                          ['RX_FFE']['FFE_TAP_POST_CURSOR_2']), end=', ', file=results)
        print("{}".format(serdes_status['index_{}_RX'.format(serdes_idx)]
                          ['RX_FFE']['FFE_TAP_POST_CURSOR_3']), end=', ', file=results)
        print("{}".format(serdes_status['index_{}_RX'.format(serdes_idx)]
                          ['RX_FFE']['FFE_TAP_POST_CURSOR_4']), end=', ', file=results)
        print("{}".format(serdes_status['index_{}_RX'.format(serdes_idx)]
                          ['RX_FFE']['FFE_TAP_POST_CURSOR_5']), end=', ', file=results)
        print("{}".format(serdes_status['index_{}_RX'.format(serdes_idx)]
                          ['RX_FFE']['FFE_TAP_POST_CURSOR_6']), end=', ', file=results)
        try:
            print("{}".format(serdes_status['index_{}_RX'.format(serdes_idx)]['RX_FFE']['AFE_TRIM']), end=', ', file=results)
        except BaseException:
            print("", end=', ', file=results)
        print("{}".format(serdes_status['index_{}_RX'.format(serdes_idx)]['RX_FFE']['PGA_GAIN']), end=', ', file=results)
        try:
            print("{0:.5f}".format(serdes_status['index_{}_RX'.format(serdes_idx)]['RX_FFE']['DFE_TAP']), end=', ', file=results)
        except BaseException:
            print("", end=', ', file=results)
        print("{0:.2f}".format(serdes_status['index_{}_RX'.format(serdes_idx)]['SNR']), end=', ', file=results)
        if sp9_exist:
            print("{}".format(sp9.split('  ')[0].split('-')[1]), end=', ', file=results)
            print("{}".format(sp9.split('  ')[1].split('-')[1]), end=', ', file=results)
        else:
            print("-1", end=', ', file=results)
            print("-1", end=', ', file=results)
        print("{}".format(RX_ver['APP_BLD_ID']), end=', ', file=results)
        print("{}".format(TX_ver['APP_BLD_ID']), end=', ', file=results)
        print("{}".format(RX_ver['API_BLD_ID']), end=', ', file=results)
        print("{}".format(TX_ver['API_BLD_ID']), end=', ', file=results)

    def make_filename(self, iteration, mode, portstr):
        return "{}/{}_{}_{}.json".format(self.directory, iteration, mode, portstr)

    def extract_filename(self, filename):
        # extract the directory which contains the file as the label
        label = os.path.dirname(filename).split('/')[-1]

        # remove the .json extension
        data = os.path.basename(filename).split('.json')[0]

        # first item is iteration
        iteration = data.split("_")[0]

        # last 3 items are port string
        length = data.count('_')
        portstr = data.split('_', length - 2)[-1]

        # item between the third last underscore and the first underscore is mode
        mode = data.rsplit('_', 3)[0].split('_', 1)[1]

        return (label, iteration, mode, portstr)

    def saves_cisco_state_port_test(self, filename, results):
        label, current_test_iteration, mode, portstr = self.extract_filename(filename)
        slice, ifg, serdes = portstr.split("_")

        port = portstr.replace('_', '/')
        jf = open(filename)
        jd = json.load(jf)
        jf.close()
        pd = jd[list(jd)[0]]
        port = list(jd)[0].replace('mac_port_', '').replace('_', '/')
        # print(jd)
        values_in = pd['state_transition_history']
        # filtered = {key: value for key, value in values_in.items() if key == 'state_transition_history'}

        # filtered = dict(zip('state_transition_history', [values[k] for k in 'state_transition_history']))
        # print(values_in[0])
        active = -1

        a_active = [0, 0, 0, 0, 0, 0, 0, 0]
        a_an_complete = [0, 0, 0, 0, 0, 0, 0, 0]
        a_tuning = [0, 0, 0, 0, 0, 0, 0, 0]
        a_tuned = [0, 0, 0, 0, 0, 0, 0, 0]
        a_pcal_stop = [0, 0, 0, 0, 0, 0, 0, 0]
        a_pcs_lock = [0, 0, 0, 0, 0, 0, 0, 0]
        a_pcs_stable = [0, 0, 0, 0, 0, 0, 0, 0]
        a_link_up = [0, 0, 0, 0, 0, 0, 0, 0]
        for logs in values_in:
            # print(logs)
            new_state = logs['new_state']
            timestamp = logs['timestamp']
            if new_state == 'ACTIVE':
                active += 1
                a_active[active] = timestamp

            if new_state == 'AN_COMPLETE':
                a_an_complete[active] = timestamp
            if new_state == 'TUNING':
                a_tuning[active] = timestamp
            if new_state == 'TUNED':
                a_tuned[active] = timestamp
            if new_state == 'PCAL_STOP':
                a_pcal_stop[active] = timestamp
            if new_state == 'PCS_LOCK':
                a_pcs_lock[active] = timestamp
            if new_state == 'PCS_STABLE':
                a_pcs_stable[active] = timestamp
            if new_state == 'LINK_UP':
                a_link_up[active] = timestamp

        print(
            '{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}'.format(
                a_active[0],
                a_an_complete[0],
                a_tuning[0],
                a_tuned[0],
                a_pcal_stop[0],
                a_pcs_lock[0],
                a_pcs_stable[0],
                a_link_up[0],
                a_active[1],
                a_an_complete[1],
                a_tuning[1],
                a_tuned[1],
                a_pcal_stop[1],
                a_pcs_lock[1],
                a_pcs_stable[1],
                a_link_up[1],
                a_active[2],
                a_an_complete[2],
                a_tuning[2],
                a_tuned[2],
                a_pcal_stop[2],
                a_pcs_lock[2],
                a_pcs_stable[2],
                a_link_up[2],
                a_active[3],
                a_an_complete[3],
                a_tuning[3],
                a_tuned[3],
                a_pcal_stop[3],
                a_pcs_lock[3],
                a_pcs_stable[3],
                a_link_up[3],
                a_active[4],
                a_an_complete[4],
                a_tuning[4],
                a_tuned[4],
                a_pcal_stop[4],
                a_pcs_lock[4],
                a_pcs_stable[4],
                a_link_up[4],
                a_active[5],
                a_an_complete[5],
                a_tuning[5],
                a_tuned[5],
                a_pcal_stop[5],
                a_pcs_lock[5],
                a_pcs_stable[5],
                a_link_up[5],
                a_active[6],
                a_an_complete[6],
                a_tuning[6],
                a_tuned[6],
                a_pcal_stop[6],
                a_pcs_lock[6],
                a_pcs_stable[6],
                a_link_up[6],
                a_active[7],
                a_an_complete[7],
                a_tuning[7],
                a_tuned[7],
                a_pcal_stop[7],
                a_pcs_lock[7],
                a_pcs_stable[7],
                a_link_up[7],
                active + 1),
            end=', ',
            file=results)

        try:
            tx_spare9 = pd['tx_spare9_fsm_histogram']
            rx_spare9 = pd['rx_spare9_fsm_histogram']
            print(
                '{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {},{}, {}, {}, {},{},{}'.format(
                    tx_spare9["FSM_-1_STATE_AN_ERROR"],
                    tx_spare9["FSM_00_STATE_AN_RESET_PD"],
                    tx_spare9["FSM_01_STATE_AN_IDLE"],
                    tx_spare9["FSM_02_STATE_AN_PMD_IDLE"],
                    tx_spare9["FSM_03_STATE_AN_PMD_10G_NRZ"],
                    tx_spare9["FSM_04_STATE_AN_TX_DISABLE"],
                    tx_spare9["FSM_05_STATE_AN_ABILITY_DETECT"],
                    tx_spare9["FSM_06_STATE_AN_ACK_DETECT"],
                    tx_spare9["FSM_07_STATE_AN_COMPLETE_ACK"],
                    tx_spare9["FSM_08_STATE_AN_GOOD_CHECK"],
                    tx_spare9["FSM_09_STATE_AN_PMD_RECONFIG"],
                    tx_spare9["FSM_10_STATE_AN_PMD_RECONFIG_LINK_BREAK"],
                    tx_spare9["FSM_11_STATE_AN_PMD_DATA_MODE"],
                    tx_spare9["FSM_12_STATE_AN_PMD_INTF_UP"],
                    tx_spare9["FSM_13_STATE_AN_NP_WAIT"],
                    tx_spare9["FSM_14_STATE_AN_GOOD"],
                    tx_spare9["FSM_15_STATE_AN_TRAIN_INIT"],
                    tx_spare9["FSM_16_STATE_AN_TRAIN_ACK_INIT"],
                    tx_spare9["FSM_17_STATE_AN_TRAIN"],
                    tx_spare9["FSM_18_STATE_AN_RESTART"],
                    tx_spare9["FSM_19_STATE_AN_RESTART_LINK_BREAK"],
                    tx_spare9["FSM_20_STATE_AN_DO_START"],
                    tx_spare9["FSM_21_STATE_AN_UNKNOWN"],
                    rx_spare9["SRM_AN_STATUS_BUSY"],
                    rx_spare9["SRM_AN_STATUS_RESOLVED"],
                    rx_spare9["SRM_AN_STATUS_LT_COMPLETE"],
                    rx_spare9["SRM_AN_STATUS_COMPLETE"],
                    rx_spare9["SRM_AN_STATUS_FAIL"]),
                end=', ',
                file=results)
        except BaseException:
            # print('exception')
            print('{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {}, {}, {},{}, {},{}, {}, {}, {},{},{}'.format(
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), end=', ', file=results)

    def savestate_port_test(self, filename):
        self.mp_parse_result = True
        self.mp_parse_warning = False
        label, current_test_iteration, mode, portstr = self.extract_filename(filename)
        slice, ifg, serdes = portstr.split("_")

        jf = open(filename)
        jd = json.load(jf)
        jf.close()
        pd = jd[list(jd)[0]]
        port = list(jd)[0].replace('mac_port_', '').replace('_', '/')

        mac_cfg = pd["mac_port_config"]
        num_serdes = mac_cfg["num_of_serdes"]
        speed = mac_cfg["serdes_speed"].replace('E_', '')
        fec_mode = mac_cfg["fec_mode"]

        mac_status = pd['mac_port_status']
        mac_state_histro = pd["mac_state_histogram"]
        link = mac_status['link_state']
        pcs = mac_status['pcs_status']

        mac_state = pd["mac_port_soft_state"]
        an_enabled = mac_state["an_enabled"]
        loopback = mac_state["loopback_mode"]

        serdes_status = pd['serdes_status']
        link_config = pd['link_config']

        cwstr = "CW0,CW1,CW2,CW3,CW4,CW5,CW6,CW7,CW8,CW9,CW10,CW11,CW12,CW13,CW14,CW15"
        tapstr = "TX FIR 0, TX FIR 1, TX FIR 2, TX FIR 3, TX PRE, TX MAIN, TX POST"

        results_file = "{}.csv".format(label)

        if not os.path.exists(results_file):
            first_file = open(results_file, 'w')  # make a new file if not exist
            first_file.write(f"Label, Iteration, Result, Link Up Time, Link Fault, FEC Fault, SerDes Fault, Speed, Port, Lane, Fec, ANLT, Loopback, Link, PCS, Anlt_rx_up, Anlt_hcd,Anlt_reconfig,Anlt_tx_up,Anlt_rx_up,Anlt_ctle_start,Anlt_ctle_done,Anlt_pset_req,Anlt_frame_lck,Anlt_pset_ack,Anlt_cmd1_req,Anlt_cmd1_ack,Anlt_term_reason,Anlt_train_fom,Anlt_rr_trans,Anlt_rr_rec,Anlt_train_done,Anlt_tx_open,Anlt_rx_open,Anlt_rx_slap,Anlt_final_snr,Anlt_restart,Anlt_an2lt_los,Anlt_an2lt_sig,Anlt_ctle_value,")
            # header for addtional print info function
            first_file.write(
                f"FEC Correctable, FEC Uncorrectable, FEC_frame_loss_rate, FEC_frame_loss_rate_accuracy,{cwstr}, Extrapolated BER, Lanewise SER, ")
            first_file.write(
                f"RX Die, RX Channel, TX Die, TX Channel, RX CTLE, RX AFE_TRIM, RX VGA_TRACKING, RX DSP_MODE, TX LUT_MODE, TX INNER_EYE1, TX INNER_EYE2, {tapstr}, RXFFE_PRE3, RXFFE_PRE2, RXFFE_PRE1, RXFFE_MAIN, RXFFE_POST1, RXFFE_POST2, RXFFE_POST3, RXFFE_POST4, RXFFE_POST5, RXFFE_POST6, AFE_TRIM, PGA_GAIN, DFE_TAP, SNR,rxps9, txps9, RX_FW_ver,TX_FW_ver,RX_API_ver,TX_API_ver,bad_eye_retry,PRE_INIT,INACTIVE,PCAL_STOP,AN_BASE_PAGE,AN_NEXT_PAGE,AN_POLL,LINK_TRAINING,AN_COMPLETE,ACTIVE,WAITING_FOR_PEER,TUNING,TUNED,PCS_LOCK,PCS_STABLE,LINK_UP,")
            first_file.write(f"Active_1,An_complete_1,Tuning_1,Tuned_1,Pcal_stop_1,Pcs_lock_1, Pcs_stable_1,Link_up_1,Active_2,An_complete_2,Tuning_2,Tuned_2,Pcal_stop_2,Pcs_lock_2, Pcs_stable_2,Link_up_2,Active_3,An_complete_3,Tuning_3,Tuned_3,Pcal_stop_3,Pcs_lock_3, Pcs_stable_3,Link_up_3,Active_4,An_complete_4,Tuning_4,Tuned_4,Pcal_stop_4,Pcs_lock_4, Pcs_stable_4,Link_up_4,Active_5,An_complete_5,Tuning_5,Tuned_5,Pcal_stop_5,Pcs_lock_5, Pcs_stable_5,Link_up_6,Active_6,An_complete_6,Tuning_6,Tuned_6,Pcal_stop_6,Pcs_lock_6, Pcs_stable_6,Link_up_6,Active_7,An_complete_7,Tuning_7,Tuned_7,Pcal_stop_7,Pcs_lock_7, Pcs_stable_7,Link_up_7,Active_8,An_complete_8,Tuning_8,Tuned_8,Pcal_stop_8,Pcs_lock_8, Pcs_stable_8,Link_up_8,n_Cisco_fsm,")
            first_file.write(f"FSM_-1_STATE_AN_ERROR,FSM_00_STATE_AN_RESET_PD,FSM_01_STATE_AN_IDLE,FSM_02_STATE_AN_PMD_IDLE,FSM_03_STATE_AN_PMD_10G_NRZ,FSM_04_STATE_AN_TX_DISABLE,FSM_05_STATE_AN_ABILITY_DETECT,FSM_06_STATE_AN_ACK_DETECT,FSM_07_STATE_AN_COMPLETE_ACK,FSM_08_STATE_AN_GOOD_CHECK,FSM_09_STATE_AN_PMD_RECONFIG,FSM_10_STATE_AN_PMD_RECONFIG_LINK_BREAK,FSM_11_STATE_AN_PMD_DATA_MODE,FSM_12_STATE_AN_PMD_INTF_UP,FSM_13_STATE_AN_NP_WAIT,FSM_14_STATE_AN_GOOD,FSM_15_STATE_AN_TRAIN_INIT,FSM_16_STATE_AN_TRAIN_ACK_INIT,FSM_17_STATE_AN_TRAIN,FSM_18_STATE_AN_RESTART,FSM_19_STATE_AN_RESTART_LINK_BREAK,FSM_20_STATE_AN_DO_START,FSM_21_STATE_AN_UNKNOWN,",)
            first_file.write(
                f"SRM_AN_STATUS_BUSY,SRM_AN_STATUS_RESOLVED,SRM_AN_STATUS_LT_COMPLETE,SRM_AN_STATUS_COMPLETE,SRM_AN_STATUS_FAIL,")
            first_file.write(f"Save State Filename\n")
            first_file.close()

        with open(results_file, 'a') as results:

            for serdes_idx in range(num_serdes):
                serdes_fault = None
                test_status = "FAIL"
                link_fault, linkup_time = self.get_link_transition_fault_cause(filename)
                fec_fault = self.get_fec_fault_cause(filename, serdes_idx)
                if (an_enabled):
                    serdes_fault_read = self.get_serdes_fault_cause(filename, serdes_idx, speed)
                else:
                    serdes_fault_read = [None, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                # print(serdes_fault_read)
                if(serdes_fault_read is not None):
                    serdes_fault = serdes_fault_read[0]
                    anlt_hcd = serdes_fault_read[1]
                    anlt_reconfig = serdes_fault_read[2]
                    anlt_tx_up = serdes_fault_read[3]
                    anlt_rx_up = serdes_fault_read[4]
                    anlt_ctle_start = serdes_fault_read[5]
                    anlt_ctle_done = serdes_fault_read[6]
                    anlt_pset_req = serdes_fault_read[7]
                    anlt_frame_lck = serdes_fault_read[8]
                    anlt_pset_ack = serdes_fault_read[9]
                    anlt_cmd1_req = serdes_fault_read[10]
                    anlt_cmd1_ack = serdes_fault_read[11]
                    anlt_term_reason = serdes_fault_read[12]
                    anlt_train_fom = serdes_fault_read[13]
                    anlt_rr_trans = serdes_fault_read[14]
                    anlt_rr_rec = serdes_fault_read[15]
                    anlt_train_done = serdes_fault_read[16]
                    anlt_tx_open = serdes_fault_read[17]
                    anlt_rx_open = serdes_fault_read[18]
                    anlt_rx_slap = serdes_fault_read[19]
                    anlt_final_snr = serdes_fault_read[20]
                    anlt_restart = serdes_fault_read[21]
                    anlt_an2lt_los = serdes_fault_read[22]
                    anlt_an2lt_sig = serdes_fault_read[23]
                    anlt_ctle_value = serdes_fault_read[24]

                if link_fault is None and fec_fault is None and serdes_fault is None:
                    test_status = "PASS"
                else:
                    self.mp_parse_warning = True
                results.write(f"{label}, {current_test_iteration}, {test_status}, {linkup_time}, {link_fault}, {fec_fault},{serdes_fault}, {num_serdes}x{speed}, {port}, {serdes_idx}, {fec_mode}, {an_enabled}, {loopback}, {link}, {pcs},{anlt_rx_up},{anlt_hcd},{anlt_reconfig},{anlt_tx_up},{anlt_rx_up},{anlt_ctle_start},{anlt_ctle_done},{anlt_pset_req},{anlt_frame_lck},{anlt_pset_ack},{anlt_cmd1_req},{anlt_cmd1_ack},{anlt_term_reason},{anlt_train_fom},{anlt_rr_trans},{anlt_rr_rec},{anlt_train_done},{anlt_tx_open},{anlt_rx_open},{anlt_rx_slap},{anlt_final_snr},{anlt_restart},{anlt_an2lt_los},{anlt_an2lt_sig},{anlt_ctle_value},")
                self.print_additional_info(filename, results, serdes_idx)
                self.print_direct_info(filename, results)
                self.saves_cisco_state_port_test(filename, results)
                results.write(f"{filename}\n")

    def get_fec_fault_cause(self, filename, serdes_idx):

        BER_FAULT_THRESHOLD = 1e-6
        LANE_SER_FAULT_THRESHOLD = 1e-5

        jf = open(filename)
        jd = json.load(jf)
        jf.close()
        pd = jd[list(jd)[0]]
        port = list(jd)[0].replace('mac_port_', '').replace('_', '/')

        mac_cfg = pd["mac_port_config"]
        fec_mode = mac_cfg["fec_mode"]

        if fec_mode != 'NONE':
            fec = pd['fec_status']
            if fec['uncorrectable'] != 0:
                return "Uncorrectable Errors"

            if fec['is_rs_fec']:  # Exists in RS_KP4 and RS_KR4
                if (fec_mode == 'RS_KP4'):  # RS-KP4
                    for cw_idx in range(3, len(fec['codeword'])):
                        if fec['codeword'][cw_idx] > 0:
                            return f"CW{cw_idx} > 0"
                elif (fec_mode == 'RS_KR4'):  # RS-KR4
                    for cw_idx in range(1, len(fec['codeword'])):
                        if fec['codeword'][cw_idx] > 0:
                            return f"CW{cw_idx} > 0"

                if fec['extrapolated_ber'] > BER_FAULT_THRESHOLD:
                    return f"BER > {BER_FAULT_THRESHOLD}"
                if "SER" in fec["symbol_errors_per_lane"]["index_{}".format(serdes_idx)]:
                    if fec["symbol_errors_per_lane"]["index_{}".format(serdes_idx)]["SER"] > LANE_SER_FAULT_THRESHOLD:
                        return f"Lane SER > {LANE_SER_FAULT_THRESHOLD}"

        return None

    def get_serdes_fault_cause(self, filename, serdes_idx, portspeed):
        LT_TIMEOUT_NRZ = 500
        LT_TIMEOUT_PAM = 3000
        jf = open(filename)
        jd = json.load(jf)
        jf.close()
        pd = jd[list(jd)[0]]
        count_restarts = 0

        try:
            anlt_timestamp = pd['anlt_timestamp'][f'index_{serdes_idx}_bundle']
            restart = anlt_timestamp['restart']
            lifetime = anlt_timestamp['lifetime']
            tx_up = anlt_timestamp['tx_up']
            rx_up = anlt_timestamp['rx_up']
            rx_open = anlt_timestamp['rx_open']
            tx_open = anlt_timestamp['tx_open']

            anlt_hcd = anlt_timestamp['hcd']
            anlt_reconfig = anlt_timestamp['reconfig']
            anlt_tx_up = anlt_timestamp['tx_up']
            anlt_rx_up = anlt_timestamp['rx_up']
            anlt_ctle_start = anlt_timestamp['ctle_start']
            anlt_ctle_done = anlt_timestamp['ctle_done']
            anlt_pset_req = anlt_timestamp['pset_req']
            anlt_frame_lock = anlt_timestamp['frame_lock']
            anlt_pset_ack = anlt_timestamp['pset_ack']
            anlt_cmd1_req = anlt_timestamp['cmd1_req']

            anlt_cmd1_ack = anlt_timestamp['cmd1_ack']
            try:
                anlt_term_reason = anlt_timestamp['term_reason']
            except BaseException:
                anlt_term_reason = [0, 0, 0, 0]
            anlt_train_fom = anlt_timestamp['train_fom']
            anlt_rr_transmitted = anlt_timestamp['rr_transmitted']
            anlt_rr_received = anlt_timestamp['rr_received']
            anlt_train_done = anlt_timestamp['train_done']
            anlt_tx_open = anlt_timestamp['tx_open']
            anlt_rx_open = anlt_timestamp['rx_open']
            anlt_rx_slap = anlt_timestamp['rx_slap']
            anlt_final_snr = anlt_timestamp['final_snr']
            anlt_restart = anlt_timestamp['restart']

            try:

                anlt_an_to_lt_los = anlt_timestamp['an_to_lt_los']
                anlt_an_to_lt_sig = anlt_timestamp['an_to_lt_sig']
            except BaseException:
                anlt_an_to_lt_los = [0, 0, 0, 0]
                anlt_an_to_lt_sig = [0, 0, 0, 0]
            anlt_ctle_value = anlt_timestamp['ctle_value']
            good_anlt = False
            good_idx = 0
            rx_up_time = 0
            index_max = max(range(len(lifetime)), key=lifetime.__getitem__)
            list_non_zero = [idx for idx, val in enumerate(rx_up) if val != 0]
            if len(list_non_zero) > 0:
                # print(filename)
                # print(rx_up,list_non_zero,lifetime,restart,tx_up)
                for idx in list_non_zero:
                    # print(rx_up[idx],rx_open[idx],restart[idx])
                    if rx_up[idx] > 0 and restart[idx] == 0:
                        good_anlt = True
                        good_idx = idx
                    elif restart[idx] != 0:
                        good_idx = idx

            # print(restart, tx_up, rx_up,good_anlt,rx_up_time,good_idx,rx_up[good_idx],tx_up[good_idx],rx_open[good_idx],tx_open[good_idx],restart[good_idx])
            list_of_val = anlt_hcd[good_idx], anlt_reconfig[good_idx], anlt_tx_up[good_idx], anlt_rx_up[good_idx], anlt_ctle_start[good_idx], anlt_ctle_done[good_idx], anlt_pset_req[good_idx], anlt_frame_lock[good_idx], anlt_pset_ack[good_idx], anlt_cmd1_req[good_idx], anlt_cmd1_ack[good_idx], anlt_term_reason[good_idx], anlt_train_fom[
                good_idx], anlt_rr_transmitted[good_idx], anlt_rr_received[good_idx], anlt_train_done[good_idx], anlt_tx_open[good_idx], anlt_rx_open[good_idx], anlt_rx_slap[good_idx], anlt_final_snr[good_idx], anlt_restart[good_idx], anlt_an_to_lt_los[good_idx], anlt_an_to_lt_sig[good_idx], anlt_ctle_value[good_idx]
            # print(list_of_val)
            if not(good_anlt):
                if len(list_non_zero) == 0:
                    return f"AN failed to complete", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                else:
                    return f"AN restarted {len(list_non_zero)} times", anlt_hcd[good_idx], anlt_reconfig[good_idx], anlt_tx_up[good_idx], anlt_rx_up[good_idx], anlt_ctle_start[good_idx], anlt_ctle_done[good_idx], anlt_pset_req[good_idx], anlt_frame_lock[good_idx], anlt_pset_ack[good_idx], anlt_cmd1_req[good_idx], anlt_cmd1_ack[good_idx], anlt_term_reason[
                        good_idx], anlt_train_fom[good_idx], anlt_rr_transmitted[good_idx], anlt_rr_received[good_idx], anlt_train_done[good_idx], anlt_tx_open[good_idx], anlt_rx_open[good_idx], anlt_rx_slap[good_idx], anlt_final_snr[good_idx], anlt_restart[good_idx], anlt_an_to_lt_los[good_idx], anlt_an_to_lt_sig[good_idx], anlt_ctle_value[good_idx]

            elif (portspeed == '50G' and tx_open[good_idx] > LT_TIMEOUT_PAM) or (portspeed != '50G' and tx_open[good_idx] > LT_TIMEOUT_NRZ):
                #@print(tx_open[good_idx],portspeed)
                return f"LT Tx_open violations were {tx_open[good_idx]}", anlt_hcd[good_idx], anlt_reconfig[good_idx], anlt_tx_up[good_idx], anlt_rx_up[good_idx], anlt_ctle_start[good_idx], anlt_ctle_done[good_idx], anlt_pset_req[good_idx], anlt_frame_lock[good_idx], anlt_pset_ack[good_idx], anlt_cmd1_req[good_idx], anlt_cmd1_ack[good_idx], anlt_term_reason[
                    good_idx], anlt_train_fom[good_idx], anlt_rr_transmitted[good_idx], anlt_rr_received[good_idx], anlt_train_done[good_idx], anlt_tx_open[good_idx], anlt_rx_open[good_idx], anlt_rx_slap[good_idx], anlt_final_snr[good_idx], anlt_restart[good_idx], anlt_an_to_lt_los[good_idx], anlt_an_to_lt_sig[good_idx], anlt_ctle_value[good_idx]

            else:
                # print(tx_open[good_idx])
                return None, anlt_hcd[good_idx], anlt_reconfig[good_idx], anlt_tx_up[good_idx], anlt_rx_up[good_idx], anlt_ctle_start[good_idx], anlt_ctle_done[good_idx], anlt_pset_req[good_idx], anlt_frame_lock[good_idx], anlt_pset_ack[good_idx], anlt_cmd1_req[good_idx], anlt_cmd1_ack[good_idx], anlt_term_reason[good_idx], anlt_train_fom[
                    good_idx], anlt_rr_transmitted[good_idx], anlt_rr_received[good_idx], anlt_train_done[good_idx], anlt_tx_open[good_idx], anlt_rx_open[good_idx], anlt_rx_slap[good_idx], anlt_final_snr[good_idx], anlt_restart[good_idx], anlt_an_to_lt_los[good_idx], anlt_an_to_lt_sig[good_idx], anlt_ctle_value[good_idx]

        except BaseException:
            # print('exception')
            # save_state for non-ANLT doesn't have anlt_timestamp
            # anlt_timestamp = pd['anlt_timestamp'][f'index_{serdes_idx}_bundle']
            # print(anlt_timestamp)
            return 'Exception', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

    def get_link_transition_fault_cause(self, filename):
        jf = open(filename)
        jd = json.load(jf)
        jf.close()
        pd = jd[list(jd)[0]]

        mac_status = pd['mac_port_status']
        link = mac_status['link_state']

        mac_state = pd["mac_port_soft_state"]
        an_enabled = mac_state["an_enabled"]

        linkup_time = None
        cause_field = None

        if not link:
            cause_field = "Link is not Up/True"
            self.mp_parse_result = False

        transition = pd['state_transition_history']
        last = len(transition) - 1
        if transition[last]['new_state'] == 'LINK_UP' and transition[ACTIVE_TRANS_IDX]['new_state'] == 'ACTIVE':
            date_time_end = datetime.datetime.strptime(transition[last]['timestamp'], '%d-%m-%Y %H:%M:%S.%f ')
            date_time_start = datetime.datetime.strptime(transition[ACTIVE_TRANS_IDX]['timestamp'], '%d-%m-%Y %H:%M:%S.%f ')
            tdelta = date_time_end - date_time_start
            linkup_time = tdelta.total_seconds()
            if linkup_time > self.link_down_timeout:
                cause_field = f"Timeout after {self.link_down_timeout} seconds. Link Up in {linkup_time} seconds with {last+1} transitions"
            elif an_enabled and last != 6 + ACTIVE_TRANS_IDX:
                cause_field = f"Transitions: expected {7+ACTIVE_TRANS_IDX} transitions for ANLT link found {last+1}"
            elif an_enabled != True and last != 7 + ACTIVE_TRANS_IDX:
                cause_field = f"Transitions: expected {8+ACTIVE_TRANS_IDX} transitions found {last+1}"
        # state transition does not start with active, due to too many state_transitions, pushed out of array
        elif transition[last]['new_state'] == 'LINK_UP' and transition[ACTIVE_TRANS_IDX]['new_state'] != 'ACTIVE':
            # Need to find better way to calculate link up time if ACTIVE state is not in save state's state_transition_history
            # For now, just calculate with first state in state_transition_history
            date_time_end = datetime.datetime.strptime(transition[last]['timestamp'], '%d-%m-%Y %H:%M:%S.%f ')
            date_time_start = datetime.datetime.strptime(transition[ACTIVE_TRANS_IDX]['timestamp'], '%d-%m-%Y %H:%M:%S.%f ')
            tdelta = date_time_end - date_time_start
            linkup_time = tdelta.total_seconds()
            cause_field = f"Timeout after {self.link_down_timeout} seconds. Transition Buffer overflow. Link Up estimate from {transition[ACTIVE_TRANS_IDX]['new_state']} to LINK_UP in {linkup_time} seconds with {last+1}+ transitions"

        return cause_field, linkup_time


if __name__ == '__main__':
    gbssp = gb_save_state_parse()

    if len(sys.argv) == 2:
        gbssp.directory = sys.argv[1]
    else:
        gbssp.directory = "automate_test_runs"

    files = os.listdir(gbssp.directory)
    # print(files)

    for file in files:
        filename = "{}/{}".format(gbssp.directory, file)
        print("Processing file : {}".format(filename))
        if "json" in filename:
            gbssp.savestate_port_test(filename)
        else:
            print("Skipping {}".format(filename))
