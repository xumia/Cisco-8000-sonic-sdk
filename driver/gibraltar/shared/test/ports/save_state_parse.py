#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import sys
import glob
import json
import datetime
import pandas as pd
import numpy as np
import time

BER_FAULT_THRESHOLD = 1e-6
LANE_SER_FAULT_THRESHOLD = 1e-5
LT_TIMEOUT_NRZ = 500
LT_TIMEOUT_PAM = 3000
temp = pd.DataFrame()


class save_state_parse:

    def __init__(self, combine_peer = False, link_down_timeout = 90, directory="/tmp/extended_ports_sanity_logs"):
        self.link_down_timeout = link_down_timeout
        self.directory = directory
        self.combine_peer = combine_peer

    def merge(self, dict1, dict2):
        return (dict2.update(dict1))

    def crete_summary_dic(self, folder, file, neighbour, pair_port, db_loss):
        summary_lanes = []
        data = os.path.basename(file).split('.json')[0]
        length = data.count('_')
        file_name = folder + '/' + file

        mac_port_raw = data.split('_', length - 2)[-1]
        iteration = int(file.split('_')[0])
        mode = (file.split('_')[1])
        self.an_mode = (length == 6)

        port_neighbour = "{}_{}_{}".format(pair_port[0], pair_port[1], pair_port[2])
        # Get peer port File name
        temp = data.split('_')[0:length - 2]
        temp.append(port_neighbour)
        name_neighbour = '_'.join(temp) + '.json'
        file_neighbour = folder + '/' + name_neighbour
        if neighbour:
            mac_port_raw = port_neighbour
            file_name = file_neighbour

        print(f"parser {file_name}")

        with open(file_name, 'r') as jfile:
            values = json.load(jfile)
            main_dict_name = 'mac_port_' + mac_port_raw
            main_dicts = values[main_dict_name]

        n_lanes = int(mode.split('x')[0])
        mac_port = mac_port_raw.replace('_', '/')
        for lane in range(n_lanes):
            summary_dic = {}
            summary_dic['General_iteration'] = iteration
            summary_dic['General_mode'] = mode
            summary_dic['General_port'] = mac_port
            summary_dic['Info_anlt'] = self.an_mode
            summary_dic['Info_db_loss'] = db_loss

            # Mac Port Info fec
            mac_port_config = {}
            mac_port_config_row = main_dicts['mac_port_config']
            mac_port_config['fec_mode'] = mac_port_config_row['fec_mode']
            mac_port_config = dict(("{}_{}".format('Info', k), v) for k, v in mac_port_config.items())
            summary_dic = {**summary_dic, **mac_port_config}

            # Serdes status
            serdes_status = {}
            serdes_status_PLL = main_dicts['serdes_status']['index_{}_PLL'.format(lane)]
            serdes_status_RX_row = main_dicts['serdes_status']['index_{}_RX'.format(lane)]
            serdes_status_RX = {}
            for i, keys in enumerate(serdes_status_RX_row.keys()):
                try:
                    serdes_status_RX_parts = serdes_status_RX_row[keys]
                    self.merge(serdes_status_RX_parts, serdes_status_RX)
                except BaseException:
                    serdes_status_RX[keys] = serdes_status_RX_row[keys]
            serdes_status_TX_row = main_dicts['serdes_status']['index_{}_TX'.format(lane)]
            serdes_status_TX = {}
            for i, keys in enumerate(serdes_status_TX_row.keys()):
                try:
                    serdes_status_TX_parts = serdes_status_TX_row[keys]
                    self.merge(serdes_status_TX_parts, serdes_status_TX)
                except BaseException:
                    serdes_status_TX[keys] = serdes_status_TX_row[keys]

            serdes_status_TXC = dict(("{}_{}".format('TX', k), v) for k, v in serdes_status_TX.items())
            serdes_status_RXC = dict(("{}_{}".format('RX', k), v) for k, v in serdes_status_RX.items())
            serdes_status_PLLC = dict(("{}_{}".format('PLL', k), v) for k, v in serdes_status_PLL.items())
            self.merge(serdes_status_PLLC, serdes_status)
            self.merge(serdes_status_RXC, serdes_status)
            self.merge(serdes_status_TXC, serdes_status)
            serdes_status = dict(("{}_{}".format('serdes_status', k), v) for k, v in serdes_status.items())
            summary_dic = {**summary_dic, **serdes_status}

            # Mac port status
            mac_port_status = {}
            mac_port_status_parts = {}
            mac_port_status_row = main_dicts['mac_port_status']
            for i, keys in enumerate(mac_port_status_row.keys()):
                if keys == 'am_lock' or keys == 'mac_pcs_lane_mapping':
                    if '50G' in mode:
                        mac_port_status_parts['lane0_{}'.format(keys)] = mac_port_status_row[keys][lane * 2 - 1]
                        mac_port_status_parts['lane1_{}'.format(keys)] = mac_port_status_row[keys][lane * 2]
                    else:
                        mac_port_status_parts['lane0_{}'.format(keys)] = mac_port_status_row[keys][lane]
                    self.merge(mac_port_status_parts, mac_port_status)
                else:
                    mac_port_status[keys] = mac_port_status_row[keys]
            mac_port_status = dict(("{}_{}".format('mac_port_status', k), v) for k, v in mac_port_status.items())
            summary_dic = {**summary_dic, **mac_port_status}

            # FEC status
            if summary_dic["Info_fec_mode"] != 'NONE':
                fec_status = {}
                fec_status_row = main_dicts['fec_status']
                for i, keys in enumerate(fec_status_row.keys()):
                    if keys == 'codeword':
                        fec_cw = fec_status_row['codeword']
                        i = 0
                        for elem in fec_cw:
                            fec_status[f'fec_cw_{i:2d}'] = elem
                            i += 1
                    elif keys == 'symbol_errors_per_lane':
                        fec_errors_per_lane = fec_status_row['symbol_errors_per_lane']['index_{}'.format(lane)]
                        self.merge(fec_errors_per_lane, fec_status)
                        pass
                    elif keys == 'symbol_burst':
                        fec_burst = fec_status_row['symbol_burst']
                        i = 0
                        for elem in fec_burst:
                            fec_status['fec_burst_{}'.format(i)] = elem
                            i += 1
                    else:
                        fec_status[keys] = fec_status_row[keys]
                fec_status = dict(("{}_{}".format('Status_fec', k), v) for k, v in fec_status.items())
                summary_dic = {**summary_dic, **fec_status}

            # Mac state histogram
            mac_state_histogram = main_dicts['mac_state_histogram']
            mac_state_histogram = dict(("{}_{}".format('mac_state_histogram', k), v) for k, v in mac_state_histogram.items())
            summary_dic = {**summary_dic, **mac_state_histogram}

            # Link config Tx FIR
            link_config = {}
            link_config_TX = main_dicts['link_config']['index_{}_TX'.format(lane)]
            fir_tap = []
            for ii in range(7):
                fir_tap.append('FIR_TAP{}'.format(ii))
            die_no = link_config_TX['die']
            link_config_TX = dict(("{}_{}".format('TX', k), v) for k, v in link_config_TX.items() if k in fir_tap)
            self.merge(link_config_TX, link_config)
            link_config = dict(("{}_{}".format('link_config', k), v) for k, v in link_config.items())
            summary_dic = {**summary_dic, **link_config}

            mac_port_soft_state = dict([("mac_port_soft_state_an_enabled", main_dicts['mac_port_soft_state']['an_enabled'])])
            summary_dic = {**summary_dic, **mac_port_soft_state}

            # MCU status
            mcu_status = main_dicts['mcu_status'][f'die_{die_no}']
            mcu_status = dict(("mcu_status_{}".format(k), v) for k, v in mcu_status.items() if k.startswith(('APP', 'API')))
            summary_dic = {**summary_dic, **mcu_status}

            # ANLT timestamp
            try:
                anlt_timestamp_row = main_dicts['anlt_timestamp']['index_{}_bundle'.format(lane)]
                idx = 0
                anlt_timestamp = {}
                an_term_reason_history = ''
                lt_term_reason_history = ''
                while True:
                    if anlt_timestamp_row['restart'][idx] == 0:
                        break
                    idx += 1
                    an_term_reason_history = an_term_reason_history + '_' + str(anlt_timestamp_row['an_term_reason'][idx])
                    lt_term_reason_history = lt_term_reason_history + '_' + str(anlt_timestamp_row['lt_term_reason'][idx])
                    if idx == 3:
                        break
                for i, keys in enumerate(anlt_timestamp_row.keys()):
                    try:
                        anlt_timestamp[keys] = anlt_timestamp_row[keys][idx]
                    except BaseException:
                        anlt_timestamp[keys] = anlt_timestamp_row[keys]
                anlt_timestamp['an_term_reason_history'] = an_term_reason_history
                anlt_timestamp['lt_term_reason_history'] = lt_term_reason_history
                anlt_timestamp = dict(("{}_{}".format('anlt_timestamp', k), v) for k, v in anlt_timestamp.items())
                summary_dic = {**summary_dic, **anlt_timestamp}
            except BaseException:
                pass

            try:
                rx_spare9_fsm_histogram = main_dicts['rx_spare9_fsm_histogram']
                rx_spare9_fsm_histogram = dict(("{}_{}".format('spare9_rx_fsm_histogram', k), v)
                                               for k, v in rx_spare9_fsm_histogram.items())
                summary_dic = {**summary_dic, **rx_spare9_fsm_histogram}

                tx_spare9_fsm_histogram = main_dicts['tx_spare9_fsm_histogram']
                tx_spare9_fsm_histogram = dict(("{}_{}".format('spare9_tx_fsm_histogram', k), v)
                                               for k, v in tx_spare9_fsm_histogram.items())
                summary_dic = {**summary_dic, **tx_spare9_fsm_histogram}
            except BaseException:
                pass

            # analysis of results:
            try:
                last_tx_sp9 = main_dicts['txsp9_state_transition_history'][-1]
                summary_dic['Results_txsp9_last_rx_state'] = last_tx_sp9['rx_state']
                summary_dic['Results_txsp9_last_tx_state'] = last_tx_sp9['tx_state'][lane]
                summary_dic['Results_lt_timestamp_snr'] = anlt_timestamp['anlt_timestamp_final_snr'] / 1000.0
                tx_open = summary_dic['anlt_timestamp_tx_open']
                if '50G' in mode:
                    summary_dic['Results_lt_timeout'] = (tx_open > LT_TIMEOUT_PAM)
                else:
                    summary_dic['Results_lt_timeout'] = (tx_open > LT_TIMEOUT_NRZ)
            except BaseException:
                summary_dic['Results_txsp9_last_rx_state'] = 'NA'
                summary_dic['Results_txsp9_last_tx_state'] = 'NA'
                summary_dic['Results_lt_timeout'] = 'NA'
                pass

            state_transition_history_row = main_dicts['state_transition_history']
            state_start = 0
            for states in state_transition_history_row:
                state = states['new_state']
                time = datetime.datetime.strptime(states['timestamp'], '%d-%m-%Y %H:%M:%S.%f ')
                if state_start == 0:
                    start_time = time
                    start_state = state
                    delta_time = 0
                else:
                    delta_time = (time - start_time).total_seconds()
                state_start += 1
                summary_dic[f'State_transition_{state_start:2d}'] = state
                summary_dic[f'State_transition_{state_start:2d}_time'] = delta_time
            summary_dic['Results_State_total_time'] = delta_time
            summary_dic['Results_State_total_time_timeout'] = delta_time > self.link_down_timeout
            summary_dic['Results_State_transition_last'] = state
            summary_dic['Results_State_transitions'] = state_start
            summary_dic['Results_State_transition_match'] = ((state_start == 7) if self.an_mode is True else (state_start == 8))

            self.fec_mode = summary_dic["Info_fec_mode"]
            if self.fec_mode != 'NONE':
                summary_dic['Results_fec_status_cw>0'] = False
                fec_status['Status_fec_extrapolated_ber'] = 0
                fec_status['Status_fec_SER'] = 0
                if summary_dic['Status_fec_is_rs_fec']:  # Exists in RS_KP4 and RS_KR4
                    if (self.fec_mode == 'RS_KP4'):  # RS-KP4
                        for cw_idx in range(3, len(fec_cw)):
                            if fec_cw[cw_idx] > 0:
                                summary_dic['Results_fec_status_cw>0'] = True

                    elif (self.fec_mode == 'RS_KR4'):  # RS-KR4
                        for cw_idx in range(1, len(fec_cw)):
                            if fec_cw[cw_idx] > 0:
                                summary_dic['Results_fec_status_cw>0'] = True
                    summary_dic['Results_fec_SER_high'] = fec_status['Status_fec_SER'] > LANE_SER_FAULT_THRESHOLD
                    summary_dic['Results_fec_FEC_ber_high'] = fec_status['Status_fec_extrapolated_ber'] > BER_FAULT_THRESHOLD
                    summary_dic['Results_fec_uncorrectable'] = fec_status['Status_fec_uncorrectable'] > 0
                    try:
                        summary_dic['Results_fec_largest_cw'] = np.max(np.where(fec_cw))
                    except BaseException:
                        pass

            summary_dic['Results_mac_Link_state'] = mac_port_status['mac_port_status_link_state']
            summary_dic['Results_mac_high_ber'] = mac_port_status['mac_port_status_high_ber']
            summary_dic['Results_pcs_status'] = mac_port_status['mac_port_status_pcs_status']

            if neighbour:
                summary_dic = dict(("{}_{}".format('B', k), v) for k, v in summary_dic.items())
            else:
                summary_dic = dict(("{}_{}".format('A', k), v) for k, v in summary_dic.items())

            # Results:
            summary_lanes.append(summary_dic)

        return summary_lanes

    def get_new_results(self, df):
        self.mp_parse_result = True
        self.mp_parse_warning = False

        # Link Up states
        def add_link_fsm(d):
            if d['A_Results_State_transition_last'] != 'LINK_UP':
                self.mp_parse_result = False
                return 'Link Not Up'
            elif d['A_Results_State_transition_match'] == False:
                return 'Link transition: retried'
            else:
                return 'Link Up'
        df['A_Results_Final_Link_status'] = df.apply(add_link_fsm, axis=1)

        # add link fail
        def add_link_fail(d):
            if d['A_Results_mac_Link_state'] == False:
                self.mp_parse_result = False
                return 'Link Down'
            elif d['A_Results_State_total_time_timeout']:
                return 'Link up Timeout'
            else:
                return False

        df['A_Results_Final_Link_Fault'] = df.apply(add_link_fail, axis=1)

        # add FEC fail
        def add_fec_fail(d):
            if d['A_Results_fec_status_cw>0'] is True:
                return 'FEC: CW'
            elif d['A_Results_fec_uncorrectable'] is True:
                return 'FEC: Uncorrectable'
            elif d['A_Results_fec_FEC_ber_high'] is True:
                return 'FEC: BER_Fail'
            elif d['A_Results_fec_SER_high'] is True:
                return 'FEC: SER_Fail'
            else:
                return False

        try:
            df['A_Results_Final_FEC_Fail'] = df.apply(add_fec_fail, axis=1)
        except BaseException:
            df['A_Results_Final_FEC_Fail'] = False

         # add ANLT_status
        def add_anlt_status(col):
            if 'FSM_14' in col:
                return 'ANLT: completed'
            elif 'FSM_04' in col:
                return 'ANLT: stuck_at_4'
            elif 'FSM_05' in col:
                return 'ANLT: stuck_at_5'
            elif 'FSM_06' in col:
                return 'ANLT: stuck_at_6'
            elif 'FSM_09' in col:
                return 'ANLT: stuck_at_9'
            elif 'FSM_00' in col:
                return 'ANLT: not started'
            elif 'NA' in col:
                return 'NA'
            else:
                return 'ANLT: not_complete'

        try:
            df['A_Results_Final_ANLT_status'] = df['A_Results_txsp9_last_tx_state'].apply(add_anlt_status)
        except BaseException:
            df['A_Results_Final_ANLT_status'] = 'NA'

        # add SerDesFail
        def add_serdes_fail(d):
            if d['A_anlt_timestamp_restart'] != 0:
                return 'AN restarted'
            elif d['A_Results_lt_timeout']:
                return 'LT timeout'
            else:
                return False

        try:
            df['A_Results_Final_SerDes_Fail'] = df.apply(add_serdes_fail, axis=1)
        except BaseException:
            df['A_Results_Final_SerDes_Fail'] = False

        # add result
        def add_result(d):
            final_warn = d['A_Results_State_transition_match'] is False or d['A_Results_State_total_time_timeout'] is True or d[
                'A_Results_Final_FEC_Fail'] is not False or d['A_Results_Final_SerDes_Fail'] is not False
            if final_warn:
                self.mp_parse_warning = True
            return final_warn

        df['A_Results_Final_Warning'] = df.apply(add_result, axis=1)

        # add result
        def add_result(d):
            return d['A_Results_mac_Link_state'] and d['A_Results_pcs_status']

        df['Results_Result'] = df.apply(add_result, axis=1)

        # add new results
        def add_new_results(d):
            if d['A_Results_Final_ANLT_status'] != 'ANLT: completed' and self.an_mode is True:
                return d['A_Results_Final_ANLT_status']
            elif d['A_Results_Final_Link_status'] != 'Link up':
                return d['A_Results_Final_Link_status']
            elif d['A_Results_Final_SerDes_Fail']:
                return d['A_Results_Final_SerDes_Fail']
            elif d['A_Results_Final_FEC_Fail'] and self.fec_mode != 'NONE':
                return d['A_Results_Final_FEC_Fail']
            elif d['A_Results_Final_Link_Fault']:
                return d['A_Results_Final_Link_Fault']
            elif d['A_Results_State_total_time'] > 35:
                return 'Time: > 35s'
            elif d['Results_Result']:
                return 'Pass'
            else:
                return 'Unknown'

        df['A_Results_Final_NewResults'] = df.apply(add_new_results, axis=1)
        return df

    def savestate_port_test(self, file, summary, peer_port = [0, 0, 0], db_loss = 'NA'):
        folder = os.path.dirname(file)
        filename = os.path.basename(file)
        print("Parse local port save_state")
        A_side = self.crete_summary_dic(folder, filename, False, peer_port, db_loss)
        lanes = len(A_side)
        if (self.combine_peer):
            print("Parse peer port save_state")
            B_side = self.crete_summary_dic(folder, filename, True, peer_port, db_loss)
            for lane in range(lanes):
                line_summary = {**A_side[lane], **B_side[lane]}
                summary.append(line_summary)
        else:
            for lane in range(lanes):
                summary.append({**A_side[lane]})

    def savestate_create_report(self, summary, new_result = True, csv_filename = ""):
        df = pd.DataFrame(summary)
        if new_result:
            df = self.get_new_results(df)
        final_df = df.sort_index(axis=1)
        if (csv_filename):
            csv_file = csv_filename
        else:
            csv_file = self.directory.split('/')[-1]
        report = self.directory + '/' + csv_file + '.csv'
        if os.path.exists(report):
            exist_df = pd.read_csv(report)
            final_df = final_df.reset_index(drop=True)
            combined_df = pd.concat([exist_df, final_df], axis=0, ignore_index=True)
            combined_df.to_csv(report)
        else:
            final_df.to_csv(report)

    def make_filename(self, iteration, mode, portstr):
        return "{}/{}_{}_{}.json".format(self.directory, iteration, mode, portstr)


if __name__ == '__main__':
    '''
       Arguments of save_state_parse.py:
        combine_peer = True | False
        link_down_timeout = 90
        json_file_directory
    '''
    ssp = save_state_parse()
    if len(sys.argv) == 4:
        ssp.directory = sys.argv[3]
        ssp.combine_peer = sys.argv[1]
    else:
        ssp.directory = "."
        ssp.combine_peer = False

    df_merged = pd.DataFrame()
    files = os.listdir(ssp.directory)
    summary = []

    for file in files:
        ssp.savestate_port_test(file, summary)
    df = pd.DataFrame(summary)
    df = ssp.get_new_results(df)  # add new results column
    Final_df = df.sort_index(axis=1)
    Final_df.to_csv(ssp.directory + '.csv')
    df_merged = pd.concat([df_merged, Final_df], ignore_index=True)
    df_merged.to_csv(ssp.directory + 'merged.csv')
