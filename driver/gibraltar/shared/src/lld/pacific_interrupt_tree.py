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


# @file
#
# Pacific interrupt tree is made of nodes and optionally bits which map to next level nodes.
# A "bit" that references another node is a "summary bit".
# A "bit" that does not reference any node is leaf of the interrupt tree and is a "cause bit".
#
# This is the basic structure of the interrupt tree:
#   interrupt_node {
#     status-reg = ...,
#     mask-reg = ...,
#     bits = {
#       0: {
#            name = "some-block-interrupt-summary",
#            type = "SUMMARY",
#            children = [ interrupt_node {...}, interrupt_node {...}, ...]
#       }
#       1: {
#            name = "ecc_1b_error",
#            type = "ECC_ERROR",
#            children = None
#       }
#       ...
#     }
#   }

# Known issues:
# -------------
# These master interrupts are not wired to any summary bit:
#     npuh.fi.interrupt_register
#     slice[].npu.rxpp_term.fi_eng[].interrupt_register
#     slice[].npu.rxpp_term.fi_stage.interrupt_register
#     slice[].npu.sna.interrupt_register
#     mmu_buff.interrupt_register
#
# Pending summary bits that point to clear next level (probably not modelled OR logic)
#     ics_top.general_interrupt_register, b0: name=IcsSlice0Interrupt, type=SUMMARY
#     ics_top.general_interrupt_register, b1: name=IcsSlice1Interrupt, type=SUMMARY
#     ics_top.general_interrupt_register, b2: name=IcsSlice2Interrupt, type=SUMMARY
#     ics_top.general_interrupt_register, b3: name=IcsSlice3Interrupt, type=SUMMARY
#     ics_top.general_interrupt_register, b4: name=IcsSlice4Interrupt, type=SUMMARY
#     ics_top.general_interrupt_register, b5: name=IcsSlice5Interrupt, type=SUMMARY
#

from common_interrupt_tree import *
import json
import lldcli


def create_interrupt_tree(lbr_filename):
    initialize(lbr_filename)

    # Interrupt registers are identical between REV_1 and REV2
    pacific_tree = lldcli.pacific_tree.create(lldcli.la_device_revision_e_PACIFIC_A0)

    msi_root = node_MsiMaster(pacific_tree)

    non_wired_roots = create_non_wired_roots(pacific_tree)
    all_roots = [msi_root] + non_wired_roots

    validate_and_print_summary(pacific_tree, all_roots)

    return all_roots

##############################################################################
# Tree nodes
##############################################################################


def node_MsiMaster(lbr_tree):
    path = lbr_tree.sbif
    status = path.msi_master_interrupt_reg
    mask = path.msi_master_interrupt_reg_mask
    bits = {
        0: bit('MsiBlocks0Int', [node_MsiBlocksInterruptSummaryReg0(lbr_tree)]),
        1: bit('MsiBlocks1Int', [node_MsiBlocksInterruptSummaryReg1(lbr_tree)]),
        2: bit('MsiPcieEcc1bErrInt', type=TYPE_ECC_1B),
        3: bit('MsiPcieEcc2bErrInt', type=TYPE_ECC_2B, sw_action=SW_ACTION_SOFT_RESET),
        4: bit('MsiSbifAeEcc1bErrInt', type=TYPE_ECC_1B),
        5: bit('MsiSbifAeEcc2bErrInt', type=TYPE_ECC_2B, sw_action=SW_ACTION_SOFT_RESET),
        6: bit('MsiSbifSyncEcc1bErrInt', type=TYPE_ECC_1B),
        7: bit('MsiSbifSyncEcc2bErrInt', type=TYPE_ECC_2B, sw_action=SW_ACTION_SOFT_RESET),
        8: bit('MsiCssMemEvenEcc1bErrInt', type=TYPE_ECC_1B),
        9: bit('MsiCssMemEvenEcc2bErrInt', type=TYPE_ECC_2B, sw_action=SW_ACTION_SOFT_RESET),
        10: bit('MsiCssMemOddEcc1bErrInt', type=TYPE_ECC_1B),
        11: bit('MsiCssMemOddEcc2bErrInt', type=TYPE_ECC_2B, sw_action=SW_ACTION_SOFT_RESET),
        12: bit('MsiAccessEngineErrInt', type=TYPE_MISCONFIGURATION),
        13: bit('MsiAccessEngineErrInt', type=TYPE_MISCONFIGURATION),
        14: bit('MsiAccessEngineErrInt', type=TYPE_MISCONFIGURATION),
        15: bit('MsiAccessEngineErrInt', type=TYPE_MISCONFIGURATION),
        16: bit('MsiAccessEngineErrInt', type=TYPE_MISCONFIGURATION),
        17: bit('MsiAccessEngineErrInt', type=TYPE_MISCONFIGURATION),
        18: bit('MsiAccessEngineErrInt', type=TYPE_MISCONFIGURATION),
        19: bit('MsiAccessEngineErrInt', type=TYPE_MISCONFIGURATION),
        20: bit('MsiAccessEngineDoneInt', type=TYPE_NO_ERR_INTERNAL),
        21: bit('MsiAccessEngineDoneInt', type=TYPE_NO_ERR_INTERNAL),
        22: bit('MsiAccessEngineDoneInt', type=TYPE_NO_ERR_INTERNAL),
        23: bit('MsiAccessEngineDoneInt', type=TYPE_NO_ERR_INTERNAL),
        24: bit('MsiAccessEngineDoneInt', type=TYPE_NO_ERR_INTERNAL),
        25: bit('MsiAccessEngineDoneInt', type=TYPE_NO_ERR_INTERNAL),
        26: bit('MsiAccessEngineDoneInt', type=TYPE_NO_ERR_INTERNAL),
        27: bit('MsiAccessEngineDoneInt', type=TYPE_NO_ERR_INTERNAL),
        28: bit('MsiDmaEngineErrInt', type=TYPE_MISCONFIGURATION),
        29: bit('MsiDmaEngineDoneInt', type=TYPE_NO_ERR_INTERNAL),
        30: bit('MsiDmaEngineDropFcInt', type=TYPE_THRESHOLD_CROSSED),
    }
    return interrupt_node(status, mask, bits, is_mask_active_low=False)


def node_MsiBlocksInterruptSummaryReg0(lbr_tree):
    path = lbr_tree
    status = path.sbif.msi_blocks_interrupt_summary_reg0
    mask = path.sbif.msi_blocks_interrupt_summary_reg0_mask
    bits = {
        0: bit('MsiCdbTopInterruptSummary', [node_cdb_top(path.cdb)]),
        1: bit('MsiCountersInterruptSummary', [node_counters(path.counters)]),
        2: bit('MsiDramControlInterruptSummary', [node_dvoq(path)]),
        3: bit('MsiEgrInterruptSummary', [node_tx_cgm_top(path)]),
        4: bit('MsiFdllInterruptSummary', [node_fdll_shared_mem(path)]),
        5: bit('MsiFllbInterruptSummary', [node_rx_counters(path)]),
        6: bit('MsiIcsInterruptSummary', [node_ics_top(path)]),
        7: bit('MsiIdbInterruptSummary', [
            node_idb_top(path.slice_pair[0].idb.top),
            node_idb_res(path.slice_pair[0].idb.res)
        ]),
        8: bit('MsiIdbInterruptSummary', [
            node_idb_top(path.slice_pair[1].idb.top),
            node_idb_res(path.slice_pair[1].idb.res)
        ]),
        9: bit('MsiIdbInterruptSummary', [
            node_idb_top(path.slice_pair[2].idb.top),
            node_idb_res(path.slice_pair[2].idb.res)
        ]),

        10: bit('MsiIfgInterruptSummary', [node_ifgb(path.slice[0].ifg[0])]),
        11: bit('MsiIfgInterruptSummary', [node_ifgb(path.slice[0].ifg[1])]),
        12: bit('MsiIfgInterruptSummary', [node_ifgb(path.slice[1].ifg[0])]),
        13: bit('MsiIfgInterruptSummary', [node_ifgb(path.slice[1].ifg[1])]),
        14: bit('MsiIfgInterruptSummary', [node_ifgb(path.slice[2].ifg[0])]),
        15: bit('MsiIfgInterruptSummary', [node_ifgb(path.slice[2].ifg[1])]),
        16: bit('MsiIfgInterruptSummary', [node_ifgb(path.slice[3].ifg[0])]),
        17: bit('MsiIfgInterruptSummary', [node_ifgb(path.slice[3].ifg[1])]),
        18: bit('MsiIfgInterruptSummary', [node_ifgb(path.slice[4].ifg[0])]),
        19: bit('MsiIfgInterruptSummary', [node_ifgb(path.slice[4].ifg[1])]),
        20: bit('MsiIfgInterruptSummary', [node_ifgb(path.slice[5].ifg[0])]),
        21: bit('MsiIfgInterruptSummary', [node_ifgb(path.slice[5].ifg[1])]),
        22: bit('MsiNwReorderInterruptSummary', [node_nw_reorder(path)]),
        23: bit('MsiPpReorderInterruptSummary', []),  # This bit is not wired to anything, PP_REORDER is in NW_REORDER subtree
        24: bit('MsiPdoqInterruptSummary', [node_pdoq_shared_mem(path)]),
        25: bit('MsiPdvoqInterruptSummary', [
                # fabric_pdvoq and pdvoq have identical interrupt registers.
                node_pdvoq_slice(path.slice[0].pdvoq),
                node_pdvoq_slice(path.slice[1].pdvoq),
                node_pdvoq_slice(path.slice[2].pdvoq),
                node_pdvoq_slice(path.slice[3].pdvoq),
                node_pdvoq_slice(path.slice[4].fabric_pdvoq),
                node_pdvoq_slice(path.slice[5].fabric_pdvoq),
                node_pdvoq_shared_mma(path.pdvoq_shared_mma),
                node_pdvoq_empd(path.pdvoq.empd[0]),
                node_pdvoq_empd(path.pdvoq.empd[1]),
                node_pdvoq_empd(path.pdvoq.empd[2]),
                node_pdvoq_empd(path.pdvoq.empd[3]),
                node_pdvoq_empd(path.pdvoq.empd[4]),
                node_pdvoq_empd(path.pdvoq.empd[5]),
                node_pdvoq_empd(path.pdvoq.empd[6]),
                node_pdvoq_empd(path.pdvoq.empd[7]),
                node_pdvoq_empd(path.pdvoq.empd[8]),
                node_pdvoq_empd(path.pdvoq.empd[9]),
                node_pdvoq_empd(path.pdvoq.empd[10]),
                node_pdvoq_empd(path.pdvoq.empd[11]),
                node_pdvoq_empd(path.pdvoq.empd[12]),
                node_pdvoq_empd(path.pdvoq.empd[13]),
                node_pdvoq_empd(path.pdvoq.empd[14]),
                node_pdvoq_empd(path.pdvoq.empd[15]),
                ]),
        26: bit('MsiReassemblyInterruptSummary', [node_reassembly(path.reassembly)]),
        27: bit('MsiRxCgmInterruptSummary', [node_rx_cgm(path.rx_cgm)]),
        28: bit('MsiRxMeterInterruptSummary', [node_rx_meter_top(path.rx_meter)]),
        29: bit('MsiRxPdrInterruptSummary', [node_rx_pdr(path)]),
        30: bit('MsiSchInterruptSummary', [node_sch_top(path)])
    }

    return interrupt_node(status, mask, bits, is_mask_active_low=False)


def node_MsiBlocksInterruptSummaryReg1(lbr_tree):
    path = lbr_tree.sbif
    status = path.msi_blocks_interrupt_summary_reg1
    mask = path.msi_blocks_interrupt_summary_reg1_mask
    bits = {
        0: bit('MsiRxppTermInterruptSummary', [
            node_rxpp_term(lbr_tree.slice[0].npu.rxpp_term.rxpp_term),
            node_npe(lbr_tree.slice[0].npu.rxpp_term.npe[0]),
            node_npe(lbr_tree.slice[0].npu.rxpp_term.npe[1]),
            node_npe(lbr_tree.slice[0].npu.rxpp_term.npe[2])
        ]),
        1: bit('MsiRxppTermInterruptSummary', [
            node_rxpp_term(lbr_tree.slice[1].npu.rxpp_term.rxpp_term),
            node_npe(lbr_tree.slice[1].npu.rxpp_term.npe[0]),
            node_npe(lbr_tree.slice[1].npu.rxpp_term.npe[1]),
            node_npe(lbr_tree.slice[1].npu.rxpp_term.npe[2])
        ]),
        2: bit('MsiRxppTermInterruptSummary', [
            node_rxpp_term(lbr_tree.slice[2].npu.rxpp_term.rxpp_term),
            node_npe(lbr_tree.slice[2].npu.rxpp_term.npe[0]),
            node_npe(lbr_tree.slice[2].npu.rxpp_term.npe[1]),
            node_npe(lbr_tree.slice[2].npu.rxpp_term.npe[2])
        ]),
        3: bit('MsiRxppTermInterruptSummary', [
            node_rxpp_term(lbr_tree.slice[3].npu.rxpp_term.rxpp_term),
            node_npe(lbr_tree.slice[3].npu.rxpp_term.npe[0]),
            node_npe(lbr_tree.slice[3].npu.rxpp_term.npe[1]),
            node_npe(lbr_tree.slice[3].npu.rxpp_term.npe[2])
        ]),
        4: bit('MsiRxppTermInterruptSummary', [
            node_rxpp_term(lbr_tree.slice[4].npu.rxpp_term.rxpp_term),
            node_npe(lbr_tree.slice[4].npu.rxpp_term.npe[0]),
            node_npe(lbr_tree.slice[4].npu.rxpp_term.npe[1]),
            node_npe(lbr_tree.slice[4].npu.rxpp_term.npe[2])
        ]),
        5: bit('MsiRxppTermInterruptSummary', [
            node_rxpp_term(lbr_tree.slice[5].npu.rxpp_term.rxpp_term),
            node_npe(lbr_tree.slice[5].npu.rxpp_term.npe[0]),
            node_npe(lbr_tree.slice[5].npu.rxpp_term.npe[1]),
            node_npe(lbr_tree.slice[5].npu.rxpp_term.npe[2])
        ]),
        6: bit('MsiRxppFwdInterruptSummary', [node_rxpp_fwd(lbr_tree.slice[0].npu)]),
        7: bit('MsiRxppFwdInterruptSummary', [node_rxpp_fwd(lbr_tree.slice[1].npu)]),
        8: bit('MsiRxppFwdInterruptSummary', [node_rxpp_fwd(lbr_tree.slice[2].npu)]),
        9: bit('MsiRxppFwdInterruptSummary', [node_rxpp_fwd(lbr_tree.slice[3].npu)]),
        10: bit('MsiRxppFwdInterruptSummary', [node_rxpp_fwd(lbr_tree.slice[4].npu)]),
        11: bit('MsiRxppFwdInterruptSummary', [node_rxpp_fwd(lbr_tree.slice[5].npu)]),
        12: bit('MsiSdbInterruptSummary', [node_sdb_mac(lbr_tree.sdb)]),
        13: bit('MsiSmsInterruptSummary', [node_sms_main(lbr_tree)]),
        14: bit('MsiTsMonInterruptSummary', [node_ts_mon(lbr_tree.ts_mon)]),
        15: bit('MsiTxppInterruptSummary', [node_txpp(lbr_tree.slice[0].npu.txpp)]),
        16: bit('MsiTxppInterruptSummary', [node_txpp(lbr_tree.slice[1].npu.txpp)]),
        17: bit('MsiTxppInterruptSummary', [node_txpp(lbr_tree.slice[2].npu.txpp)]),
        18: bit('MsiTxppInterruptSummary', [node_txpp(lbr_tree.slice[3].npu.txpp)]),
        19: bit('MsiTxppInterruptSummary', [node_txpp(lbr_tree.slice[4].npu.txpp)]),
        20: bit('MsiTxppInterruptSummary', [node_txpp(lbr_tree.slice[5].npu.txpp)]),
        21: bit('MsiHbmloInterruptSummary', [node_hbm(lbr_tree.hbm.lo)]),
        22: bit('MsiHbmhiInterruptSummary', [node_hbm(lbr_tree.hbm.hi)]),
        23: bit('MsiMmuInterruptSummary', [node_mmu(lbr_tree)]),
        24: bit('MsiCsmsInterruptSummary', [node_csms(lbr_tree.csms)]),
        25: bit('MsiFteInterruptSummary', [node_fte(lbr_tree.dmc.fte)]),
        26: bit('MsiFrmInterruptSummary', [node_frm(lbr_tree.dmc.frm)]),
        27: bit('MsiPierInterruptSummary', [node_pier(lbr_tree.dmc.pier)]),
        28: bit('MsiNpuHostInterruptSummary', [
                node_npu_host(lbr_tree.npuh.host),
                node_npe(lbr_tree.npuh.npe),
                ]),
        29: bit('MsiMrbInterruptSummary', [node_mrb(lbr_tree.dmc.mrb)]),
    }
    return interrupt_node(status, mask, bits, is_mask_active_low=False)


def node_idb_top(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('idb_interruptsSummary', [node_idb_top_idb_interrupts(path)]),
        2: bit('EmResponseInterruptSummary', [node_idb_top_em_response(path)]),
    }
    return master_interrupt_node(status, bits)


def node_idb_top_idb_interrupts(path):
    status = path.idb_interrupts
    mask = path.idb_interrupts_mask
    bits = {
        0: bit('slice0_service_relay_table_address_out_of_bounds', type=TYPE_OTHER),
        1: bit('slice1_service_relay_table_address_out_of_bounds', type=TYPE_OTHER)
    }
    return interrupt_node(status, mask, bits)


def node_idb_top_em_response(path):
    status = path.em_response_interrupt
    mask = path.em_response_interrupt_mask
    bits = {
        0: bit('Slice0_SmallEncTableResp', type=TYPE_NO_ERR_NOTIFICATION),
        1: bit('Slice1_SmallEncTableResp', type=TYPE_NO_ERR_NOTIFICATION),
        2: bit('L3Dlp0TableResp', type=TYPE_NO_ERR_NOTIFICATION),
        3: bit('MymacTable0Resp', type=TYPE_NO_ERR_NOTIFICATION),
        4: bit('MymacTable1Resp', type=TYPE_NO_ERR_NOTIFICATION),
    }
    return interrupt_node(status, mask, bits)


def node_idb_res(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('idb_interruptsSummary', [node_idb_res_idb_interrupts(path)]),
        2: bit('EmResponseInterruptSummary', [node_idb_res_em_response(path)]),
    }
    return master_interrupt_node(status, bits)


def node_idb_res_idb_interrupts(path):
    status = path.idb_interrupts
    mask = path.idb_interrupts_mask
    bits = {
        0: bit('slice0_native_lb_member_table_em_miss', type=TYPE_MISCONFIGURATION),
        1: bit('slice0_path_lb_member_table_em_miss', type=TYPE_MISCONFIGURATION),
        2: bit('slice0_port_npp_lb_member_table_em_miss', type=TYPE_MISCONFIGURATION),
        3: bit('slice0_port_dsp_lb_member_table_em_miss', type=TYPE_MISCONFIGURATION),
        4: bit('slice0_native_protection_table_type_not_valid', type=TYPE_MISCONFIGURATION),
        5: bit('slice0_path_protection_table_type_not_valid', type=TYPE_MISCONFIGURATION),
        6: bit('slice0_port_protection_table_type_not_valid', type=TYPE_MISCONFIGURATION),
        7: bit('slice1_native_lb_member_table_em_miss', type=TYPE_MISCONFIGURATION),
        8: bit('slice1_path_lb_member_table_em_miss', type=TYPE_MISCONFIGURATION),
        9: bit('slice1_port_npp_lb_member_table_em_miss', type=TYPE_MISCONFIGURATION),
        10: bit('slice1_port_dsp_lb_member_table_em_miss', type=TYPE_MISCONFIGURATION),
        11: bit('slice1_native_protection_table_type_not_valid', type=TYPE_MISCONFIGURATION),
        12: bit('slice1_path_protection_table_type_not_valid', type=TYPE_MISCONFIGURATION),
        13: bit('slice1_port_protection_table_type_not_valid', type=TYPE_MISCONFIGURATION),
    }
    return interrupt_node(status, mask, bits)


def node_idb_res_em_response(path):
    status = path.em_response_interrupt
    mask = path.em_response_interrupt_mask
    bits = {
        0: bit('Slice0NativeLbMemberTableResp', type=TYPE_NO_ERR_NOTIFICATION),
        1: bit('Slice1NativeLbMemberTableResp', type=TYPE_NO_ERR_NOTIFICATION),
        2: bit('Slice0PathLbMemberTableResp', type=TYPE_NO_ERR_NOTIFICATION),
        3: bit('Slice1PathLbMemberTableResp', type=TYPE_NO_ERR_NOTIFICATION),
        4: bit('Slice0PortNppLbMemberTableResp', type=TYPE_NO_ERR_NOTIFICATION),
        5: bit('Slice1PortNppLbMemberTableResp', type=TYPE_NO_ERR_NOTIFICATION),
        6: bit('Slice0PortDspLbMemberTableResp', type=TYPE_NO_ERR_NOTIFICATION),
        7: bit('Slice1PortDspLbMemberTableResp', type=TYPE_NO_ERR_NOTIFICATION),
    }
    return interrupt_node(status, mask, bits)


def node_ifgb(path):
    status = path.ifgb.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path.ifgb)]),
        1: bit('IfgInterruptSummarySummary', [node_ifg_interrupt_summary(path)]),
        2: bit('IfgbInterruptRegSummary', [node_ifgb_interrupt_reg(path)]),
        3: bit('TxTsfOvfInterruptRegSummary', [node_tx_tsf_ovf_interrupt_reg(path)]),
    }
    return master_interrupt_node(status, bits)


def node_ifg_interrupt_summary(path):
    status = path.ifgb.ifg_interrupt_summary
    mask = path.ifgb.ifg_interrupt_summary_mask
    bits = {
        0: bit('MacPool0', [node_mac_pool8(path.mac_pool8[0])]),
        1: bit('MacPool1', [node_mac_pool8(path.mac_pool8[1])]),
        2: bit('MacPool2', [node_mac_pool2(path.mac_pool2)]),
        3: bit('SrdPool', [node_serdes_pool18(path.serdes_pool)]),
    }
    return interrupt_node(status, mask, bits)


def node_ifgb_interrupt_reg(path):
    status = path.ifgb.ifgb_interrupt_reg
    mask = path.ifgb.ifgb_interrupt_reg_mask
    bits = {
        0: bit('RxMlpSync', type=TYPE_OTHER),
        1: bit('RxMlpSyncTimeout', type=TYPE_OTHER),
        2: bit('DbgBufOverflow', type=TYPE_LACK_OF_RESOURCES),
        3: bit('RxRcontextAllocErr', type=TYPE_LACK_OF_RESOURCES),
    }
    return interrupt_node(status, mask, bits)


def node_tx_tsf_ovf_interrupt_reg(path):
    status = path.ifgb.tx_tsf_ovf_interrupt_reg
    mask = path.ifgb.tx_tsf_ovf_interrupt_reg_mask
    bits = {}
    for i in range(18):
        bits[i] = bit('Port{0}TxInTsfOvf'.format(i), type=TYPE_MAC_LINK_ERROR)
    return interrupt_node(status, mask, bits)


def node_mac_pool8(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('RxLinkStatusDownSummary', [node_mac_rx_link_status_down(path, 8)]),
        2: bit('RxPcsLinkStatusDownSummary', [node_mac_rx_pcs_link_status_down(path, 8)]),
        3: bit('RxPcsAlignStatusDownSummary', [node_mac_rx_pcs_align_status_down(path, 8)]),
        4: bit('RxPcsHiBerUpSummary', [node_mac_rx_pcs_hi_ber_up(path, 8)]),
        5: bit('TxCrcErrInterruptRegisterSummary', [node_mac_tx_crc_err(path, 8)]),
        6: bit('TxUnderrunErrInterruptRegisterSummary', [node_mac_tx_underrun_err(path, 8)]),
        7: bit('TxMissingEopErrInterruptRegisterSummary', [node_mac_tx_missing_eop_err(path, 8)]),
        8: bit('RxCodeErrInterruptRegisterSummary', [node_mac_rx_code_err(path, 8)]),
        9: bit('RxCrcErrInterruptRegisterSummary', [node_mac_rx_crc_err(path, 8)]),
        10: bit('RxInvertCrcErrInterruptRegisterSummary', [node_mac_rx_invert_crc_err(path, 8)]),
        11: bit('RxOobInvertCrcErrInterruptRegisterSummary', [node_mac_rx_oob_invert_crc_err(path, 8)]),
        12: bit('RxOversizeErrInterruptRegisterSummary', [node_mac_rx_oversize_err(path, 8)]),
        13: bit('RxUndersizeErrInterruptRegisterSummary', [node_mac_rx_undersize_err(path, 8)]),

        14: bit('RxDeskFifOvfInterruptRegister0Summary', [node_mac_rx_deskew_fifo_ovf(path, 0)]),
        15: bit('RxDeskFifOvfInterruptRegister1Summary', [node_mac_rx_deskew_fifo_ovf(path, 1)]),
        16: bit('RxDeskFifOvfInterruptRegister2Summary', [node_mac_rx_deskew_fifo_ovf(path, 2)]),
        17: bit('RxDeskFifOvfInterruptRegister3Summary', [node_mac_rx_deskew_fifo_ovf(path, 3)]),
        18: bit('RxDeskFifOvfInterruptRegister4Summary', [node_mac_rx_deskew_fifo_ovf(path, 4)]),
        19: bit('RxDeskFifOvfInterruptRegister5Summary', [node_mac_rx_deskew_fifo_ovf(path, 5)]),
        20: bit('RxDeskFifOvfInterruptRegister6Summary', [node_mac_rx_deskew_fifo_ovf(path, 6)]),
        21: bit('RxDeskFifOvfInterruptRegister7Summary', [node_mac_rx_deskew_fifo_ovf(path, 7)]),

        22: bit('RxPmaSigOkLossInterruptRegisterSummary', [node_mac_rx_pma_sig_ok_loss(path, 8)]),
        23: bit('RsfRxHighSerInterruptRegisterSummary', [node_mac_rsf_rx_high_ser(path, 8)]),
        24: bit('RsfRxDegradedSerInterruptRegisterSummary', [node_mac_rsf_rx_degraded_ser(path, 8)]),
        25: bit('RsfRxRmDegradedSerInterruptRegisterSummary', [node_mac_rsf_rx_rm_degraded_ser(path, 8)]),
        26: bit('DeviceTimeOverrideInterruptRegisterSummary', [node_mac_device_time_override(path, 8)]),
    }
    return master_interrupt_node(status, bits)


def node_mac_pool2(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('RxLinkStatusDownSummary', [node_mac_rx_link_status_down(path, 2)]),
        2: bit('RxPcsLinkStatusDownSummary', [node_mac_rx_pcs_link_status_down(path, 2)]),
        3: bit('RxPcsAlignStatusDownSummary', [node_mac_rx_pcs_align_status_down(path, 2)]),
        4: bit('RxPcsHiBerUpSummary', [node_mac_rx_pcs_hi_ber_up(path, 2)]),
        5: bit('RxCodeErrInterruptRegisterSummary', [node_mac_rx_code_err(path, 2)]),
        6: bit('TxCrcErrInterruptRegisterSummary', [node_mac_tx_crc_err(path, 2)]),
        7: bit('TxUnderrunErrInterruptRegisterSummary', [node_mac_tx_underrun_err(path, 2)]),
        8: bit('TxMissingEopErrInterruptRegisterSummary', [node_mac_tx_missing_eop_err(path, 2)]),
        9: bit('RxCrcErrInterruptRegisterSummary', [node_mac_rx_crc_err(path, 2)]),
        10: bit('RxInvertCrcErrInterruptRegisterSummary', [node_mac_rx_invert_crc_err(path, 2)]),
        11: bit('RxOobInvertCrcErrInterruptRegisterSummary', [node_mac_rx_oob_invert_crc_err(path, 2)]),
        12: bit('RxOversizeErrInterruptRegisterSummary', [node_mac_rx_oversize_err(path, 2)]),
        13: bit('RxUndersizeErrInterruptRegisterSummary', [node_mac_rx_undersize_err(path, 2)]),

        14: bit('RxDeskFifOvfInterruptRegister0Summary', [node_mac_rx_deskew_fifo_ovf(path, 0)]),
        15: bit('RxDeskFifOvfInterruptRegister1Summary', [node_mac_rx_deskew_fifo_ovf(path, 1)]),

        16: bit('RxPmaSigOkLossInterruptRegisterSummary', [node_mac_rx_pma_sig_ok_loss(path, 2)]),
        17: bit('RsfRxHighSerInterruptRegisterSummary', [node_mac_rsf_rx_high_ser(path, 2)]),
        18: bit('RsfRxDegradedSerInterruptRegisterSummary', [node_mac_rsf_rx_degraded_ser(path, 2)]),
        19: bit('RsfRxRmDegradedSerInterruptRegisterSummary', [node_mac_rsf_rx_rm_degraded_ser(path, 2)]),
        20: bit('DeviceTimeOverrideInterruptRegisterSummary', [node_mac_device_time_override(path, 2)]),
    }
    return master_interrupt_node(status, bits)


def node_mac_rx_link_status_down(path, lanes_n):
    return node_mac_lane_interrupt(path, lanes_n, 'rx_link_status_down', 'RxLinkStatusDown', TYPE_MAC_LINK_DOWN, is_masked=True)


def node_mac_rx_pcs_link_status_down(path, lanes_n):
    return node_mac_lane_interrupt(
        path,
        lanes_n,
        'rx_pcs_link_status_down',
        'RxPcsLinkStatusDown',
        TYPE_MAC_LINK_DOWN,
        is_masked=True)


def node_mac_rx_pcs_align_status_down(path, lanes_n):
    return node_mac_lane_interrupt(
        path,
        lanes_n,
        'rx_pcs_align_status_down',
        'RxPcsAlignStatusDown',
        TYPE_MAC_LINK_DOWN,
        is_masked=True)


def node_mac_rx_pcs_hi_ber_up(path, lanes_n):
    return node_mac_lane_interrupt(path, lanes_n, 'rx_pcs_hi_ber_up', 'RxPcsHiBerUp', TYPE_MAC_LINK_DOWN, is_masked=True)


def node_mac_tx_crc_err(path, lanes_n):
    return node_mac_lane_interrupt(path, lanes_n, 'tx_crc_err_interrupt_register', 'TxCrcErr', TYPE_MAC_LINK_ERROR, is_masked=True)


def node_mac_tx_underrun_err(path, lanes_n):
    return node_mac_lane_interrupt(path, lanes_n, 'tx_underrun_err_interrupt_register',
                                   'TxUnderrunErr', TYPE_MAC_LINK_ERROR, is_masked=True)


def node_mac_tx_missing_eop_err(path, lanes_n):
    return node_mac_lane_interrupt(path, lanes_n, 'tx_missing_eop_err_interrupt_register',
                                   'TxMissingEopErr', TYPE_MAC_LINK_ERROR, is_masked=True)


def node_mac_rx_code_err(path, lanes_n):
    return node_mac_lane_interrupt(path, lanes_n, 'rx_code_err_interrupt_register',
                                   'RxCodeErr', TYPE_MAC_LINK_ERROR, is_masked=True)


def node_mac_rx_crc_err(path, lanes_n):
    return node_mac_lane_interrupt(path, lanes_n, 'rx_crc_err_interrupt_register', 'RxCrcErr', TYPE_MAC_LINK_ERROR, is_masked=True)


def node_mac_rx_invert_crc_err(path, lanes_n):
    return node_mac_lane_interrupt(path, lanes_n, 'rx_invert_crc_err_interrupt_register',
                                   'RxInvertCrcErr', TYPE_MAC_LINK_ERROR, is_masked=True)


def node_mac_rx_oob_invert_crc_err(path, lanes_n):
    return node_mac_lane_interrupt(
        path,
        lanes_n,
        'rx_oob_invert_crc_err_interrupt_register',
        'RxOobInvertCrcErr',
        TYPE_MAC_LINK_ERROR,
        is_masked=True)


def node_mac_rx_oversize_err(path, lanes_n):
    return node_mac_lane_interrupt(path, lanes_n, 'rx_oversize_err_interrupt_register',
                                   'RxOversizeErr', TYPE_MAC_LINK_ERROR, is_masked=True)


def node_mac_rx_undersize_err(path, lanes_n):
    return node_mac_lane_interrupt(path, lanes_n, 'rx_undersize_err_interrupt_register',
                                   'RxUndersizeErr', TYPE_MAC_LINK_ERROR, is_masked=True)


def node_mac_rx_pma_sig_ok_loss(path, lanes_n):
    return node_mac_lane_interrupt(path, lanes_n, 'rx_pma_sig_ok_loss_interrupt_register',
                                   'RxSignalOkLoss', TYPE_MAC_LINK_DOWN, is_masked=True)


def node_mac_rsf_rx_high_ser(path, lanes_n):
    return node_mac_lane_interrupt(path, lanes_n, 'rsf_rx_high_ser_interrupt_register',
                                   'RxHighSer', TYPE_MAC_LINK_DOWN, is_masked=True)


def node_mac_rsf_rx_degraded_ser(path, lanes_n):
    return node_mac_lane_interrupt(path, lanes_n, 'rsf_rx_degraded_ser_interrupt_register',
                                   'RxDegradedSer', TYPE_MAC_LINK_ERROR, is_masked=True)


def node_mac_rsf_rx_rm_degraded_ser(path, lanes_n):
    return node_mac_lane_interrupt(
        path,
        lanes_n,
        'rsf_rx_rm_degraded_ser_interrupt_register',
        'RxRmDegradedSer',
        TYPE_MAC_LINK_ERROR,
        is_masked=True)


def node_mac_device_time_override(path, lanes_n):
    return node_mac_lane_interrupt(
        path,
        lanes_n,
        'device_time_override_interrupt_register',
        'DeviceTimeOverride',
        TYPE_MAC_LINK_ERROR,
        is_masked=True)


# Generate a node for a mac_pool interrupt register which has 1 bit per lane
#
# Example of generated code:
#   status = slice[0].ifg[0].mac_pool2.rx_link_status_down
#   mask = slice[0].ifg[0].mac_pool2.rx_link_status_down_mask
#   bits = {
#       0: bit('RxLinkStatusDown0', type = TYPE_MAC_LINK_DOWN),
#       1: bit('RxLinkStatusDown1', type = TYPE_MAC_LINK_DOWN),
#   }
def node_mac_lane_interrupt(
        path,
        lanes_n,
        reg_name,
        bit_name_base,
        interrupt_type,
        interrupt_sw_action=SW_ACTION_NONE,
        is_masked=False):
    status = eval('path.' + reg_name)
    mask = eval('path.' + reg_name + '_mask')
    bits = {}
    for i in range(lanes_n):
        bits[i] = bit('{0}{1}'.format(bit_name_base, i), type=interrupt_type, sw_action=interrupt_sw_action, is_masked=is_masked)
    return interrupt_node(status, mask, bits)


def node_mac_rx_deskew_fifo_ovf(path, lane_i):
    status = eval('path.rx_desk_fif_ovf_interrupt_register{0}'.format(lane_i))
    mask = eval('path.rx_desk_fif_ovf_interrupt_register{0}_mask'.format(lane_i))
    bits = {}
    for fifo_i in range(10):
        bits[fifo_i] = bit('RxDeskewFifOvf{0}_{1}'.format(lane_i, fifo_i), type=TYPE_MAC_LINK_DOWN, is_masked=True)
    return interrupt_node(status, mask, bits)


def node_serdes_pool18(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('SbmEccErrorInterruptRegisterSummary', [node_serdes_sbus_master(path)]),
        2: bit('SerDesSingleEccErrorInterruptRegisterSummary', [node_serdes_sbe(path)]),
        3: bit('SerDesDoubleEccErrorInterruptRegisterSummary', [node_serdes_dbe(path)]),
    }
    return master_interrupt_node(status, bits)


def node_serdes_sbus_master(path):
    status = path.sbm_ecc_error_interrupt_register
    mask = path.sbm_ecc_error_interrupt_register_mask
    bits = {
        0: bit('Sbe', type=TYPE_ECC_1B),
        1: bit('Dbe', type=TYPE_ECC_2B)
    }
    return interrupt_node(status, mask, bits)


def node_serdes_sbe(path):
    status = path.ser_des_single_ecc_error_interrupt_register
    mask = path.ser_des_single_ecc_error_interrupt_register_mask
    bits = {}
    for i in range(18):
        bits[i] = bit('Sbe{0}'.format(i), type=TYPE_ECC_1B)
    return interrupt_node(status, mask, bits)


def node_serdes_dbe(path):
    status = path.ser_des_double_ecc_error_interrupt_register
    mask = path.ser_des_double_ecc_error_interrupt_register_mask
    bits = {}
    for i in range(18):
        bits[i] = bit('Dbe{0}'.format(i), type=TYPE_ECC_2B)
    return interrupt_node(status, mask, bits)


def node_txpp(path):
    status = path.txpp.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path.txpp)]),
        1: bit('InternalInterruptSummary', [node_txpp_InternalInterrupt(path)])
    }
    return master_interrupt_node(status, bits)


def node_txpp_InternalInterrupt(path):
    status = path.txpp.internal_interrupt
    mask = path.txpp.internal_interrupt_mask
    bits = {
        0: bit('EneCluster0Interrupt', [node_EneCluster(path.cluster[0])]),
        1: bit('EneCluster1Interrupt', [node_EneCluster(path.cluster[1])]),
        2: bit('Npe0Interrupt', [node_npe(path.npe[0])]),
        3: bit('Npe1Interrupt', [node_npe(path.npe[1])]),
        4: bit('Ifg0DeepTermExcessiveTermintaion', type=TYPE_MISCONFIGURATION, is_masked=True),
        5: bit('Ifg1DeepTermExcessiveTermintaion', type=TYPE_MISCONFIGURATION, is_masked=True),
        6: bit('Ifg0Wd2BitEccErrInterrupt', type=TYPE_ECC_2B, sw_action=SW_ACTION_HARD_RESET, is_masked=True),
        7: bit('Ifg1Wd2BitEccErrInterrupt', type=TYPE_ECC_2B, sw_action=SW_ACTION_HARD_RESET, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_EneCluster(path):
    status = path.interrupt_register
    bits = {0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)])}
    for i in range(12):
        bits[1 + i] = bit('EneInterruptSignals{0}Summary'.format(i), [node_ene_interrupt_signals(path, i)])
    return master_interrupt_node(status, bits)


def node_ene_interrupt_signals(path, i):
    status = path.ene_interrupt_signals[i]
    mask = path.ene_interrupt_signals_mask[i]
    bits = {0: bit('EneTtlCountExpiredInt', type=TYPE_THRESHOLD_CROSSED)}
    return interrupt_node(status, mask, bits)


def node_npe(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('NpeInterruptsSummary', [node_NpeInterrupts(path)])
    }
    return master_interrupt_node(status, bits)


def node_NpeInterrupts(path):
    status = path.npe_interrupts
    mask = path.npe_interrupts_mask
    bits = {
        0: bit('CountersOverflow', type=TYPE_MISCONFIGURATION),
        1: bit('PacketTimeout', type=TYPE_MISCONFIGURATION)
    }
    return interrupt_node(status, mask, bits)


def node_hbm(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('GeneralInterruptRegisterSummary', [node_hbm_general_interrupt_register(path)])
    }
    return master_interrupt_node(status, bits)


def node_hbm_general_interrupt_register(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('AsyncFifoEmptyInterrupt0', type=TYPE_DESIGN_BUG, sw_action=SW_ACTION_REPLACE_DEVICE),
        1: bit('AsyncFifoEmptyInterrupt1', type=TYPE_DESIGN_BUG, sw_action=SW_ACTION_REPLACE_DEVICE),
        2: bit('AsyncFifoEmptyInterrupt2', type=TYPE_DESIGN_BUG, sw_action=SW_ACTION_REPLACE_DEVICE),
        3: bit('AsyncFifoEmptyInterrupt3', type=TYPE_DESIGN_BUG, sw_action=SW_ACTION_REPLACE_DEVICE),
        4: bit('AsyncFifoEmptyInterrupt4', type=TYPE_DESIGN_BUG, sw_action=SW_ACTION_REPLACE_DEVICE),
        5: bit('AsyncFifoEmptyInterrupt5', type=TYPE_DESIGN_BUG, sw_action=SW_ACTION_REPLACE_DEVICE),
        6: bit('AsyncFifoEmptyInterrupt6', type=TYPE_DESIGN_BUG, sw_action=SW_ACTION_REPLACE_DEVICE),
        7: bit('AsyncFifoEmptyInterrupt7', type=TYPE_DESIGN_BUG, sw_action=SW_ACTION_REPLACE_DEVICE),
        8: bit('CattripInterrupt', type=TYPE_THRESHOLD_CROSSED),
        9: bit('SpcioSbe', type=TYPE_ECC_1B),
        10: bit('SpcioDbe', type=TYPE_ECC_2B)
    }
    # HBM mask has in inverse logic: '1' == disabled, '0' == enabled
    return interrupt_node(status, mask, bits)


def node_mmu(path):
    status = path.mmu.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path.mmu)]),
        1: bit('GeneralInterruptRegisterSummary', [node_mmu_general_interrupt_register(path)])
    }
    return master_interrupt_node(status, bits)


def node_mmu_general_interrupt_register(path):
    status = path.mmu.general_interrupt_register
    mask = path.mmu.general_interrupt_register_mask
    bits = {
        0: bit('hbm_chnl_0_1_interrupt', [node_hbm_chnl(path.hbm.chnl[0].wide)]),
        1: bit('hbm_chnl_2_3_interrupt', [node_hbm_chnl(path.hbm.chnl[1].wide)]),
        2: bit('hbm_chnl_4_5_interrupt', [node_hbm_chnl(path.hbm.chnl[2].tall)]),
        3: bit('hbm_chnl_6_7_interrupt', [node_hbm_chnl(path.hbm.chnl[3].tall)]),
        4: bit('hbm_chnl_8_9_interrupt', [node_hbm_chnl(path.hbm.chnl[4].tall)]),
        5: bit('hbm_chnl_10_11_interrupt', [node_hbm_chnl(path.hbm.chnl[5].tall)]),
        6: bit('hbm_chnl_12_13_interrupt', [node_hbm_chnl(path.hbm.chnl[6].wide)]),
        7: bit('hbm_chnl_14_15_interrupt', [node_hbm_chnl(path.hbm.chnl[7].wide)]),
        # MMU reports only 2bit ECC errors as an interrupt.
        # And 1bit ECC errors are fixed internally by HW w/o any notifications.
        8: bit('mmu_has_error_buffer_interrupt', type=TYPE_DRAM_CORRUPTED_BUFFER),
        # This one is alive bot not useful in Pacific, planned to be fully used in GB though.
        9: bit('lpm_error_interrupt', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_hbm_chnl(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('GeneralInterruptRegisterSummary', [node_hbm_chnl_general_interrupt_register(path)]),
    }
    return master_interrupt_node(status, bits)


def node_hbm_chnl_general_interrupt_register(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('AddressParityErrorChannell0', type=TYPE_LINK_ERROR),
        1: bit('AddressParityErrorChannell1', type=TYPE_LINK_ERROR),
    }
    return interrupt_node(status, mask, bits)


def node_rxpp_term(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('EmResponseInterruptSummary', [node_rxpp_term_em_response_interrupt(path)])
    }
    return master_interrupt_node(status, bits)


def node_rxpp_term_em_response_interrupt(path):
    status = path.em_response_interrupt
    mask = path.em_response_interrupt_mask
    bits = {
        0: bit('TunnelTerminationTable0Resp', type=TYPE_NO_ERR_NOTIFICATION),
        1: bit('TunnelTerminationTable1Resp', type=TYPE_NO_ERR_NOTIFICATION)
    }
    return interrupt_node(status, mask, bits)


def node_rxpp_fwd(npu):
    status = npu.rxpp_fwd.rxpp_fwd.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(npu.rxpp_fwd.rxpp_fwd)]),
        1: bit('cache_interrupt_regSummary', [node_cache_interrupt_reg(npu)])
    }
    return master_interrupt_node(status, bits)


def node_cache_interrupt_reg(npu):
    status = npu.rxpp_fwd.rxpp_fwd.cache_interrupt_reg
    mask = npu.rxpp_fwd.rxpp_fwd.cache_interrupt_reg_mask
    bits = {0: bit('cache_interrupt', [
        node_cdb_cache(npu.cdb_cache),
        node_npe(npu.rxpp_fwd.npe[0]),
        node_npe(npu.rxpp_fwd.npe[1]),
        node_npe(npu.rxpp_fwd.npe[2])
    ])}
    return interrupt_node(status, mask, bits)


def node_cdb_cache(path):
    status = path.interrupt_register
    bits = {0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)])}
    return master_interrupt_node(status, bits)


def node_sdb_mac(sdb):
    status = sdb.mac.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(sdb.mac)]),
        1: bit('sdb_enc_interrupt_summary_regSummary', [node_sdb_enc_interrupt_summary(sdb)]),
        2: bit('EmResponseInterruptSummary', [node_sdb_mac_em_response_interrupt(sdb.mac)])
    }
    return master_interrupt_node(status, bits)


def node_sdb_enc_interrupt_summary(sdb):
    status = sdb.mac.sdb_enc_interrupt_summary_reg
    mask = sdb.mac.sdb_enc_interrupt_summary_reg_mask
    bits = {0: bit('sdb_enc_interrupt_summary', [node_sdb_enc(sdb.enc)])}
    return interrupt_node(status, mask, bits)


def node_sdb_enc(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('EmResponseInterruptSummary', [node_sdb_enc_em_response_interrupt(path)])
    }
    return master_interrupt_node(status, bits)


def node_sdb_enc_em_response_interrupt(path):
    status = path.em_response_interrupt
    mask = path.em_response_interrupt_mask
    bits = {}
    for db_i in range(4):
        bits[db_i] = bit('LargeEncDB{0}Resp'.format(db_i), type=TYPE_NO_ERR_NOTIFICATION)
    return interrupt_node(status, mask, bits)


def node_sdb_mac_em_response_interrupt(path):
    status = path.em_response_interrupt
    mask = path.em_response_interrupt_mask
    bits = {}
    for db_i in range(8):
        for access_i in range(2):
            bit_name = 'ServiceMappingDB{0}Access{1}Resp'.format(db_i, access_i)
            bits[db_i * 2 + access_i] = bit(bit_name, type=TYPE_NO_ERR_NOTIFICATION)
    return interrupt_node(status, mask, bits)


def node_MemProtectInterrupt(path):
    status = path.mem_protect_interrupt

    bits = {
        0: bit('Ecc_1bErrInterrupt', type=TYPE_MEM_PROTECT),
        1: bit('Ecc_2bErrInterrupt', type=TYPE_MEM_PROTECT, sw_action=SW_ACTION_HARD_RESET),
        2: bit('ParityErrInterrupt', type=TYPE_MEM_PROTECT, sw_action=SW_ACTION_HARD_RESET)
    }

    # Discover "ser_selector" and "selected_info" registers.
    ser_selector = path.get_register(REG_SER_ERROR_DEBUG_CONFIGURATION)
    selected_info = path.get_register(REG_SELECTED_SER_ERROR_INFO)

    # A block may have a mem_protect_interrupt register but no protected memories.
    # In this case, both 'ser_selector' and 'selected_info' registers will be absent.
    if not ser_selector and not selected_info:
        return interrupt_node(status, None, bits)

    # Both registers have fixed known names but variable size fields.
    # We fetch the bitfields from lbr_json

    mem_protect_fields = [
        get_field(ser_selector, 'erroneous_memory_selector'),
        get_field(ser_selector, 'reset_memory_errors'),
        get_field(selected_info, 'mem_err_addr'),
        get_field(selected_info, 'mem_err_type')
    ]

    return interrupt_node(status, None, bits, mem_protect_fields=mem_protect_fields)


def node_sms_main(path):
    status = path.sms_main.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path.sms_main)]),
        1: bit('SmsCgmErrorRegSummary', [node_sms_cgm_error_reg(path.sms_main)]),
        2: bit('SmsOutOfBufferErrorRegSummary', [node_sms_out_of_buffer_error_reg(path.sms_main)]),
        3: bit('SmsReqFifoOvfRegSummary', [node_sms_req_fifo_ovf_reg(path.sms_main)]),
        4: bit('SmsInterruptRegSummary', [node_sms_interrupt_reg(path)]),
    }
    return master_interrupt_node(status, bits)


def node_sms_cgm_error_reg(path):
    status = path.sms_cgm_error_reg
    mask = path.sms_cgm_error_reg_mask
    bits = {
        0: bit('SmsCgmError', type=TYPE_THRESHOLD_CROSSED),
        1: bit('SmsCgmDramSliceError', type=TYPE_THRESHOLD_CROSSED),
    }
    return interrupt_node(status, mask, bits)


def node_sms_out_of_buffer_error_reg(path):
    status = path.sms_out_of_buffer_error_reg
    mask = path.sms_out_of_buffer_error_reg_mask
    bits = {
        0: bit('SmsOutOfBufferError', type=TYPE_LACK_OF_RESOURCES),
    }
    return interrupt_node(status, mask, bits)


def node_sms_req_fifo_ovf_reg(path):
    status = path.sms_req_fifo_ovf_reg
    mask = path.sms_req_fifo_ovf_reg_mask
    bits = {
        0: bit('SmsReqFifoOvf', type=TYPE_LACK_OF_RESOURCES, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_sms_interrupt_reg(path):
    status = path.sms_main.sms_interrupt_reg
    mask = path.sms_main.sms_interrupt_reg_mask
    bits = {}
    for quad_i in range(4):
        bits[quad_i] = bit('SmsInterrupt_quad_{0}'.format(quad_i), [node_sms_quad(path.sms_quad[quad_i])])
    return interrupt_node(status, mask, bits)


def node_sms_quad(path):
    status = path.interrupt_register
    bits = {}

    bits[0] = bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)])
    for quad_i in range(4):
        bits[1 + quad_i] = bit('Sms2CifInterrupt1bEccErrorReg{0}Summary'.format(quad_i),
                               [node_sms2cif_ecc_reg(path, '1b', TYPE_ECC_1B, quad_i)])
    for quad_i in range(4):
        bits[5 + quad_i] = bit('Sms2CifInterrupt2bEccErrorReg{0}Summary'.format(quad_i),
                               [node_sms2cif_ecc_reg(path, '2b', TYPE_ECC_2B, quad_i)])
    bits[9] = bit('Sms2CifOverflowRegSummary', [node_sms2cif_overflow_reg(path)])
    return master_interrupt_node(status, bits)


def node_sms2cif_ecc_reg(path, Nb, interrupt_type, index):
    status = eval('path.sms2_cif_interrupt{0}_ecc_error_reg[{1}]'.format(Nb, index))
    mask = eval('path.sms2_cif_interrupt{0}_ecc_error_reg_mask[{1}]'.format(Nb, index))
    bits = {
        0: bit('Interrupt{0}EccError'.format(Nb), type=interrupt_type),
    }
    return interrupt_node(status, mask, bits)


def node_sms2cif_overflow_reg(path):
    status = path.sms2_cif_overflow_reg
    mask = path.sms2_cif_overflow_reg_mask
    bits = {
        0: bit('Sms2CifReorderFifoOvf', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        1: bit('Sms2CifFdoqFifoOvf', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_ts_mon(path):
    status = path.interrupt_register
    bits = {}
    bits[0] = bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)])
    for slice_i in range(6):
        bits[1 + slice_i] = bit('SliceInterruptRegister{0}Summary'.format(slice_i),
                                [node_ts_mon_slice_interrupt_reg(path, slice_i)])
    return master_interrupt_node(status, bits)


def node_ts_mon_slice_interrupt_reg(path, slice_i):
    status = path.slice_interrupt_register[slice_i]
    mask = path.slice_interrupt_register_mask[slice_i]
    bits = {
        0: bit('LinkDownInterrupt', type=TYPE_LINK_DOWN),
        1: bit('MsCounterOverflow', type=TYPE_DESIGN_BUG),
        2: bit('MsCounterUnderflow', type=TYPE_DESIGN_BUG),
    }
    return interrupt_node(status, mask, bits)


def node_csms(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('CsmsInterruptRegSummary', [node_csms_interrupt_reg(path)])
    }
    return master_interrupt_node(status, bits)


def node_csms_interrupt_reg(path):
    status = path.csms_interrupt_reg
    mask = path.csms_interrupt_reg_mask
    bits = {
        0: bit('CreditGntDestDevUnreachable', type=TYPE_CREDIT_DEV_UNREACHABLE),

        1: bit('MsgBufferEnqPreFifoOverflow0', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        2: bit('MsgBufferEnqPreFifoOverflow1', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        3: bit('MsgBufferEnqPreFifoOverflow2', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        4: bit('MsgBufferEnqPreFifoOverflow3', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),

        5: bit('MsgBufferDdmqOverflow0', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET, is_masked=True),
        6: bit('MsgBufferDdmqOverflow1', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET, is_masked=True),
        7: bit('MsgBufferDdmqOverflow2', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET, is_masked=True),
        8: bit('MsgBufferDdmqOverflow3', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET, is_masked=True),

        9: bit('MsgBufferDeqCmdFifoOverflow0', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        10: bit('MsgBufferDeqCmdFifoOverflow1', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        11: bit('MsgBufferDeqCmdFifoOverflow2', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        12: bit('MsgBufferDeqCmdFifoOverflow3', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),

        13: bit('MsgBufferLocalFifoOverflow0', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        14: bit('MsgBufferLocalFifoOverflow1', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        15: bit('MsgBufferLocalFifoOverflow2', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        16: bit('MsgBufferLocalFifoOverflow3', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        17: bit('MsgMapFifoOverflow4', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        18: bit('MsgMapFifoOverflow5', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),

        19: bit('UnpackFifoOverflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        20: bit('GntSwTargetFifoOverflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        21: bit('ReqSwTargetFifoOverflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_fte(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('FteInterruptRegSummary', [node_fte_interrupt_reg(path)]),
    }
    return master_interrupt_node(status, bits)


def node_fte_interrupt_reg(path):
    status = path.fte_interrupt_reg
    mask = path.fte_interrupt_reg_mask
    bits = {
        0: bit('LostSyncInterrupt', type=TYPE_THRESHOLD_CROSSED, sw_action=SW_ACTION_HARD_RESET),
        1: bit('ExpectedDeviceTimeDiffInterrupt', type=TYPE_THRESHOLD_CROSSED),
    }
    return interrupt_node(status, mask, bits)


def node_frm(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('FrmInterruptRegSummary', [node_frm_interrupt_reg(path)]),
    }
    return master_interrupt_node(status, bits)


def node_frm_interrupt_reg(path):
    status = path.frm_interrupt_reg
    mask = path.frm_interrupt_reg_mask
    bits = {
        0: bit('LinkStatusDownInt', type=TYPE_LINK_DOWN, is_masked=True),
        1: bit('FrtWrFifoOverflowInt', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        2: bit('DcfmFeedbackFifoFullInt', type=TYPE_INFORMATIVE),
    }
    return interrupt_node(status, mask, bits)


def node_pier(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('PierCoreInterruptRegSummary', [node_pier_core_interrupt_reg(path)]),
    }
    return master_interrupt_node(status, bits)


def node_pier_core_interrupt_reg(path):
    status = path.pier_core_interrupt_reg
    mask = path.pier_core_interrupt_reg_mask
    bits = {
        0: bit('CscpUnreachDevice', type=TYPE_LINK_DOWN),
        1: bit('InbeMultiFifoOvf', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_mrb(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_npu_host(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('EneInterruptSignalsSummary', [node_npu_host_ene_interrupt_signals(path)]),
        2: bit('dropped_massageSummary', [node_npu_host_dropped_massage(path)]),
        3: bit('EmResponseInterruptSummary', [node_npu_host_em_response_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_npu_host_ene_interrupt_signals(path):
    status = path.ene_interrupt_signals
    mask = path.ene_interrupt_signals_mask
    bits = {
        0: bit('EneTtlCountExpiredInt', type=TYPE_MISCONFIGURATION),
    }
    return interrupt_node(status, mask, bits)


def node_npu_host_dropped_massage(path):
    status = path.dropped_massage
    mask = path.dropped_massage_mask
    bits = {
        0: bit('interrupt', type=TYPE_LACK_OF_RESOURCES),
    }
    return interrupt_node(status, mask, bits)


def node_npu_host_em_response_interrupt(path):
    status = path.em_response_interrupt
    mask = path.em_response_interrupt_mask
    bits = {
        0: bit('eth_mp_emResp', type=TYPE_NO_ERR_NOTIFICATION),
    }
    return interrupt_node(status, mask, bits)


def node_reassembly(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_rx_cgm(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('RxCGMInterruptReg10Summary', [node_rx_cgm_slice(path, 0)]),
        2: bit('RxCGMInterruptReg11Summary', [node_rx_cgm_slice(path, 1)]),
        3: bit('RxCGMInterruptReg12Summary', [node_rx_cgm_slice(path, 2)]),
        4: bit('RxCGMInterruptReg13Summary', [node_rx_cgm_slice(path, 3)]),
        5: bit('RxCGMInterruptReg14Summary', [node_rx_cgm_slice(path, 4)]),
        6: bit('RxCGMInterruptReg15Summary', [node_rx_cgm_slice(path, 5)]),
    }
    return master_interrupt_node(status, bits)


def node_rx_cgm_slice(path, i):
    status = path.rx_cgm_interrupt_reg1[i]
    mask = path.rx_cgm_interrupt_reg1_mask[i]
    bits = {0: bit('SliceLocalUSerCounterWrapAround', type=TYPE_OTHER)}
    return interrupt_node(status, mask, bits)


def node_rx_meter_top(path):
    status = path.top.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path.top)]),
        1: bit('MeterBlocksInterruptRegisterSummary', [node_rx_meter_top_blocks(path)]),
    }
    return master_interrupt_node(status, bits)


def node_rx_meter_top_blocks(path):
    status = path.top.meter_blocks_interrupt_register
    mask = path.top.meter_blocks_interrupt_register_mask
    bits = {
        0: bit('ExactRxMeterCluster0Interrupt', [node_rx_meter_block(path.block[0])]),
        1: bit('ExactRxMeterCluster1Interrupt', [node_rx_meter_block(path.block[1])]),
        2: bit('ExactRxMeterCluster2Interrupt', [node_rx_meter_block(path.block[2])]),
        3: bit('ExactRxMeterCluster3Interrupt', [node_rx_meter_block(path.block[3])]),
    }
    return interrupt_node(status, mask, bits)


def node_rx_meter_block(path):
    status = path.interrupt_register
    bits = {0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)])}
    return master_interrupt_node(status, bits)


def node_rx_pdr(path):
    status = path.rx_pdr.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path.rx_pdr)]),
        1: bit('RxpdrGlobalInterruptRegSummary', [node_rx_pdr_global(path)]),
    }
    return master_interrupt_node(status, bits)


def node_rx_pdr_global(path):
    status = path.rx_pdr.rxpdr_global_interrupt_reg
    mask = path.rx_pdr.rxpdr_global_interrupt_reg_mask
    bits = {
        0: bit('SharedDb0InetrruptSummary', [node_rx_pdr_shared_db(path.rx_pdr_mc_db[0])]),
        1: bit('SharedDb1InetrruptSummary', [node_rx_pdr_shared_db(path.rx_pdr_mc_db[1])]),
        2: bit('Slices01InetrruptSummary', [node_rx_pdr_slice_pair(path.slice_pair[0].rx_pdr)]),
        3: bit('Slices23InetrruptSummary', [node_rx_pdr_slice_pair(path.slice_pair[1].rx_pdr)]),
        4: bit('Slices45InetrruptSummary', [node_rx_pdr_slice_pair(path.slice_pair[2].rx_pdr)]),

    }
    return interrupt_node(status, mask, bits)


def node_rx_pdr_shared_db(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('SharedDBInterruptRegSummary', [node_rx_pdr_shared_db_interrupt_reg(path)]),
        2: bit('EmResponseInterruptSummary', [node_rx_pdr_shared_db_em_response(path)]),
    }
    return master_interrupt_node(status, bits)


def node_rx_pdr_shared_db_interrupt_reg(path):
    status = path.shared_db_interrupt_reg
    mask = path.shared_db_interrupt_reg_mask
    bits = {
        0: bit('LookupAError', type=TYPE_ECC_2B),
        1: bit('LookupBError', type=TYPE_ECC_2B),
        2: bit('FeLinkBmpTableMem0OneEccErr', type=TYPE_ECC_1B, is_masked=True),
        3: bit('FeLinkBmpTableMem1OneEccErr', type=TYPE_ECC_1B, is_masked=True),
        4: bit('FeLinkBmpTableMem2OneEccErr', type=TYPE_ECC_1B, is_masked=True),
        5: bit('FeLinkBmpTableMem3OneEccErr', type=TYPE_ECC_1B, is_masked=True),
        6: bit('FeLinkBmpTableMem0TwoEccErr', type=TYPE_ECC_2B, is_masked=True),
        7: bit('FeLinkBmpTableMem1TwoEccErr', type=TYPE_ECC_2B, is_masked=True),
        8: bit('FeLinkBmpTableMem2TwoEccErr', type=TYPE_ECC_2B, is_masked=True),
        9: bit('FeLinkBmpTableMem3TwoEccErr', type=TYPE_ECC_2B, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_rx_pdr_shared_db_em_response(path):
    status = path.em_response_interrupt
    mask = path.em_response_interrupt_mask
    bits = {
        0: bit('SharedDbResp', type=TYPE_NO_ERR_NOTIFICATION),
    }
    return interrupt_node(status, mask, bits)


def node_rx_pdr_slice_pair(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('SliceInterruptRegister0Summary', [node_rx_pdr_slice(path, 0)]),
        2: bit('SliceInterruptRegister1Summary', [node_rx_pdr_slice(path, 1)]),
    }
    return master_interrupt_node(status, bits)


def node_rx_pdr_slice(path, i):
    status = path.slice_interrupt_register[i]
    mask = path.slice_interrupt_register_mask[i]
    bits = {
        0: bit('SliceTrLcSaMcPipeEmdbEntryNotFound', type=TYPE_MISCONFIGURATION, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_sch_top(path):
    status = path.sch_top.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path.sch_top)]),
        1: bit('SchIfgInterruptSummary', [node_sch_ifg(path)]),
    }
    return master_interrupt_node(status, bits)


def node_sch_ifg(path):
    status = path.sch_top.sch_ifg_interrupt
    mask = path.sch_top.sch_ifg_interrupt_mask
    bits = {
        0: bit('Ifg0Interrupt', [node_sch(path.slice[0].ifg[0].sch)]),
        1: bit('Ifg1Interrupt', [node_sch(path.slice[0].ifg[1].sch)]),
        2: bit('Ifg2Interrupt', [node_sch(path.slice[1].ifg[0].sch)]),
        3: bit('Ifg3Interrupt', [node_sch(path.slice[1].ifg[1].sch)]),
        4: bit('Ifg4Interrupt', [node_sch(path.slice[2].ifg[0].sch)]),
        5: bit('Ifg5Interrupt', [node_sch(path.slice[2].ifg[1].sch)]),
        6: bit('Ifg6Interrupt', [node_sch(path.slice[3].ifg[0].sch)]),
        7: bit('Ifg7Interrupt', [node_sch(path.slice[3].ifg[1].sch)]),
        8: bit('Ifg8Interrupt', [node_sch(path.slice[4].ifg[0].fabric_sch)]),
        9: bit('Ifg9Interrupt', [node_sch(path.slice[4].ifg[1].fabric_sch)]),
        10: bit('Ifg10Interrupt', [node_sch(path.slice[5].ifg[0].fabric_sch)]),
        11: bit('Ifg11Interrupt', [node_sch(path.slice[5].ifg[1].fabric_sch)]),
    }
    return interrupt_node(status, mask, bits)


def node_sch(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('GeneralInterruptRegisterSummary', [node_sch_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_sch_general_interrupt(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('SpeculativeGrant', type=TYPE_DESIGN_BUG, is_masked=True),
        1: bit('IllegalReqVsc', type=TYPE_MISCONFIGURATION),
    }
    return interrupt_node(status, mask, bits)


def node_cdb_top(path):
    status = path.top.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path.top)]),
        1: bit('interrupt_summery_arraySummary', [node_cdb_top_interrupt_summary_array(path.top)]),
        2: bit('cdb_core0_interrupt_summary_regSummary', [node_cdb_top_core_summary(path, 0)]),
        3: bit('cdb_core1_interrupt_summary_regSummary', [node_cdb_top_core_summary(path, 1)]),
        4: bit('cdb_core2_interrupt_summary_regSummary', [node_cdb_top_core_summary(path, 2)]),
        5: bit('cdb_core3_interrupt_summary_regSummary', [node_cdb_top_core_summary(path, 3)]),
        6: bit('cdb_core4_interrupt_summary_regSummary', [node_cdb_top_core_summary(path, 4)]),
        7: bit('cdb_core5_interrupt_summary_regSummary', [node_cdb_top_core_summary(path, 5)]),
        8: bit('cdb_core6_interrupt_summary_regSummary', [node_cdb_top_core_summary(path, 6)]),
        9: bit('cdb_core7_interrupt_summary_regSummary', [node_cdb_top_core_summary(path, 7)]),
        10: bit('lpm_uneven_load_blanceSummary', [node_cdb_top_lpm_uneven_load_blance(path.top)]),
        11: bit('cem_uneven_load_blanceSummary', [node_cdb_top_cem_uneven_load_blance(path.top)]),
        12: bit('AgingOverflowSummary', [node_cdb_top_aging_overflow(path.top)]),
        13: bit('BulkUpdateOverflowSummary', [node_cdb_top_bulk_update_overflow(path.top)]),
        14: bit('arc_interrupt_to_cpuSummary', [node_cdb_top_arc_interrupt_to_cpu(path.top)]),
    }
    return master_interrupt_node(status, bits)


def node_cdb_top_interrupt_summary_array(path):
    status = path.interrupt_summery_array
    mask = path.interrupt_summery_array_mask
    bits = {
        0: bit('efdb_table_duplicate_entry', type=TYPE_OTHER),
        1: bit('efdb_table_plb_miss', type=TYPE_OTHER),
        2: bit('slb_efdb_table_insert_not_succeeded', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_cdb_top_lpm_uneven_load_blance(path):
    status = path.lpm_uneven_load_blance
    mask = path.lpm_uneven_load_blance_mask
    bits = {
        0: bit('lpm_uneven_load_balance', type=TYPE_THRESHOLD_CROSSED, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_cdb_top_cem_uneven_load_blance(path):
    status = path.cem_uneven_load_blance
    mask = path.cem_uneven_load_blance_mask
    bits = {
        0: bit('cem_uneven_load_balance', type=TYPE_THRESHOLD_CROSSED, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_cdb_top_aging_overflow(path):
    status = path.aging_overflow
    mask = path.aging_overflow_mask
    bits = {
        0: bit('aging_overflow', type=TYPE_MISCONFIGURATION),
    }
    return interrupt_node(status, mask, bits)


def node_cdb_top_bulk_update_overflow(path):
    status = path.bulk_update_overflow
    mask = path.bulk_update_overflow_mask
    bits = {
        0: bit('bulk_update_overflow', type=TYPE_MISCONFIGURATION),
    }
    return interrupt_node(status, mask, bits)


def node_cdb_top_arc_interrupt_to_cpu(path):
    status = path.arc_interrupt_to_cpu
    mask = path.arc_interrupt_to_cpu_mask
    bits = {
        0: bit('cem_mng2css_interrupt', type=TYPE_NO_ERR_NOTIFICATION),
    }
    return interrupt_node(status, mask, bits)


def node_cdb_top_core_summary(path, i):
    status = path.top.cdb_core_interrupt_summary_reg[i]
    mask = path.top.cdb_core_interrupt_summary_reg_mask[i]
    if i % 2 == 0:
        bits = {0: bit('cdb_core_interrupt_summary', [node_cdb_core(path.core_reduced[i // 2])])}
    else:
        bits = {0: bit('cdb_core_interrupt_summary', [node_cdb_core(path.core[i // 2])])}
    return interrupt_node(status, mask, bits)


def node_cdb_core(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        # LPM shared SRAM
        1: bit('lpm0_shared_sram_1b_err_int_regSummary', [node_cdb_core_1bit(path, 'lpm_shared_sram_1b_err', 0, TYPE_LPM_SRAM_ECC_1B)]),
        2: bit('lpm1_shared_sram_1b_err_int_regSummary', [node_cdb_core_1bit(path, 'lpm_shared_sram_1b_err', 1, TYPE_LPM_SRAM_ECC_1B)]),
        3: bit('lpm0_shared_sram_2b_err_int_regSummary', [node_cdb_core_1bit(path, 'lpm_shared_sram_2b_err', 0, TYPE_LPM_SRAM_ECC_2B)]),
        4: bit('lpm1_shared_sram_2b_err_int_regSummary', [node_cdb_core_1bit(path, 'lpm_shared_sram_2b_err', 1, TYPE_LPM_SRAM_ECC_2B)]),
        # EM shared SRAM
        5: bit('em0_shared_sram_err_int_regSummary', [node_cdb_core_1bit(path, 'em_shared_sram_err', 0, TYPE_OTHER)]),
        6: bit('em1_shared_sram_err_int_regSummary', [node_cdb_core_1bit(path, 'em_shared_sram_err', 1, TYPE_OTHER)]),
    }
    return master_interrupt_node(status, bits)


def node_cdb_core_1bit(path, name, i, bit_type):
    status = eval('path.' + name + ('_int_reg[%d]' % i))
    mask = eval('path.' + name + ('_int_reg_mask[%d]' % i))
    is_masked = (name == "em_shared_sram_err")
    bits = {
        0: bit(name + '_interrupt', type=bit_type, is_masked=is_masked)
    }
    return interrupt_node(status, mask, bits)


def node_counters(path):
    status = path.top.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path.top)]),
        1: bit('InterruptRegSummary', [node_counters_interrupt_reg(path.top)]),
        2: bit('BankGroupInterruptReg0Summary', [node_counters_bank_group_interrupt_reg0(path)]),
        3: bit('BankGroupInterruptReg1Summary', [node_counters_bank_group_interrupt_reg1(path)]),
    }
    return master_interrupt_node(status, bits)


def node_counters_interrupt_reg(path):
    status = path.interrupt_reg
    mask = path.interrupt_reg_mask
    bits = {
        0: bit('SamePdBankCollision', type=TYPE_MISCONFIGURATION),
    }
    return interrupt_node(status, mask, bits)


def node_counters_bank_group_interrupt_reg0(path):
    status = path.top.bank_group_interrupt_reg0
    mask = path.top.bank_group_interrupt_reg0_mask
    bits = {}
    # bits[0:17] map to bank_4k[0:17]
    for i in range(18):
        bits[i] = bit('BankGroupInterrupt{}'.format(i), [node_counters_bank_group_4K6K(path.bank_4k[i])])
    return interrupt_node(status, mask, bits)


def node_counters_bank_group_interrupt_reg1(path):
    status = path.top.bank_group_interrupt_reg1
    mask = path.top.bank_group_interrupt_reg1_mask
    bits = {}
    # bits[0:13] map to bank_4k[18:31]
    # bits[14:17] map to bank_6k[0:3]
    for i in range(18):
        if i < 14:
            bits[i] = bit('BankGroupInterrupt{}'.format(i + 18), [node_counters_bank_group_4K6K(path.bank_4k[i + 18])])
        else:
            bits[i] = bit('BankGroupInterrupt{}'.format(i + 18), [node_counters_bank_group_4K6K(path.bank_6k[i - 14])])
    return interrupt_node(status, mask, bits)


def node_counters_bank_group_4K6K(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('InterruptReg0Summary', [node_counters_bank_group_4K6K_interrupt_reg(path, 0)]),
        2: bit('InterruptReg1Summary', [node_counters_bank_group_4K6K_interrupt_reg(path, 1)]),
        3: bit('InterruptReg2Summary', [node_counters_bank_group_4K6K_interrupt_reg(path, 2)]),
    }
    return master_interrupt_node(status, bits)


def node_counters_bank_group_4K6K_interrupt_reg(path, i):
    status = path.interrupt_reg[i]
    mask = path.interrupt_reg_mask[i]
    bits = {
        0: bit('MaxCounterCrossedThreshold', type=TYPE_COUNTER_THRESHOLD_CROSSED),
        1: bit('PdConfigMismatch', type=TYPE_MISCONFIGURATION),
        2: bit('LmResultFifoOverflow', type=TYPE_DESIGN_BUG),
    }
    return interrupt_node(status, mask, bits)


def node_dvoq(path):
    status = path.dvoq.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path.dvoq)]),
        1: bit('SlaveInterruptsSummary', [node_dvoq_slave(path)]),
    }
    return master_interrupt_node(status, bits)


def node_dvoq_slave(path):
    status = path.dvoq.slave_interrupts
    mask = path.dvoq.slave_interrupts_mask
    bits = {
        0: bit('hmc_cgm', [node_hmc_cgm(path.hmc_cgm)]),
        1: bit('dics', [node_dics(path.dics)]),
    }
    return interrupt_node(status, mask, bits)


def node_hmc_cgm(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('CgmIntSummary', [node_hmc_cgm_int(path)]),
    }
    return master_interrupt_node(status, bits)


def node_hmc_cgm_int(path):
    status = path.cgm_int
    mask = path.cgm_int_mask
    bits = {
        0: bit('TotalBuffersUnderflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        1: bit('PoolUnderflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_dics(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('GeneralInterruptRegisterSummary', [node_dics_general(path)]),
        2: bit('FabricBlockingIntrRegSummary', [node_dics_fabric_blocking(path)]),
    }
    return master_interrupt_node(status, bits)


def node_dics_general(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('FabricBlockingIntr', type=TYPE_MISCONFIGURATION, is_masked=True),
        1: bit('AgedOutFifoFull', type=TYPE_INFORMATIVE),
        2: bit('dics2mmu_fifo_overflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        3: bit('crdt_req_cbt_overflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_dics_fabric_blocking(path):
    status = path.fabric_blocking_intr_reg
    mask = path.fabric_blocking_intr_reg_mask
    bits = {
        0: bit('TotalListFull', type=TYPE_INFORMATIVE, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_tx_cgm_top(path):
    status = path.tx_cgm_top.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path.tx_cgm_top)]),
        1: bit('GlobalCgmInterruptSummary', [node_tx_cgm_top_global(path.tx_cgm_top)]),
        2: bit('EgrSliceInterrupt0Summary', [node_tx_cgm_top_slice(path, 0)]),
        3: bit('EgrSliceInterrupt1Summary', [node_tx_cgm_top_slice(path, 1)]),
        4: bit('EgrSliceInterrupt2Summary', [node_tx_cgm_top_slice(path, 2)]),
        5: bit('EgrSliceInterrupt3Summary', [node_tx_cgm_top_slice(path, 3)]),
        6: bit('EgrSliceInterrupt4Summary', [node_tx_cgm_top_slice(path, 4)]),
        7: bit('EgrSliceInterrupt5Summary', [node_tx_cgm_top_slice(path, 5)]),
    }
    return master_interrupt_node(status, bits)


def node_tx_cgm_top_global(path):
    status = path.global_cgm_interrupt
    mask = path.global_cgm_interrupt_mask
    bits = {
        0: bit('TotalSchUcBufferRollOver', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        1: bit('TotalSchUcLocalBufferRollOver', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        2: bit('TotalSchUcRemoteBufferRollOver', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        3: bit('TotalPdRollOver', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        4: bit('TotalSchUcPdRollOver', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        5: bit('TotalMcPdRollOver', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        6: bit('TotalFabPdRollOver', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_tx_cgm_top_slice(path, i):
    status = path.tx_cgm_top.egr_slice_interrupt[i]
    mask = path.tx_cgm_top.egr_slice_interrupt_mask[i]
    bits = {
        0: bit('TsmsSliceInterrupt', [node_tx_tsms(path.slice[i].ts_ms)]),
        1: bit('TxpdrSliceInterrupt', [node_tx_pdr(path.slice[i].tx.pdr)]),
        2: bit('TxcgmSliceInterrupt', [node_tx_cgm(path.slice[i].tx.cgm)]),
    }
    return interrupt_node(status, mask, bits)


def node_tx_tsms(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('GeneralInterruptRegisterSummary', [node_tsms_general(path)]),
    }
    return master_interrupt_node(status, bits)


def node_tsms_general(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('UchMsTimeError', type=TYPE_INFORMATIVE),  # masked in LC mode only
        1: bit('UclMsTimeError', type=TYPE_INFORMATIVE),
        2: bit('McMsTimeError', type=TYPE_INFORMATIVE),
        3: bit('TsmsFifoOverflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_tx_pdr(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('GeneralInterruptRegisterSummary', [node_tx_pdr_general(path)]),
    }
    return master_interrupt_node(status, bits)


def node_tx_pdr_general(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('McFlbToUcOq', type=TYPE_OTHER),
        1: bit('EmptyLinkBitmap', type=TYPE_INFORMATIVE),
        2: bit('UcdvRollover', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_tx_cgm(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('SliceCgmInterruptSummary', [node_tx_cgm_slice(path)]),
    }
    return master_interrupt_node(status, bits)


def node_tx_cgm_slice(path):
    status = path.slice_cgm_interrupt
    mask = path.slice_cgm_interrupt_mask
    bits = {
        0: bit('OqgUcPdCounterRollOver', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        1: bit('OqgUcBufferCounterRollOver', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        2: bit('OqgUcByteCounterRollOver', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        3: bit('IfgUcPdCounterRollOver', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        4: bit('IfgUcBufferCounterRollOver', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        5: bit('IfgUcByteCounterRollOver', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        6: bit('UcdvRollover', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_fdll_shared_mem(path):
    status = path.fdll_shared_mem.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path.fdll_shared_mem)]),
        1: bit('GeneralInterruptRegisterSummary', [node_fdll_shared_mem_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_fdll_shared_mem_general_interrupt(path):
    status = path.fdll_shared_mem.general_interrupt_register
    mask = path.fdll_shared_mem.general_interrupt_register_mask
    bits = {
        0: bit('WriteFailCbtOverflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        1: bit('EmpdInterrupt0', [node_fdll(path.fdll[0])]),
        2: bit('EmpdInterrupt1', [node_fdll(path.fdll[1])]),
        3: bit('EmpdInterrupt2', [node_fdll(path.fdll[2])]),
        4: bit('EmpdInterrupt3', [node_fdll(path.fdll[3])]),
        5: bit('EmpdInterrupt4', [node_fdll(path.fdll[4])]),
        6: bit('EmpdInterrupt5', [node_fdll(path.fdll[5])]),
        7: bit('EmpdInterrupt6', [node_fdll(path.fdll[6])]),
        8: bit('EmpdInterrupt7', [node_fdll(path.fdll[7])]),
    }
    return interrupt_node(status, mask, bits)


def node_fdll(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('GeneralInterruptSummary', [node_fdll_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_fdll_general_interrupt(path):
    status = path.general_interrupt
    mask = path.general_interrupt_mask
    bits = {
        0: bit('EmdbDuplicateEntry', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET, is_masked=True)
    }
    return interrupt_node(status, mask, bits)


def node_rx_counters(path):
    status = path.rx_counters.interrupt_register
    bits = {0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path.rx_counters)])}
    for i in range(6):
        bits[i + 1] = bit('SliceInterruptReg{}Summary'.format(i), [node_rx_counters_slice_fllb(path, i)])
    return master_interrupt_node(status, bits)


def node_rx_counters_slice_fllb(path, i):
    status = eval('path.rx_counters.slice_interrupt_reg[%d]' % i)
    mask = eval('path.rx_counters.slice_interrupt_reg_mask[%d]' % i)
    bits = {}
    if i < 5:
        bits[0] = bit('FllbSliceInterrupt', [node_slice_fllb(path.slice[i].fllb)])
    elif i == 5:
        bits[0] = bit('FllbSliceInterrupt', [node_slice_fllb(path.slice[i].fabric_fllb)])
    else:
        assert False

    bits[1] = bit('LmReadToNonEnabledBank', type=TYPE_MISCONFIGURATION, is_masked=True)
    return interrupt_node(status, mask, bits)


def node_slice_fllb(path):
    status = path.interrupt_register
    bits = {0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)])}
    return master_interrupt_node(status, bits)


def node_ics_top(path):
    status = path.ics_top.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path.ics_top)]),
        1: bit('GeneralInterruptRegisterSummary', [node_ics_top_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_ics_top_general_interrupt(path):
    status = path.ics_top.general_interrupt_register
    mask = path.ics_top.general_interrupt_register_mask
    bits = {
        0: bit('IcsSlice0Interrupt', [node_ics_slice(path.slice[0].ics)]),
        1: bit('IcsSlice1Interrupt', [node_ics_slice(path.slice[1].ics)]),
        2: bit('IcsSlice2Interrupt', [node_ics_slice(path.slice[2].ics)]),
        3: bit('IcsSlice3Interrupt', [node_ics_slice(path.slice[3].ics)]),
        4: bit('IcsSlice4Interrupt', [node_ics_slice(path.slice[4].ics)]),
        5: bit('IcsSlice5Interrupt', [node_ics_slice(path.slice[5].ics)]),
        6: bit('FilbSlice0Interrupt', [node_filb_slice(path.slice[0].filb)]),
        7: bit('FilbSlice1Interrupt', [node_filb_slice(path.slice[1].filb)]),
        8: bit('FilbSlice2Interrupt', [node_filb_slice(path.slice[2].filb)]),
        9: bit('FilbSlice3Interrupt', [node_filb_slice(path.slice[3].filb)]),
        10: bit('FilbSlice4Interrupt', [node_fabric_filb_slice(path.slice[4].fabric_filb)]),
        11: bit('FilbSlice5Interrupt', [node_fabric_filb_slice(path.slice[5].fabric_filb)]),
        12: bit('dram_pack_pref_fifo_overf', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        13: bit('dram_delete_pref_fifo_overf', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_ics_slice(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('GeneralInterruptRegisterSummary', [node_ics_slice_general_interrupt(path)]),
        2: bit('FabricBlockingIntrRegSummary', [node_ics_slice_fabric_blocking(path)]),
    }
    return master_interrupt_node(status, bits)


def node_ics_slice_general_interrupt(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('FabricBlockingIntr', type=TYPE_OTHER, is_masked=True),
        1: bit('QueueAgedOutIntr', type=TYPE_QUEUE_AGED_OUT, is_masked=True),
        2: bit('RxcgmCbtFullIntr', type=TYPE_LACK_OF_RESOURCES, is_masked=True),
        3: bit('voq_to_context_fifo_overflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        4: bit('DramListQsizeFifOverflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        5: bit('DramListRereadFifOverflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        6: bit('DramListEnqFifOverflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        7: bit('ExitDramListRereadFull', type=TYPE_MISCONFIGURATION),
    }
    return interrupt_node(status, mask, bits)


def node_ics_slice_fabric_blocking(path):
    status = path.fabric_blocking_intr_reg
    mask = path.fabric_blocking_intr_reg_mask
    bits = {
        0: bit('FlbHpListFull', type=TYPE_LACK_OF_RESOURCES, is_masked=True),
        1: bit('FlbLpListFull', type=TYPE_LACK_OF_RESOURCES, is_masked=True),
        2: bit('RlbUchListFull', type=TYPE_LACK_OF_RESOURCES, is_masked=True),
        3: bit('RlbUclListFull', type=TYPE_LACK_OF_RESOURCES, is_masked=True),
        4: bit('RlbMcListFull', type=TYPE_LACK_OF_RESOURCES, is_masked=True),
        5: bit('TotalListFull', type=TYPE_LACK_OF_RESOURCES, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_filb_slice(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('GeneralInterruptRegisterSummary', [node_filb_slice_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


# The LBR file is filb5.lbr, but it applies to slices 4 and 5
def node_fabric_filb_slice(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('GeneralInterruptRegisterSummary', [node_fabric_filb_slice_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_filb_slice_general_interrupt(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('SlbOpenButNoLink', type=TYPE_LACK_OF_RESOURCES),
        1: bit('slb_pd_fifo_overflow', type=TYPE_MISCONFIGURATION, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_fabric_filb_slice_general_interrupt(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    is_masked = (path.get_name() == "slice[5].fabric_filb")
    bits = {
        0: bit('FabricBlockingIntr', type=TYPE_OTHER, is_masked=is_masked),
    }
    return interrupt_node(status, mask, bits)


def node_nw_reorder(path):
    status = path.nw_reorder.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path.nw_reorder)]),
        1: bit('ReorderGlobalInterruptSummary', [node_nw_reorder_global(path)]),
    }
    return master_interrupt_node(status, bits)


def node_nw_reorder_global(path):
    status = path.nw_reorder.reorder_global_interrupt
    mask = path.nw_reorder.reorder_global_interrupt_mask
    bits = {
        0: bit('NwReorderBlock0Interrupt', [node_nw_reorder_block(path.slice[3].nw_reorder_block[0])]),
        1: bit('NwReorderBlock1Interrupt', [node_nw_reorder_block(path.slice[3].nw_reorder_block[1])]),
        2: bit('NwReorderBlock2Interrupt', [node_nw_reorder_block(path.slice[4].nw_reorder_block[0])]),
        3: bit('NwReorderBlock3Interrupt', [node_nw_reorder_block(path.slice[4].nw_reorder_block[1])]),
        4: bit('NwReorderBlock4Interrupt', [node_nw_reorder_block(path.slice[5].nw_reorder_block[0])]),
        5: bit('NwReorderBlock5Interrupt', [node_nw_reorder_block(path.slice[5].nw_reorder_block[1])]),
        6: bit('PpReorderSlice0Interrupt', [node_pp_reorder_slice(path.slice[0].pp_reorder)]),
        7: bit('PpReorderSlice1Interrupt', [node_pp_reorder_slice(path.slice[1].pp_reorder)]),
        8: bit('PpReorderSlice2Interrupt', [node_pp_reorder_slice(path.slice[2].pp_reorder)]),
    }
    return interrupt_node(status, mask, bits)


def node_nw_reorder_block(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_pp_reorder_slice(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_pdoq_shared_mem(path):
    status = path.pdoq_shared_mem.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path.pdoq_shared_mem)]),
        1: bit('PdoqSliceInterruptsSummary', [node_pdoq_shared_mem_pdoq_slice_interrupts(path)]),
        2: bit('FdoqSliceInterruptsSummary', [node_pdoq_shared_mem_fdoq_slice_interrupts(path)]),
        3: bit('EmpdInterruptsSummary', [node_pdoq_shared_mem_empd_interrupts(path)]),
    }
    return master_interrupt_node(status, bits)


def node_pdoq_shared_mem_pdoq_slice_interrupts(path):
    status = path.pdoq_shared_mem.pdoq_slice_interrupts
    mask = path.pdoq_shared_mem.pdoq_slice_interrupts_mask
    bits = {
        0: bit('PdoqSliceInterrupt0', [node_pdoq_slice_interrupt(path.slice[0].pdoq.top)]),
        1: bit('PdoqSliceInterrupt1', [node_pdoq_slice_interrupt(path.slice[1].pdoq.top)]),
        2: bit('PdoqSliceInterrupt2', [node_pdoq_slice_interrupt(path.slice[2].pdoq.top)]),
        3: bit('PdoqSliceInterrupt3', [node_pdoq_slice_interrupt(path.slice[3].pdoq.top)]),
        4: bit('PdoqSliceInterrupt4', [node_pdoq_slice_interrupt(path.slice[4].pdoq.top)]),
        5: bit('PdoqSliceInterrupt5', [node_pdoq_slice_interrupt(path.slice[5].pdoq.top)]),
    }
    return interrupt_node(status, mask, bits)


def node_pdoq_shared_mem_fdoq_slice_interrupts(path):
    status = path.pdoq_shared_mem.fdoq_slice_interrupts
    mask = path.pdoq_shared_mem.fdoq_slice_interrupts_mask
    bits = {
        0: bit('FdoqSliceInterrupt0', [node_fdoq_slice_interrupt(path.slice[0].pdoq.fdoq)]),
        1: bit('FdoqSliceInterrupt1', [node_fdoq_slice_interrupt(path.slice[1].pdoq.fdoq)]),
        2: bit('FdoqSliceInterrupt2', [node_fdoq_slice_interrupt(path.slice[2].pdoq.fdoq)]),
        3: bit('FdoqSliceInterrupt3', [node_fdoq_slice_interrupt(path.slice[3].pdoq.fdoq)]),
        4: bit('FdoqSliceInterrupt4', [node_fdoq_slice_interrupt(path.slice[4].pdoq.fdoq)]),
        5: bit('FdoqSliceInterrupt5', [node_fdoq_slice_interrupt(path.slice[5].pdoq.fdoq)]),
    }
    return interrupt_node(status, mask, bits)


def node_pdoq_slice_interrupt(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('GeneralInterruptRegisterSummary', [node_pdoq_slice_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_fdoq_slice_interrupt(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('GeneralInterruptSummary', [node_fdoq_slice_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_pdoq_slice_general_interrupt(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('SomeInterrupt0', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_fdoq_slice_general_interrupt(path):
    status = path.general_interrupt
    mask = path.general_interrupt_mask
    bits = {
        0: bit('FdllContextFifoOvf', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_pdoq_shared_mem_empd_interrupts(path):
    status = path.pdoq_shared_mem.empd_interrupts
    mask = path.pdoq_shared_mem.empd_interrupts_mask
    bits = {}
    for i in range(16):
        bits[i] = bit('EmpdInterrupt{}'.format(i), [node_pdoq_empd(path.pdoq.empd[i])])
    return interrupt_node(status, mask, bits)


def node_pdoq_empd(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('GeneralInterruptSummary', [node_pdoq_empd_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_pdoq_empd_general_interrupt(path):
    status = path.general_interrupt
    mask = path.general_interrupt_mask
    bits = {
        0: bit('EmdbDuplicateEntry', type=TYPE_DESIGN_BUG, sw_action=SW_ACTION_SOFT_RESET, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_pdvoq_slice(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('GeneralInterruptRegisterSummary', [node_pdvoq_slice_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_pdvoq_slice_general_interrupt(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('RdReqFifoOveflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        1: bit('DeqReqFifoOverflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        2: bit('InFifoOverflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        3: bit('dram_release_fifo_overflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        4: bit('ics_return_fifo_overflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        5: bit('cpu_return_fifo_overflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        6: bit('back_to_tail_fifo_overflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_pdvoq_shared_mma(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('GeneralInterruptRegisterSummary', [node_pdvoq_shared_mma_general_interrupt(path)]),
        2: bit('CgmCounterOverflowIntSummary', [node_pdvoq_shared_mma_cgm_counter_overflow(path)]),
    }
    return master_interrupt_node(status, bits)


def node_pdvoq_shared_mma_general_interrupt(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('DeleteContextFifoOverflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
        1: bit('PreShrFifoOverflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_pdvoq_shared_mma_cgm_counter_overflow(path):
    status = path.cgm_counter_overflow_int
    mask = path.cgm_counter_overflow_int_mask
    bits = {
        0: bit('cgm_counter_overflow', type=TYPE_MISCONFIGURATION, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_mem_protect_only(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_pdvoq_empd(path):
    return node_mem_protect_only(path)


def node_npu_sna(path):
    status = path.interrupt_register
    bits = {
        0: bit('MemProtectInterruptSummary', [node_MemProtectInterrupt(path)]),
        1: bit('sna_interrupt_arraySummary', [node_sna_interrupt_array(path)]),
    }
    return master_interrupt_node(status, bits)


def node_sna_interrupt_array(path):
    status = path.sna_interrupt_array
    mask = path.sna_interrupt_array_mask
    bits = {
        0: bit('program_selection_reg_tcam_miss', type=TYPE_MISCONFIGURATION),
    }
    return interrupt_node(status, mask, bits)


def create_non_wired_roots(lbr_tree):
    roots = [
        node_mem_protect_only(lbr_tree.npuh.fi),
        node_mem_protect_only(lbr_tree.mmu_buff),
    ]
    for s in lbr_tree.slice:
        roots += [
            node_mem_protect_only(s.npu.rxpp_term.fi_eng[0]),
            node_mem_protect_only(s.npu.rxpp_term.fi_eng[1]),
            node_mem_protect_only(s.npu.rxpp_term.fi_eng[2]),
            node_mem_protect_only(s.npu.rxpp_term.fi_eng[3]),
            node_mem_protect_only(s.npu.rxpp_term.fi_eng[4]),
            node_mem_protect_only(s.npu.rxpp_term.fi_eng[5]),
            node_mem_protect_only(s.npu.rxpp_term.fi_eng[6]),
            node_mem_protect_only(s.npu.rxpp_term.fi_eng[7]),
            node_mem_protect_only(s.npu.rxpp_term.fi_stage),
            node_npu_sna(s.npu.sna),
        ]
    return roots
