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
# Leaba interrupt tree is made of nodes and optionally bits which map to next level nodes.
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


from common_interrupt_tree import *
import json
import lldcli


def create_interrupt_tree(lbr_filename):
    initialize(lbr_filename)

    gibraltar_tree = lldcli.gibraltar_tree.create(lldcli.la_device_revision_e_GIBRALTAR_A0)

    msi_root = node_msi_master(gibraltar_tree)
    non_wired_roots = create_non_wired_roots(gibraltar_tree)
    all_roots = [msi_root] + non_wired_roots

    validate_and_print_summary(gibraltar_tree, all_roots)

    return all_roots


def create_non_wired_roots(lbr_tree):
    roots = []
    for s in lbr_tree.slice:
        roots += [
            node_npu_rxpp_term_fi_eng(s.npu.rxpp_term.fi_eng[0]),
            node_npu_rxpp_term_fi_eng(s.npu.rxpp_term.fi_eng[1]),
            node_npu_rxpp_term_fi_eng(s.npu.rxpp_term.fi_eng[2]),
            node_npu_rxpp_term_fi_eng(s.npu.rxpp_term.fi_eng[3]),
            node_npu_rxpp_term_fi_eng(s.npu.rxpp_term.fi_eng[4]),
            node_npu_rxpp_term_fi_eng(s.npu.rxpp_term.fi_eng[5]),
            node_npu_rxpp_term_fi_eng(s.npu.rxpp_term.fi_eng[6]),
            node_npu_rxpp_term_fi_eng(s.npu.rxpp_term.fi_eng[7]),

            node_mem_protect_only(s.npu.rxpp_term.fi_stage),

            node_npu_rxpp_term_sna(s.npu.rxpp_term.sna),
        ]

    roots += [node_npuh_fi(lbr_tree.npuh.fi)]

    return roots

##############################################################################
# Tree nodes
##############################################################################


def node_msi_master(lbr_tree):
    path = lbr_tree.sbif
    status = path.msi_master_interrupt_reg
    mask = path.msi_master_interrupt_reg_mask
    bits = {
        0: bit('msi_blocks0_int', [node_msi_blocks_interrupt_summary_reg0(lbr_tree)]),
        1: bit('msi_blocks1_int', [node_msi_blocks_interrupt_summary_reg1(lbr_tree)]),
        2: bit('msi_blocks2_int', [node_msi_blocks_interrupt_summary_reg2(lbr_tree)]),
        3: bit('msi_acc_eng_err_int', type=TYPE_MISCONFIGURATION),
        4: bit('msi_acc_eng_err_int', type=TYPE_MISCONFIGURATION),
        5: bit('msi_acc_eng_err_int', type=TYPE_MISCONFIGURATION),
        6: bit('msi_acc_eng_err_int', type=TYPE_MISCONFIGURATION),
        7: bit('msi_acc_eng_err_int', type=TYPE_MISCONFIGURATION),
        8: bit('msi_acc_eng_err_int', type=TYPE_MISCONFIGURATION),
        9: bit('msi_acc_eng_err_int', type=TYPE_MISCONFIGURATION),
        10: bit('msi_acc_eng_err_int', type=TYPE_MISCONFIGURATION),
        11: bit('msi_acc_eng_done_int', type=TYPE_NO_ERR_INTERNAL),
        12: bit('msi_acc_eng_done_int', type=TYPE_NO_ERR_INTERNAL),
        13: bit('msi_acc_eng_done_int', type=TYPE_NO_ERR_INTERNAL),
        14: bit('msi_acc_eng_done_int', type=TYPE_NO_ERR_INTERNAL),
        15: bit('msi_acc_eng_done_int', type=TYPE_NO_ERR_INTERNAL),
        16: bit('msi_acc_eng_done_int', type=TYPE_NO_ERR_INTERNAL),
        17: bit('msi_acc_eng_done_int', type=TYPE_NO_ERR_INTERNAL),
        18: bit('msi_acc_eng_done_int', type=TYPE_NO_ERR_INTERNAL),
        19: bit('msi_packet_dma_err_int', type=TYPE_MISCONFIGURATION),
        20: bit('msi_packet_dma_done_int', type=TYPE_NO_ERR_INTERNAL),
        21: bit('msi_packet_dma_drop_fc_int', type=TYPE_NO_ERR_INTERNAL),
        22: bit('msi_axi_mem_ecc_int', type=TYPE_ECC_2B),
        23: bit('msi_css_mem_ecc_int', type=TYPE_ECC_2B),
        24: bit('msi_sbif_mem_ecc_int', type=TYPE_ECC_2B),
        25: bit('msi_pcie_phy_ln0_int', type=TYPE_NO_ERR_INTERNAL),
        26: bit('msi_pcie_phy_ln1_int', type=TYPE_NO_ERR_INTERNAL),
    }
    return interrupt_node(status, mask, bits)


def node_msi_blocks_interrupt_summary_reg0(lbr_tree):
    path = lbr_tree
    status = path.sbif.msi_blocks_interrupt_summary_reg0
    mask = path.sbif.msi_blocks_interrupt_summary_reg0_mask
    bits = {
        0: bit('msi_cdb_top_interrupt_summary', [node_cdb_top(path.cdb)]),
        1: bit('msi_counters_interrupt_summary', [node_counters(path.counters)]),
        2: bit('msi_dram_control_interrupt_summary', [node_dvoq(path)]),
        3: bit('msi_egr_interrupt_summary', [node_tx_cgm(path)]),
        4: bit('msi_fdll_interrupt_summary', [node_fdll_shared(path)]),
        5: bit('msi_fllb_interrupt_summary', [node_rx_counters(path)]),
        6: bit('msi_ics_interrupt_summary', [node_ics_top(path)]),
        7: bit('msi_nw_reorder_interrupt_summary', [node_nw_reorder(path)]),
        8: bit('msi_pp_reorder_interrupt_summary', []),  # this bit is not in use
        9: bit('msi_pdoq_interrupt_summary', [node_pdoq_shared_mem(path)]),
        10: bit('msi_pdvoq_interrupt_summary', [
            node_pdvoq_shared_mma(path.pdvoq_shared_mma),
            node_slice_pdvoq(path.slice[0].pdvoq),
            node_slice_pdvoq(path.slice[1].pdvoq),
            node_slice_pdvoq(path.slice[2].pdvoq),
            node_slice_pdvoq(path.slice[3].pdvoq),
            node_slice_pdvoq(path.slice[4].pdvoq),
            node_slice_pdvoq(path.slice[5].pdvoq),
            node_mem_protect_only(path.pdvoq.empd[0]),
            node_mem_protect_only(path.pdvoq.empd[1]),
            node_mem_protect_only(path.pdvoq.empd[2]),
            node_mem_protect_only(path.pdvoq.empd[3]),
            node_mem_protect_only(path.pdvoq.empd[4]),
            node_mem_protect_only(path.pdvoq.empd[5]),
            node_mem_protect_only(path.pdvoq.empd[6]),
            node_mem_protect_only(path.pdvoq.empd[7]),
            node_mem_protect_only(path.pdvoq.empd[8]),
            node_mem_protect_only(path.pdvoq.empd[9]),
            node_mem_protect_only(path.pdvoq.empd[10]),
            node_mem_protect_only(path.pdvoq.empd[11]),
            node_mem_protect_only(path.pdvoq.empd[12]),
            node_mem_protect_only(path.pdvoq.empd[13]),
            node_mem_protect_only(path.pdvoq.empd[14]),
            node_mem_protect_only(path.pdvoq.empd[15]),
        ]),
        11: bit('msi_reassembly_interrupt_summary', [node_mem_protect_only(path.reassembly)]),
        12: bit('msi_rx_cgm_interrupt_summary', [node_rx_cgm(path.rx_cgm)]),
        13: bit('msi_rx_meter_interrupt_summary', [node_rx_meter(path.rx_meter)]),
        14: bit('msi_rx_pdr_interrupt_summary', [node_rx_pdr(path)]),
        15: bit('msi_sch_interrupt_summary', [node_sch_top(path)]),
        16: bit('msi_sms_interrupt_summary', [node_sms_main(path)]),
        17: bit('msi_ts_mon_interrupt_summary', [node_ts_mon(path.ts_mon)]),
        18: bit('msi_hbmhi_interrupt_summary', [node_hbm_db(path.hbm.db[1])]),
        19: bit('msi_hbmlo_interrupt_summary', [node_hbm_db(path.hbm.db[0])]),
        20: bit('msi_mmu_interrupt_summary', [node_mmu(path)]),
        21: bit('msi_csms_interrupt_summary', [node_csms(path.csms)]),
        22: bit('msi_pier_interrupt_summary', [node_dmc_pier(path.dmc.pier)]),
        23: bit('msi_frm_interrupt_summary', [node_dmc_frm(path.dmc.frm)]),
        24: bit('msi_fte_interrupt_summary', [node_dmc_fte(path.dmc.fte)]),
        25: bit('msi_npu_host_interrupt_summary', [
            node_npuh_host(path.npuh.host),
            node_npuh_npe(path.npuh.npe),
        ]),
        26: bit('msi_mrb_interrupt_summary', [node_dmc_mrb(path.dmc.mrb)]),
    }

    return interrupt_node(status, mask, bits)


def node_msi_blocks_interrupt_summary_reg1(lbr_tree):
    path = lbr_tree
    status = path.sbif.msi_blocks_interrupt_summary_reg1
    mask = path.sbif.msi_blocks_interrupt_summary_reg1_mask
    bits = {
        0: bit('msi_idb_interrupt_summary', [node_slice_pair_idb(path.slice_pair[0].idb)]),
        1: bit('msi_idb_interrupt_summary', [node_slice_pair_idb(path.slice_pair[1].idb)]),
        2: bit('msi_idb_interrupt_summary', [node_slice_pair_idb(path.slice_pair[2].idb)]),
        3: bit('msi_ifg_core_interrupt_summary', [node_ifg_core(path.slice[0].ifg[0])]),
        4: bit('msi_ifg_core_interrupt_summary', [node_ifg_core(path.slice[0].ifg[1])]),
        5: bit('msi_ifg_core_interrupt_summary', [node_ifg_core(path.slice[1].ifg[0])]),
        6: bit('msi_ifg_core_interrupt_summary', [node_ifg_core(path.slice[1].ifg[1])]),
        7: bit('msi_ifg_core_interrupt_summary', [node_ifg_core(path.slice[2].ifg[0])]),
        8: bit('msi_ifg_core_interrupt_summary', [node_ifg_core(path.slice[2].ifg[1])]),
        9: bit('msi_ifg_core_interrupt_summary', [node_ifg_core(path.slice[3].ifg[0])]),
        10: bit('msi_ifg_core_interrupt_summary', [node_ifg_core(path.slice[3].ifg[1])]),
        11: bit('msi_ifg_core_interrupt_summary', [node_ifg_core(path.slice[4].ifg[0])]),
        12: bit('msi_ifg_core_interrupt_summary', [node_ifg_core(path.slice[4].ifg[1])]),
        13: bit('msi_ifg_core_interrupt_summary', [node_ifg_core(path.slice[5].ifg[0])]),
        14: bit('msi_ifg_core_interrupt_summary', [node_ifg_core(path.slice[5].ifg[1])]),
        15: bit('msi_ifg_serdes_interrupt_summary', [node_ifg_serdes(path.slice[0].ifg[0].serdes_pool24)]),
        16: bit('msi_ifg_serdes_interrupt_summary', [node_ifg_serdes(path.slice[0].ifg[1].serdes_pool24)]),
        17: bit('msi_ifg_serdes_interrupt_summary', [node_ifg_serdes(path.slice[1].ifg[0].serdes_pool24)]),
        18: bit('msi_ifg_serdes_interrupt_summary', [node_ifg_serdes(path.slice[1].ifg[1].serdes_pool16)]),
        19: bit('msi_ifg_serdes_interrupt_summary', [node_ifg_serdes(path.slice[2].ifg[0].serdes_pool16)]),
        20: bit('msi_ifg_serdes_interrupt_summary', [node_ifg_serdes(path.slice[2].ifg[1].serdes_pool24)]),
        21: bit('msi_ifg_serdes_interrupt_summary', [node_ifg_serdes(path.slice[3].ifg[0].serdes_pool24)]),
        22: bit('msi_ifg_serdes_interrupt_summary', [node_ifg_serdes(path.slice[3].ifg[1].serdes_pool16)]),
        23: bit('msi_ifg_serdes_interrupt_summary', [node_ifg_serdes(path.slice[4].ifg[0].serdes_pool16)]),
        24: bit('msi_ifg_serdes_interrupt_summary', [node_ifg_serdes(path.slice[4].ifg[1].serdes_pool24)]),
        25: bit('msi_ifg_serdes_interrupt_summary', [node_ifg_serdes(path.slice[5].ifg[0].serdes_pool24)]),
        26: bit('msi_ifg_serdes_interrupt_summary', [node_ifg_serdes(path.slice[5].ifg[1].serdes_pool24)]),
    }

    return interrupt_node(status, mask, bits)


def node_msi_blocks_interrupt_summary_reg2(lbr_tree):
    path = lbr_tree
    status = path.sbif.msi_blocks_interrupt_summary_reg2
    mask = path.sbif.msi_blocks_interrupt_summary_reg2_mask
    bits = {
        0: bit('msi_rxpp_term_interrupt_summary', [node_npu_rxpp_term(path.slice[0].npu.rxpp_term)]),
        1: bit('msi_rxpp_term_interrupt_summary', [node_npu_rxpp_term(path.slice[1].npu.rxpp_term)]),
        2: bit('msi_rxpp_term_interrupt_summary', [node_npu_rxpp_term(path.slice[2].npu.rxpp_term)]),
        3: bit('msi_rxpp_term_interrupt_summary', [node_npu_rxpp_term(path.slice[3].npu.rxpp_term)]),
        4: bit('msi_rxpp_term_interrupt_summary', [node_npu_rxpp_term(path.slice[4].npu.rxpp_term)]),
        5: bit('msi_rxpp_term_interrupt_summary', [node_npu_rxpp_term(path.slice[5].npu.rxpp_term)]),

        6: bit('msi_rxpp_fwd_interrupt_summary', [node_npu_rxpp_fwd(path.slice[0].npu.rxpp_fwd)]),
        7: bit('msi_rxpp_fwd_interrupt_summary', [node_npu_rxpp_fwd(path.slice[1].npu.rxpp_fwd)]),
        8: bit('msi_rxpp_fwd_interrupt_summary', [node_npu_rxpp_fwd(path.slice[2].npu.rxpp_fwd)]),
        9: bit('msi_rxpp_fwd_interrupt_summary', [node_npu_rxpp_fwd(path.slice[3].npu.rxpp_fwd)]),
        10: bit('msi_rxpp_fwd_interrupt_summary', [node_npu_rxpp_fwd(path.slice[4].npu.rxpp_fwd)]),
        11: bit('msi_rxpp_fwd_interrupt_summary', [node_npu_rxpp_fwd(path.slice[5].npu.rxpp_fwd)]),

        12: bit('msi_txpp_interrupt_summary', [node_npu_txpp(path.slice[0].npu.txpp)]),
        13: bit('msi_txpp_interrupt_summary', [node_npu_txpp(path.slice[1].npu.txpp)]),
        14: bit('msi_txpp_interrupt_summary', [node_npu_txpp(path.slice[2].npu.txpp)]),
        15: bit('msi_txpp_interrupt_summary', [node_npu_txpp(path.slice[3].npu.txpp)]),
        16: bit('msi_txpp_interrupt_summary', [node_npu_txpp(path.slice[4].npu.txpp)]),
        17: bit('msi_txpp_interrupt_summary', [node_npu_txpp(path.slice[5].npu.txpp)]),
    }

    return interrupt_node(status, mask, bits)


def node_cdb_top(path):
    status = path.top.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.top)]),
        1: bit('cdb_core0_interrupt_summary_reg_summary', [node_cdb_core_interrupt_summary(path, 0)]),
        2: bit('cdb_core1_interrupt_summary_reg_summary', [node_cdb_core_interrupt_summary(path, 1)]),
        3: bit('cdb_core2_interrupt_summary_reg_summary', [node_cdb_core_interrupt_summary(path, 2)]),
        4: bit('cdb_core3_interrupt_summary_reg_summary', [node_cdb_core_interrupt_summary(path, 3)]),
        5: bit('cdb_core4_interrupt_summary_reg_summary', [node_cdb_core_interrupt_summary(path, 4)]),
        6: bit('cdb_core5_interrupt_summary_reg_summary', [node_cdb_core_interrupt_summary(path, 5)]),
        7: bit('cdb_core6_interrupt_summary_reg_summary', [node_cdb_core_interrupt_summary(path, 6)]),
        8: bit('cdb_core7_interrupt_summary_reg_summary', [node_cdb_core_interrupt_summary(path, 7)]),
        9: bit('lpm_uneven_load_blance_summary', [node_cdb_lpm_uneven_load_blance(path.top)]),
        10: bit('cem_uneven_load_blance_summary', [node_cdb_cem_uneven_load_blance(path.top)]),
        11: bit('aging_overflow_summary', [node_cdb_aging_overflow(path.top)]),
        12: bit('bulk_update_overflow_summary', [node_cdb_bulk_update_overflow(path.top)]),
        13: bit('arc_interrupt_to_cpu_summary', [node_cdb_arc_interrupt_to_cpu(path.top)]),
    }
    return master_interrupt_node(status, bits)


def node_cdb_core_interrupt_summary(path, i):
    status = path.top.cdb_core_interrupt_summary_reg[i]
    mask = path.top.cdb_core_interrupt_summary_reg_mask[i]
    bits = {
        0: bit('cdb_core_interrupt_summary', [node_cdb_core(path.core[i])]),
    }
    return interrupt_node(status, mask, bits)


def node_cdb_core(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('lpm0_shared_sram_1b_err_int_reg_summary', [node_cdb_core_lpm_shared_sram_1b_err(path, 0)]),
        2: bit('lpm1_shared_sram_1b_err_int_reg_summary', [node_cdb_core_lpm_shared_sram_1b_err(path, 1)]),
        3: bit('lpm0_shared_sram_2b_err_int_reg_summary', [node_cdb_core_lpm_shared_sram_2b_err(path, 0)]),
        4: bit('lpm1_shared_sram_2b_err_int_reg_summary', [node_cdb_core_lpm_shared_sram_2b_err(path, 1)]),
        5: bit('em0_shared_sram_err_int_reg_summary', [node_cdb_core_em_shared_sram_err(path, 0)]),
        6: bit('em1_shared_sram_err_int_reg_summary', [node_cdb_core_em_shared_sram_err(path, 1)]),
        7: bit('lpm0_no_tcam_hit_int_reg_summary', [node_cdb_core_lpm_no_tcam_hit(path, 0)]),
        8: bit('lpm1_no_tcam_hit_int_reg_summary', [node_cdb_core_lpm_no_tcam_hit(path, 1)]),
    }
    return master_interrupt_node(status, bits)


def node_cdb_core_lpm_shared_sram_1b_err(path, i):
    status = path.lpm_shared_sram_1b_err_int_reg[i]
    mask = path.lpm_shared_sram_1b_err_int_reg_mask[i]
    bits = {
        0: bit('lpm_shared_sram_1b_err_interrupt', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_cdb_core_lpm_shared_sram_2b_err(path, i):
    status = path.lpm_shared_sram_2b_err_int_reg[i]
    mask = path.lpm_shared_sram_2b_err_int_reg_mask[i]
    bits = {
        0: bit('lpm_shared_sram_2b_err_interrupt', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_cdb_core_em_shared_sram_err(path, i):
    status = path.em_shared_sram_err_int_reg[i]
    mask = path.em_shared_sram_err_int_reg_mask[i]
    bits = {
        0: bit('em_shared_sram_err_interrupt', type=TYPE_OTHER, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_cdb_core_lpm_no_tcam_hit(path, i):
    status = path.lpm_no_tcam_hit_int_reg[i]
    mask = path.lpm_no_tcam_hit_int_reg_mask[i]
    bits = {
        0: bit('lpm_no_tcam_hit_int', type=TYPE_OTHER, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_cdb_lpm_uneven_load_blance(path):
    status = path.lpm_uneven_load_blance
    mask = path.lpm_uneven_load_blance_mask
    bits = {
        0: bit('lpm_uneven_load_balance', type=TYPE_OTHER, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_cdb_cem_uneven_load_blance(path):
    status = path.cem_uneven_load_blance
    mask = path.cem_uneven_load_blance_mask
    bits = {
        0: bit('cem_uneven_load_balance', type=TYPE_OTHER, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_cdb_aging_overflow(path):
    status = path.aging_overflow
    mask = path.aging_overflow_mask
    bits = {
        0: bit('aging_overflow', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_cdb_bulk_update_overflow(path):
    status = path.bulk_update_overflow
    mask = path.bulk_update_overflow_mask
    bits = {
        0: bit('bulk_update_overflow', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_cdb_arc_interrupt_to_cpu(path):
    status = path.arc_interrupt_to_cpu
    mask = path.arc_interrupt_to_cpu_mask
    bits = {
        0: bit('cem_mng2css_interrupt', type=TYPE_NO_ERR_NOTIFICATION),
    }
    return interrupt_node(status, mask, bits)


def node_counters(path):
    status = path.top.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.top)]),
        1: bit('interrupt_reg_summary', [node_counters_interrupt_reg(path.top)]),
        2: bit('bank_group_interrupt_reg0_summary', [node_counters_bank_group_0(path)]),
        3: bit('bank_group_interrupt_reg1_summary', [node_counters_bank_group_1(path)])
    }
    return master_interrupt_node(status, bits)


def node_counters_interrupt_reg(path):
    status = path.interrupt_reg
    mask = path.interrupt_reg_mask
    bits = {
        0: bit('same_pd_bank_collision', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_counters_bank_group_0(path):
    status = path.top.bank_group_interrupt_reg0
    mask = path.top.bank_group_interrupt_reg0_mask
    bits = {}
    for i in range(18):
        bits[i] = bit('bank_group_interrupt%d' % i, [node_counters_bank_group_8k(path.bank_8k[i])])
    return interrupt_node(status, mask, bits)


def node_counters_bank_group_1(path):
    status = path.top.bank_group_interrupt_reg1
    mask = path.top.bank_group_interrupt_reg1_mask
    bits = {}
    for i in range(14):
        bits[i] = bit('bank_group_interrupt%d' % (i + 18), [node_counters_bank_group_8k(path.bank_8k[i + 18])])
    for i in range(14, 18):
        bits[i] = bit('bank_group_interrupt%d' % (i + 18), [node_counters_bank_group(path.bank_6k[i - 14])])
    return interrupt_node(status, mask, bits)


def node_counters_bank_group(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('interrupt_reg0_summary', [node_counters_bank_interrupt_reg(path, 0)]),
        2: bit('interrupt_reg1_summary', [node_counters_bank_interrupt_reg(path, 1)]),
        3: bit('interrupt_reg2_summary', [node_counters_bank_interrupt_reg(path, 2)]),
    }
    return master_interrupt_node(status, bits)


def node_counters_bank_interrupt_reg(path, i):
    status = path.interrupt_reg[i]
    mask = path.interrupt_reg_mask[i]
    bits = {
        0: bit('max_counter_crossed_threshold', type=TYPE_COUNTER_THRESHOLD_CROSSED),
        1: bit('pd_config_mismatch', type=TYPE_OTHER),
        2: bit('lm_result_fifo_overflow', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_counters_bank_group_8k(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('interrupt_reg0_summary', [node_counters_bank_interrupt_reg_8k(path, 0)]),
        2: bit('interrupt_reg1_summary', [node_counters_bank_interrupt_reg_8k(path, 1)]),
        3: bit('interrupt_reg2_summary', [node_counters_bank_interrupt_reg_8k(path, 2)]),
    }
    return master_interrupt_node(status, bits)


def node_counters_bank_interrupt_reg_8k(path, i):
    status = path.interrupt_reg[i]
    mask = path.interrupt_reg_mask[i]
    bits = {
        0: bit('max_counter_crossed_threshold', type=TYPE_COUNTER_THRESHOLD_CROSSED),
        1: bit('pd_config_mismatch', type=TYPE_OTHER),
        2: bit('lm_result_fifo_overflow', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_dvoq(path):
    status = path.dvoq.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.dvoq)]),
        1: bit('slave_interrupts_summary', [node_dvoq_slave_interrupts(path)]),
    }
    return master_interrupt_node(status, bits)


def node_dvoq_slave_interrupts(path):
    status = path.dvoq.slave_interrupts
    mask = path.dvoq.slave_interrupts_mask
    bits = {
        0: bit('hmc_cgm', [node_dram_cgm(path.dram_cgm)]),
        1: bit('dics', [node_dics(path.dics)]),
    }
    return interrupt_node(status, mask, bits)


def node_dram_cgm(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('cgm_int_summary', [node_dram_cgm_int(path)]),
    }
    return master_interrupt_node(status, bits)


def node_dram_cgm_int(path):
    status = path.cgm_int
    mask = path.cgm_int_mask
    bits = {
        0: bit('total_buffers_underflow', type=TYPE_OTHER),
        1: bit('pool_underflow', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_dics(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('general_interrupt_register_summary', [node_dics_general_interrupt(path)]),
        2: bit('fabric_blocking_intr_reg_summary', [node_dics_fabric_blocking_intr(path)]),
    }
    return master_interrupt_node(status, bits)


def node_dics_general_interrupt(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('fabric_blocking_intr', type=TYPE_OTHER, is_masked=True),
        1: bit('aged_out_fifo_full', type=TYPE_OTHER),
        2: bit('dics2mmu_fifo_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        3: bit('crdt_req_cbt_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_dics_fabric_blocking_intr(path):
    status = path.fabric_blocking_intr_reg
    mask = path.fabric_blocking_intr_reg_mask
    bits = {
        0: bit('total_list_full', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_tx_cgm(path):
    status = path.tx_cgm_top.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.tx_cgm_top)]),
        1: bit('global_cgm_interrupt_summary', [node_tx_cgm_global(path.tx_cgm_top)]),
        2: bit('egr_slice_interrupt0_summary', [node_tx_cgm_egr_slice(path, 0)]),
        3: bit('egr_slice_interrupt1_summary', [node_tx_cgm_egr_slice(path, 1)]),
        4: bit('egr_slice_interrupt2_summary', [node_tx_cgm_egr_slice(path, 2)]),
        5: bit('egr_slice_interrupt3_summary', [node_tx_cgm_egr_slice(path, 3)]),
        6: bit('egr_slice_interrupt4_summary', [node_tx_cgm_egr_slice(path, 4)]),
        7: bit('egr_slice_interrupt5_summary', [node_tx_cgm_egr_slice(path, 5)]),
    }
    return master_interrupt_node(status, bits)


def node_tx_cgm_global(path):
    status = path.global_cgm_interrupt
    mask = path.global_cgm_interrupt_mask
    bits = {
        0: bit('total_sch_uc_buffer_roll_over', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        1: bit('total_sch_uc_local_buffer_roll_over', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        2: bit('total_sch_uc_remote_buffer_roll_over', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        3: bit('total_pd_roll_over', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        4: bit('total_sch_uc_pd_roll_over', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        5: bit('total_mc_pd_roll_over', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        6: bit('total_fab_pd_roll_over', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_tx_cgm_egr_slice(path, i):
    status = path.tx_cgm_top.egr_slice_interrupt[i]
    mask = path.tx_cgm_top.egr_slice_interrupt_mask[i]
    bits = {
        0: bit('tsms_slice_interrupt', [node_slice_ts_ms(path.slice[i].ts_ms)]),
        1: bit('txpdr_slice_interrupt', [node_slice_tx_pdr(path.slice[i].tx.pdr)]),
        2: bit('txcgm_slice_interrupt', [node_slice_tx_cgm(path.slice[i].tx.cgm)]),
    }
    return interrupt_node(status, mask, bits)


def node_slice_ts_ms(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('general_interrupt_register_summary', [node_ts_ms_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_ts_ms_general_interrupt(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('uch_ms_time_error', type=TYPE_OTHER),
        1: bit('ucl_ms_time_error', type=TYPE_OTHER),
        2: bit('mc_ms_time_error', type=TYPE_OTHER),
        3: bit('tsms_fifo_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_slice_tx_pdr(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('general_interrupt_register_summary', [node_slice_tx_pdr_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_slice_tx_pdr_general_interrupt(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('mc_flb_to_uc_oq', type=TYPE_OTHER),
        1: bit('empty_link_bitmap', type=TYPE_OTHER),
        2: bit('ucdv_rollover', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_slice_tx_cgm(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('slice_cgm_interrupt_summary', [node_slice_tx_cgm_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_slice_tx_cgm_general_interrupt(path):
    status = path.slice_cgm_interrupt
    mask = path.slice_cgm_interrupt_mask
    bits = {
        0: bit('oqg_uc_pd_counter_roll_over', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        1: bit('oqg_uc_buffer_counter_roll_over', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        2: bit('oqg_uc_byte_counter_roll_over', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        3: bit('ifg_uc_pd_counter_roll_over', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        4: bit('ifg_uc_buffer_counter_roll_over', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        5: bit('ifg_uc_byte_counter_roll_over', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        6: bit('ucdv_rollover', type=TYPE_OTHER, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_fdll_shared(path):
    status = path.fdll_shared_mem.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.fdll_shared_mem)]),
        1: bit('general_interrupt_register_summary', [node_fdll_shared_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_fdll_shared_general_interrupt(path):
    status = path.fdll_shared_mem.general_interrupt_register
    mask = path.fdll_shared_mem.general_interrupt_register_mask
    bits = {
        0: bit('write_fail_cbt_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        1: bit('empd_interrupt0', [node_fdll(path.fdll[0])]),
        2: bit('empd_interrupt1', [node_fdll(path.fdll[1])]),
        3: bit('empd_interrupt2', [node_fdll(path.fdll[2])]),
        4: bit('empd_interrupt3', [node_fdll(path.fdll[3])]),
        5: bit('empd_interrupt4', [node_fdll(path.fdll[4])]),
        6: bit('empd_interrupt5', [node_fdll(path.fdll[5])]),
        7: bit('empd_interrupt6', [node_fdll(path.fdll[6])]),
        8: bit('empd_interrupt7', [node_fdll(path.fdll[7])]),
    }
    return interrupt_node(status, mask, bits)


def node_fdll(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('general_interrupt_summary', [node_fdll_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_fdll_general_interrupt(path):
    status = path.general_interrupt
    mask = path.general_interrupt_mask
    bits = {
        0: bit('emdb_duplicate_entry', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        1: bit('ucdv_rollover', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_rx_counters(path):
    status = path.rx_counters.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.rx_counters)]),
        1: bit('slice_interrupt_reg0_summary', [node_rx_counters_slice(path, 0)]),
        2: bit('slice_interrupt_reg1_summary', [node_rx_counters_slice(path, 1)]),
        3: bit('slice_interrupt_reg2_summary', [node_rx_counters_slice(path, 2)]),
        4: bit('slice_interrupt_reg3_summary', [node_rx_counters_slice(path, 3)]),
        5: bit('slice_interrupt_reg4_summary', [node_rx_counters_slice(path, 4)]),
        6: bit('slice_interrupt_reg5_summary', [node_rx_counters_slice(path, 5)]),
    }
    return master_interrupt_node(status, bits)


def node_rx_counters_slice(path, i):
    status = path.rx_counters.slice_interrupt_reg[i]
    mask = path.rx_counters.slice_interrupt_reg_mask[i]

    if i == 5:
        fllb = path.slice[5].fabric_fllb
    else:
        fllb = path.slice[i].fllb

    bits = {
        0: bit('fllb_slice_interrupt', [node_mem_protect_only(fllb)]),
        1: bit('lm_read_to_non_enabled_bank', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_ics_top(path):
    status = path.ics_top.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.ics_top)]),
        1: bit('general_interrupt_register_summary', [node_ics_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_ics_general_interrupt(path):
    status = path.ics_top.general_interrupt_register
    mask = path.ics_top.general_interrupt_register_mask
    bits = {
        0: bit('ics_slice0_interrupt', [node_slice_ics(path.slice[0].ics)]),
        1: bit('ics_slice1_interrupt', [node_slice_ics(path.slice[1].ics)]),
        2: bit('ics_slice2_interrupt', [node_slice_ics(path.slice[2].ics)]),
        3: bit('ics_slice3_interrupt', [node_slice_ics(path.slice[3].ics)]),
        4: bit('ics_slice4_interrupt', [node_slice_ics(path.slice[4].ics)]),
        5: bit('ics_slice5_interrupt', [node_slice_ics(path.slice[5].ics)]),

        6: bit('filb_slice0_interrupt', [node_slice_filb(path.slice[0].filb)]),
        7: bit('filb_slice1_interrupt', [node_slice_filb(path.slice[1].filb)]),
        8: bit('filb_slice2_interrupt', [node_slice_filb(path.slice[2].filb)]),
        9: bit('filb_slice3_interrupt', [node_slice_filb(path.slice[3].filb)]),
        10: bit('filb_slice4_interrupt', [node_slice_filb(path.slice[4].filb)]),
        11: bit('filb_slice5_interrupt', [node_slice_filb(path.slice[5].filb)]),

        12: bit('dram_pack_pref_fifo_overf', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        13: bit('dram_delete_pref_fifo_overf', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_slice_ics(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('general_interrupt_register_summary', [node_slice_ics_general_interrupt(path)]),
        2: bit('fabric_blocking_intr_reg_summary', [node_slice_ics_fabric_blocking(path)]),
    }
    return master_interrupt_node(status, bits)


def node_slice_ics_general_interrupt(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('fabric_blocking_intr', type=TYPE_OTHER),
        1: bit('queue_aged_out_intr', type=TYPE_OTHER, is_masked=True),
        2: bit('rxcgm_cbt_full_intr', type=TYPE_OTHER, is_masked=True),
        3: bit('voq_to_context_fifo_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        4: bit('dram_list_qsize_fif_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        5: bit('dram_list_reread_fif_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        6: bit('dram_list_enq_fif_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        7: bit('exit_dram_list_reread_full', type=TYPE_OTHER, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_slice_ics_fabric_blocking(path):
    status = path.fabric_blocking_intr_reg
    mask = path.fabric_blocking_intr_reg_mask
    bits = {
        0: bit('flb_hp_list_full', type=TYPE_LACK_OF_RESOURCES),
        1: bit('flb_lp_list_full', type=TYPE_LACK_OF_RESOURCES),
        2: bit('rlb_uch_list_full', type=TYPE_LACK_OF_RESOURCES),
        3: bit('rlb_ucl_list_full', type=TYPE_LACK_OF_RESOURCES),
        4: bit('rlb_mc_list_full', type=TYPE_LACK_OF_RESOURCES),
        5: bit('total_list_full', type=TYPE_LACK_OF_RESOURCES),
    }
    return interrupt_node(status, mask, bits)


def node_slice_filb(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('general_interrupt_register_summary', [node_slice_filb_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_slice_filb_general_interrupt(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('slb_open_but_no_link', type=TYPE_LACK_OF_RESOURCES),
        1: bit('slb_pd_fifo_overflow', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_nw_reorder(path):
    status = path.nw_reorder.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.nw_reorder)]),
        1: bit('reorder_global_interrupt_summary', [node_nw_reorder_global(path)]),
    }
    return master_interrupt_node(status, bits)


def node_nw_reorder_global(path):
    status = path.nw_reorder.reorder_global_interrupt
    mask = path.nw_reorder.reorder_global_interrupt_mask
    bits = {
        0: bit('nw_reorder_block0_interrupt', [node_mem_protect_only(path.slice[3].nw_reorder_block[0])]),
        1: bit('nw_reorder_block1_interrupt', [node_mem_protect_only(path.slice[3].nw_reorder_block[1])]),
        2: bit('nw_reorder_block2_interrupt', [node_mem_protect_only(path.slice[4].nw_reorder_block[0])]),
        3: bit('nw_reorder_block3_interrupt', [node_mem_protect_only(path.slice[4].nw_reorder_block[1])]),
        4: bit('nw_reorder_block4_interrupt', [node_mem_protect_only(path.slice[5].nw_reorder_block[0])]),
        5: bit('nw_reorder_block5_interrupt', [node_mem_protect_only(path.slice[5].nw_reorder_block[1])]),
        6: bit('pp_reorder_slice0_interrupt', [node_mem_protect_only(path.slice[0].pp_reorder)]),
        7: bit('pp_reorder_slice1_interrupt', [node_mem_protect_only(path.slice[1].pp_reorder)]),
        8: bit('pp_reorder_slice2_interrupt', [node_mem_protect_only(path.slice[2].pp_reorder)]),
    }
    return interrupt_node(status, mask, bits)


def node_pdoq_shared_mem(path):
    status = path.pdoq_shared_mem.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.pdoq_shared_mem)]),
        1: bit('pdoq_slice_interrupts_summary', [node_pdoq_shared_mem_pdoq_slice(path)]),
        2: bit('fdoq_slice_interrupts_summary', [node_pdoq_shared_mem_fdoq_slice(path)]),
        3: bit('empd_interrupts_summary', [node_pdoq_shared_mem_empd_interrupts(path)]),
    }
    return master_interrupt_node(status, bits)


def node_pdoq_shared_mem_pdoq_slice(path):
    status = path.pdoq_shared_mem.pdoq_slice_interrupts
    mask = path.pdoq_shared_mem.pdoq_slice_interrupts_mask
    bits = {
        0: bit('pdoq_slice_interrupt0', [node_slice_pdoq_top(path.slice[0].pdoq.top)]),
        1: bit('pdoq_slice_interrupt1', [node_slice_pdoq_top(path.slice[1].pdoq.top)]),
        2: bit('pdoq_slice_interrupt2', [node_slice_pdoq_top(path.slice[2].pdoq.top)]),
        3: bit('pdoq_slice_interrupt3', [node_slice_pdoq_top(path.slice[3].pdoq.top)]),
        4: bit('pdoq_slice_interrupt4', [node_slice_pdoq_top(path.slice[4].pdoq.top)]),
        5: bit('pdoq_slice_interrupt5', [node_slice_pdoq_top(path.slice[5].pdoq.top)]),
    }
    return interrupt_node(status, mask, bits)


def node_slice_pdoq_top(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('general_interrupt_register_summary', [node_slice_pdoq_top_general(path)]),
    }
    return master_interrupt_node(status, bits)


def node_slice_pdoq_top_general(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('some_interrupt0', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_pdoq_shared_mem_fdoq_slice(path):
    status = path.pdoq_shared_mem.fdoq_slice_interrupts
    mask = path.pdoq_shared_mem.fdoq_slice_interrupts_mask
    bits = {
        0: bit('fdoq_slice_interrupt0', [node_slice_pdoq_fdoq(path.slice[0].pdoq.fdoq)]),
        1: bit('fdoq_slice_interrupt1', [node_slice_pdoq_fdoq(path.slice[1].pdoq.fdoq)]),
        2: bit('fdoq_slice_interrupt2', [node_slice_pdoq_fdoq(path.slice[2].pdoq.fdoq)]),
        3: bit('fdoq_slice_interrupt3', [node_slice_pdoq_fdoq(path.slice[3].pdoq.fdoq)]),
        4: bit('fdoq_slice_interrupt4', [node_slice_pdoq_fdoq(path.slice[4].pdoq.fdoq)]),
        5: bit('fdoq_slice_interrupt5', [node_slice_pdoq_fdoq(path.slice[5].pdoq.fdoq)]),
    }
    return interrupt_node(status, mask, bits)


def node_slice_pdoq_fdoq(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('general_interrupt_summary', [node_slice_pdoq_fdoq_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_slice_pdoq_fdoq_general_interrupt(path):
    status = path.general_interrupt
    mask = path.general_interrupt_mask
    bits = {
        0: bit('fdll_context_fifo_ovf', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_pdoq_shared_mem_empd_interrupts(path):
    status = path.pdoq_shared_mem.empd_interrupts
    mask = path.pdoq_shared_mem.empd_interrupts_mask
    bits = {}
    for i in range(16):
        bits[i] = bit('empd_interrupt{}'.format(i), [node_pdoq_empd(path.pdoq.empd[i])])
    return interrupt_node(status, mask, bits)


def node_pdoq_empd(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('general_interrupt_summary', [node_pdoq_empd_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_pdoq_empd_general_interrupt(path):
    status = path.general_interrupt
    mask = path.general_interrupt_mask
    bits = {
        0: bit('emdb_duplicate_entry', type=TYPE_OTHER, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_pdvoq_shared_mma(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('general_interrupt_register_summary', [node_pdvoq_shared_mma_general_interrupt(path)]),
        2: bit('cgm_counter_overflow_int_summary', [node_pdvoq_shared_mma_cgm_counter_overflow(path)]),
    }
    return master_interrupt_node(status, bits)


def node_pdvoq_shared_mma_general_interrupt(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('delete_context_fifo_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        1: bit('pre_shr_fifo_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_pdvoq_shared_mma_cgm_counter_overflow(path):
    status = path.cgm_counter_overflow_int
    mask = path.cgm_counter_overflow_int_mask
    bits = {
        0: bit('cgm_counter_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
    }

    return interrupt_node(status, mask, bits)


def node_slice_pdvoq(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('general_interrupt_register_summary', [node_slice_pdvoq_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_slice_pdvoq_general_interrupt(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('rd_req_fifo_oveflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        1: bit('deq_req_fifo_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        2: bit('in_fifo_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        3: bit('dram_release_fifo_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        4: bit('ics_return_fifo_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        5: bit('cpu_return_fifo_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        6: bit('back_to_tail_fifo_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        7: bit('from_dram_cgm_fifo_overflow', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_rx_cgm(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('rx_cgm_interrupt_reg10_summary', [node_rx_cgm_interrupt(path, 0)]),
        2: bit('rx_cgm_interrupt_reg11_summary', [node_rx_cgm_interrupt(path, 1)]),
        3: bit('rx_cgm_interrupt_reg12_summary', [node_rx_cgm_interrupt(path, 2)]),
        4: bit('rx_cgm_interrupt_reg13_summary', [node_rx_cgm_interrupt(path, 3)]),
        5: bit('rx_cgm_interrupt_reg14_summary', [node_rx_cgm_interrupt(path, 4)]),
        6: bit('rx_cgm_interrupt_reg15_summary', [node_rx_cgm_interrupt(path, 5)]),
    }
    return master_interrupt_node(status, bits)


def node_rx_cgm_interrupt(path, i):
    status = path.rx_cgm_interrupt_reg1[i]
    mask = path.rx_cgm_interrupt_reg1_mask[i]
    bits = {
        0: bit('slice_local_u_ser_counter_wrap_around', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_rx_meter(path):
    status = path.top.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.top)]),
        1: bit('meter_blocks_interrupt_register_summary', [node_rx_meter_blocks(path)]),
    }
    return master_interrupt_node(status, bits)


def node_rx_meter_blocks(path):
    status = path.top.meter_blocks_interrupt_register
    mask = path.top.meter_blocks_interrupt_register_mask
    bits = {
        0: bit('exact_rx_meter_cluster0_interrupt', [node_mem_protect_only(path.block[0])]),
        1: bit('exact_rx_meter_cluster1_interrupt', [node_mem_protect_only(path.block[1])]),
        2: bit('exact_rx_meter_cluster2_interrupt', [node_mem_protect_only(path.block[2])]),
        3: bit('exact_rx_meter_cluster3_interrupt', [node_mem_protect_only(path.block[3])]),
        4: bit('start_rate_fix_fifo0_overflow', type=TYPE_OTHER),
        5: bit('start_rate_fix_fifo1_overflow', type=TYPE_OTHER),
        6: bit('start_rate_fix_fifo2_overflow', type=TYPE_OTHER),
        7: bit('start_rate_fix_fifo3_overflow', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_rx_pdr(path):
    status = path.rx_pdr.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.rx_pdr)]),
        1: bit('rxpdr_global_interrupt_reg_summary', [node_rx_pdr_global(path)]),
    }
    return master_interrupt_node(status, bits)


def node_rx_pdr_global(path):
    status = path.rx_pdr.rxpdr_global_interrupt_reg
    mask = path.rx_pdr.rxpdr_global_interrupt_reg_mask
    bits = {
        0: bit('shared_db0_inetrrupt_summary', [node_rx_pdr_mc_db(path.rx_pdr_mc_db[0])]),
        1: bit('shared_db1_inetrrupt_summary', [node_rx_pdr_mc_db(path.rx_pdr_mc_db[1])]),
        2: bit('slices01_inetrrupt_summary', [node_slice_pair_rx_pdr(path.slice_pair[0].rx_pdr)]),
        3: bit('slices23_inetrrupt_summary', [node_slice_pair_rx_pdr(path.slice_pair[1].rx_pdr)]),
        4: bit('slices45_inetrrupt_summary', [node_slice_pair_rx_pdr(path.slice_pair[2].rx_pdr)]),
    }
    return interrupt_node(status, mask, bits)


def node_rx_pdr_mc_db(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('shared_db_interrupt_reg_summary', [node_rx_pdr_mc_db_shared_db(path)]),
        2: bit('em_response_interrupt_summary', [node_rx_pdr_mc_db_em_response(path)]),
    }
    return master_interrupt_node(status, bits)


def node_rx_pdr_mc_db_shared_db(path):
    status = path.shared_db_interrupt_reg
    mask = path.shared_db_interrupt_reg_mask
    bits = {
        0: bit('lookup_a_error', type=TYPE_OTHER),
        1: bit('lookup_b_error', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_rx_pdr_mc_db_em_response(path):
    status = path.em_response_interrupt
    mask = path.em_response_interrupt_mask
    bits = {
        0: bit('shared_db_resp', type=TYPE_NO_ERR_NOTIFICATION),
    }
    return interrupt_node(status, mask, bits)


def node_slice_pair_rx_pdr(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('slice_interrupt_register0_summary', [node_slice_pair_rx_pdr_slice(path, 0)]),
        2: bit('slice_interrupt_register1_summary', [node_slice_pair_rx_pdr_slice(path, 1)]),
    }
    return master_interrupt_node(status, bits)


def node_slice_pair_rx_pdr_slice(path, i):
    status = path.slice_interrupt_register[i]
    mask = path.slice_interrupt_register_mask[i]
    bits = {
        0: bit('slice_tr_lc_sa_mc_pipe_emdb_entry_not_found', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_sch_top(path):
    status = path.sch_top.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.sch_top)]),
        1: bit('sch_ifg_interrupt_summary', [node_sch_top_sch_ifg(path)]),
    }
    return master_interrupt_node(status, bits)


def node_sch_top_sch_ifg(path):
    status = path.sch_top.sch_ifg_interrupt
    mask = path.sch_top.sch_ifg_interrupt_mask
    bits = {
        0: bit('ifg0_interrupt', [node_ifg_sch(path.slice[0].ifg[0].sch)]),
        1: bit('ifg1_interrupt', [node_ifg_sch(path.slice[0].ifg[1].sch)]),
        2: bit('ifg2_interrupt', [node_ifg_sch(path.slice[1].ifg[0].sch)]),
        3: bit('ifg3_interrupt', [node_ifg_sch(path.slice[1].ifg[1].sch)]),
        4: bit('ifg4_interrupt', [node_ifg_sch(path.slice[2].ifg[0].sch)]),
        5: bit('ifg5_interrupt', [node_ifg_sch(path.slice[2].ifg[1].sch)]),
        6: bit('ifg6_interrupt', [node_ifg_sch(path.slice[3].ifg[0].sch)]),
        7: bit('ifg7_interrupt', [node_ifg_sch(path.slice[3].ifg[1].sch)]),
        8: bit('ifg8_interrupt', [node_ifg_sch(path.slice[4].ifg[0].sch)]),
        9: bit('ifg9_interrupt', [node_ifg_sch(path.slice[4].ifg[1].sch)]),
        10: bit('ifg10_interrupt', [node_ifg_sch(path.slice[5].ifg[0].sch)]),
        11: bit('ifg11_interrupt', [node_ifg_sch(path.slice[5].ifg[1].sch)]),
    }
    return interrupt_node(status, mask, bits)


def node_ifg_sch(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('general_interrupt_register_summary', [node_ifg_sch_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_ifg_sch_general_interrupt(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('speculative_grant', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET, is_masked=True),
        1: bit('illegal_req_vsc', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_slice_pair_idb(path):
    status = path.macdb.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.macdb)]),
        1: bit('external_interrupts_summary', [node_slice_pair_idb_macdb_external(path)]),
        2: bit('idb_interrupts_summary', [node_slice_pair_idb_macdb_slice_service_relay_table(path.macdb)]),
        3: bit('em_response_interrupt_summary', [node_slice_pair_idb_macdb_em_response(path.macdb)]),
    }
    return master_interrupt_node(status, bits)


def node_slice_pair_idb_macdb_external(path):
    status = path.macdb.external_interrupts
    mask = path.macdb.external_interrupts_mask
    bits = {
        0: bit('resolution_interrupt_summary', [node_slice_pair_idb_res(path.res)]),
        1: bit('encdb_interrupt_summary', [node_slice_pair_idb_encdb(path.encdb)]),
    }
    return interrupt_node(status, mask, bits)


def node_slice_pair_idb_macdb_em_response(path):
    status = path.em_response_interrupt
    mask = path.em_response_interrupt_mask
    bits = {
        0: bit('mymac_table0_resp', type=TYPE_OTHER),
        1: bit('mymac_table1_resp', type=TYPE_OTHER),
        2: bit('service_mapping_access0_resp', type=TYPE_OTHER),
        3: bit('service_mapping_access1_resp', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_slice_pair_idb_macdb_slice_service_relay_table(path):
    status = path.idb_interrupts
    mask = path.idb_interrupts_mask
    bits = {
        0: bit('slice0_service_relay_table_address_out_of_bounds', type=TYPE_OTHER),
        1: bit('slice1_service_relay_table_address_out_of_bounds', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_slice_pair_idb_res(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('resolution_interrupts0_summary', [node_slice_pair_idb_res_resolution(path, 0)]),
        2: bit('resolution_interrupts1_summary', [node_slice_pair_idb_res_resolution(path, 1)]),
        3: bit('em_response_interrupt_summary', [node_slice_pair_idb_res_em_response(path)]),
    }
    return master_interrupt_node(status, bits)


def node_slice_pair_idb_res_resolution(path, i):
    status = path.resolution_interrupts[i]
    mask = path.resolution_interrupts_mask[i]
    bits = {
        0: bit('slice_lp_queuing_em_miss_interrupt', type=TYPE_OTHER),
        1: bit('slice_stage0_em_miss_interrupt', type=TYPE_OTHER),
        2: bit('slice_stage1_em_miss_interrupt', type=TYPE_OTHER),
        3: bit('slice_stage2_em_miss_interrupt', type=TYPE_OTHER),
        4: bit('slice_stage3_em_miss_interrupt', type=TYPE_OTHER),
        5: bit('slice_lp_queuing_prev_core_push_to_full_interrupt', type=TYPE_OTHER),
        6: bit('slice_stage0_prev_core_push_to_full_interrupt', type=TYPE_OTHER),
        7: bit('slice_stage1_prev_core_push_to_full_interrupt', type=TYPE_OTHER),
        8: bit('slice_stage2_prev_core_push_to_full_interrupt', type=TYPE_OTHER),
        9: bit('slice_stage3_prev_core_push_to_full_interrupt', type=TYPE_OTHER),
        10: bit('slice_resolution_ttl', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_slice_pair_idb_res_em_response(path):
    status = path.em_response_interrupt
    mask = path.em_response_interrupt_mask
    bits = {
        0: bit('resolution_stage0_em_resp', type=TYPE_OTHER),
        1: bit('lp_queuing_em_resp', type=TYPE_OTHER),
        2: bit('resolution_stage1_em_resp', type=TYPE_OTHER),
        3: bit('resolution_stage2_em_resp', type=TYPE_OTHER),
        4: bit('resolution_stage3_em_resp', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_slice_pair_idb_encdb(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('em_response_interrupt_summary', [node_slice_pair_idb_encdb_em_response(path)]),
    }
    return master_interrupt_node(status, bits)


def node_slice_pair_idb_encdb_em_response(path):
    status = path.em_response_interrupt
    mask = path.em_response_interrupt_mask
    bits = {
        0: bit('small_enc_table_resp', type=TYPE_OTHER),
        1: bit('l3_dlp0_table_resp', type=TYPE_OTHER),
        2: bit('large_enc_resp', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_ifg_core(path):
    status = path.ifgb.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.ifgb)]),
        1: bit('ifg_interrupt_summary_summary', [node_ifg_interrupt_summary(path)]),
        2: bit('ifgb_interrupt_reg_summary', [node_ifgb_interrupt(path.ifgb)]),
        3: bit('rx_oobe_crc_err_interrupt_reg_summary', [node_ifgb_rx_oobe_crc_err_interrupt(path.ifgb)]),
        4: bit('tx_tsf_ovf_interrupt_reg_summary', [node_ifgb_tx_tsf_ovf_interrupt_reg(path.ifgb)]),
        5: bit('tx_prot_interrupt_reg_summary', [node_ifgb_tx_prot_interrupt_reg(path.ifgb)]),
        6: bit('rx_prot_interrupt_reg_summary', [node_ifgb_rx_prot_interrupt_reg(path.ifgb)]),
    }
    return master_interrupt_node(status, bits)


def node_ifgb_interrupt(path):
    status = path.ifgb_interrupt_reg
    mask = path.ifgb_interrupt_reg_mask
    bits = {
        0: bit('rx_mlp_sync', type=TYPE_OTHER),
        1: bit('rx_mlp_sync_timeout', type=TYPE_OTHER),
        2: bit('dbg_buf_overflow', type=TYPE_LACK_OF_RESOURCES),
        3: bit('rx_rcontext_alloc_err', type=TYPE_LACK_OF_RESOURCES),
    }
    return interrupt_node(status, mask, bits)


def node_ifgb_rx_oobe_crc_err_interrupt(path):
    status = path.rx_oobe_crc_err_interrupt_reg
    mask = path.rx_oobe_crc_err_interrupt_reg_mask
    bits = {
        0: bit('oobe_port0_crc_err', type=TYPE_OTHER),
        1: bit('oobe_port1_crc_err', type=TYPE_OTHER),
        2: bit('oobe_port2_crc_err', type=TYPE_OTHER),
        3: bit('oobe_port3_crc_err', type=TYPE_OTHER),
        4: bit('oobe_port4_crc_err', type=TYPE_OTHER),
        5: bit('oobe_port5_crc_err', type=TYPE_OTHER),
        6: bit('oobe_port6_crc_err', type=TYPE_OTHER),
        7: bit('oobe_port7_crc_err', type=TYPE_OTHER),
        8: bit('oobe_port8_crc_err', type=TYPE_OTHER),
        9: bit('oobe_port9_crc_err', type=TYPE_OTHER),
        10: bit('oobe_port10_crc_err', type=TYPE_OTHER),
        11: bit('oobe_port11_crc_err', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_ifgb_rx_prot_interrupt_reg(path):
    status = path.rx_prot_interrupt_reg
    mask = path.rx_prot_interrupt_reg_mask
    bits = {
        0: bit('rx_missing_eop_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        1: bit('rx_missing_sop_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        2: bit('rx_fabric_type_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        3: bit('rx_invalid_pif_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        4: bit('rx_min_pkt_siz_err', type=TYPE_THRESHOLD_CROSSED),
        5: bit('rx_max_pkt_siz_err', type=TYPE_THRESHOLD_CROSSED),
        6: bit('rx_frag_siz_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        7: bit('rx_fd_inconsist_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        8: bit('rx_non_eop_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        9: bit('rx_missing_eof_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        10: bit('rx_beat_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        11: bit('rx_missing_nop_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        12: bit('rx_pkt_reas_inconsist_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        13: bit('rx_fatal_eof_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        14: bit('rx_filter0_hit', type=TYPE_OTHER),
        15: bit('rx_filter1_hit', type=TYPE_OTHER),
        16: bit('rx_filter2_hit', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_ifgb_tx_prot_interrupt_reg(path):
    status = path.tx_prot_interrupt_reg
    mask = path.tx_prot_interrupt_reg_mask
    bits = {
        0: bit('tx_missing_eop_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        1: bit('tx_missing_sop_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        2: bit('tx_fabric_type_err', type=TYPE_OTHER),
        3: bit('tx_invalid_pif_err', type=TYPE_OTHER),
        4: bit('tx_min_pkt_size_non_sop_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        5: bit('tx_min_pkt_size_sop_err', type=TYPE_OTHER, is_masked=True),
        6: bit('tx_non_sop_wsize_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        7: bit('tx_sop_wsize_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        8: bit('tx_start_packing_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        9: bit('tx_ts_cmd_err', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        10: bit('tx_filter0_hit', type=TYPE_OTHER),
        11: bit('tx_filter1_hit', type=TYPE_OTHER),
        12: bit('tx_filter2_hit', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_ifg_interrupt_summary(path):
    status = path.ifgb.ifg_interrupt_summary
    mask = path.ifgb.ifg_interrupt_summary_mask

    three_macpools = path.mac_pool8[2].is_valid()
    bits = {
        0: bit('mac_pool0', [node_mac_pool8(path.mac_pool8[0])]),
        1: bit('mac_pool1', [node_mac_pool8(path.mac_pool8[1])]),
        2: bit('mac_pool2', [node_mac_pool8(path.mac_pool8[2])] if three_macpools else []),
    }
    return interrupt_node(status, mask, bits)


def node_ifgb_tx_tsf_ovf_interrupt_reg(path):
    status = path.tx_tsf_ovf_interrupt_reg
    mask = path.tx_tsf_ovf_interrupt_reg_mask
    bits = {}
    for i in range(24):
        bits[i] = bit('Port{0}TxInTsfOvf'.format(i), type=TYPE_MAC_LINK_ERROR)
    return interrupt_node(status, mask, bits)


def node_mac_pool8(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('rx_link_status_down_summary', [node_mac_rx_link_status_down(path)]),
        2: bit('rx_pcs_link_status_down_summary', [node_mac_rx_pcs_link_status_down(path)]),
        3: bit('rx_pcs_align_status_down_summary', [node_mac_rx_pcs_align_status_down(path)]),
        4: bit('rx_pcs_hi_ber_up_summary', [node_mac_rx_pcs_hi_ber_up(path)]),
        5: bit('tx_crc_err_interrupt_register_summary', [node_mac_tx_crc_err(path)]),
        6: bit('tx_underrun_err_interrupt_register_summary', [node_mac_tx_underrun_err(path)]),
        7: bit('tx_missing_eop_err_interrupt_register_summary', [node_mac_tx_missing_eop_err(path)]),
        8: bit('rx_code_err_interrupt_register_summary', [node_mac_rx_code_err(path)]),
        9: bit('rx_crc_err_interrupt_register_summary', [node_mac_rx_crc_err(path)]),
        10: bit('rx_invert_crc_err_interrupt_register_summary', [node_mac_rx_invert_crc_err(path)]),
        11: bit('rx_oversize_err_interrupt_register_summary', [node_mac_rx_oversize_err(path)]),
        12: bit('rx_undersize_err_interrupt_register_summary', [node_mac_rx_undersize_err(path)]),
        13: bit('rx_desk_fif_ovf_interrupt_register0_summary', [node_mac_rx_desk_fif_ovf(path, 0)]),
        14: bit('rx_desk_fif_ovf_interrupt_register1_summary', [node_mac_rx_desk_fif_ovf(path, 1)]),
        15: bit('rx_desk_fif_ovf_interrupt_register2_summary', [node_mac_rx_desk_fif_ovf(path, 2)]),
        16: bit('rx_desk_fif_ovf_interrupt_register3_summary', [node_mac_rx_desk_fif_ovf(path, 3)]),
        17: bit('rx_desk_fif_ovf_interrupt_register4_summary', [node_mac_rx_desk_fif_ovf(path, 4)]),
        18: bit('rx_desk_fif_ovf_interrupt_register5_summary', [node_mac_rx_desk_fif_ovf(path, 5)]),
        19: bit('rx_desk_fif_ovf_interrupt_register6_summary', [node_mac_rx_desk_fif_ovf(path, 6)]),
        20: bit('rx_desk_fif_ovf_interrupt_register7_summary', [node_mac_rx_desk_fif_ovf(path, 7)]),
        21: bit('rx_pma_sig_ok_loss_interrupt_register_summary', [node_mac_rx_pma_sig_ok_loss(path)]),
        22: bit('rsf_rx_high_ser_interrupt_register_summary', [node_mac_rsf_rx_high_ser(path)]),
        23: bit('rsf_rx_degraded_ser_interrupt_register_summary', [node_mac_rsf_rx_degraded_ser(path)]),
        24: bit('rsf_rx_rm_degraded_ser_interrupt_register_summary', [node_mac_rsf_rx_rm_degraded_ser(path)]),
        25: bit('device_time_fif_ne_interrupt_register_summary', [node_mac_device_time_fif_ne(path)]),
        26: bit('device_time_override_interrupt_register_summary', [node_mac_device_time_override(path)]),
    }
    return master_interrupt_node(status, bits)


def node_ifg_serdes(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('apb_cmd_done_summary', [node_ifg_serdes_apb_cmd_done(path)]),
    }
    for i in range(status.get_desc().width_in_bits - 2):
        bits[i + 2] = bit('serdes_interrupts{}_summary'.format(i), [node_serdes_interrupts(path, i)])

    return master_interrupt_node(status, bits)


def node_ifg_serdes_apb_cmd_done(path):
    status = path.apb_cmd_done
    mask = path.apb_cmd_done_mask
    bits = {
        0: bit('apb_cmd_done_interrupt', type=TYPE_OTHER, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_serdes_interrupts(path, i):
    status = path.serdes_interrupts[i]
    mask = path.serdes_interrupts_mask[i]
    bits = {
        0: bit('general_interrupt', type=TYPE_OTHER, is_masked=True),
        1: bit('anlt_intr_n', type=TYPE_OTHER, is_masked=True),
        2: bit('an0_done', type=TYPE_OTHER, is_masked=True),
        3: bit('an1_done', type=TYPE_OTHER, is_masked=True),
        4: bit('lt0_done', type=TYPE_OTHER, is_masked=True),
        5: bit('lt1_done', type=TYPE_OTHER, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_mem_protect_interrupt(path):
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


# A few LBR blocks have a 1-bit master interrupt which points to a mem_protect interrupt.
# This repeating patern is defined here:
def node_mem_protect_only(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_mac_rx_link_status_down(path):
    return node_mac_lane_interrupt(path, 'rx_link_status_down', 'rx_link_status_down', TYPE_MAC_LINK_DOWN, is_masked=True)


def node_mac_rx_pcs_link_status_down(path):
    return node_mac_lane_interrupt(path, 'rx_pcs_link_status_down', 'rx_pcs_link_status_down', TYPE_MAC_LINK_DOWN, is_masked=True)


def node_mac_rx_pcs_align_status_down(path):
    return node_mac_lane_interrupt(path, 'rx_pcs_align_status_down', 'rx_pcs_align_status_down', TYPE_MAC_LINK_DOWN, is_masked=True)


def node_mac_rx_pcs_hi_ber_up(path):
    return node_mac_lane_interrupt(path, 'rx_pcs_hi_ber_up', 'rx_pcs_hi_ber_up', TYPE_MAC_LINK_DOWN, is_masked=True)


def node_mac_tx_crc_err(path):
    return node_mac_lane_interrupt(path, 'tx_crc_err_interrupt_register', 'tx_crc_err', TYPE_MAC_LINK_ERROR, is_masked=True)


def node_mac_tx_underrun_err(path):
    return node_mac_lane_interrupt(
        path,
        'tx_underrun_err_interrupt_register',
        'tx_underrun_err',
        TYPE_MAC_LINK_ERROR,
        is_masked=True)


def node_mac_tx_missing_eop_err(path):
    return node_mac_lane_interrupt(
        path,
        'tx_missing_eop_err_interrupt_register',
        'tx_missing_eop_err',
        TYPE_MAC_LINK_ERROR,
        is_masked=True)


def node_mac_rx_code_err(path):
    return node_mac_lane_interrupt(path, 'rx_code_err_interrupt_register', 'rx_code_err', TYPE_MAC_LINK_ERROR, is_masked=True)


def node_mac_rx_crc_err(path):
    return node_mac_lane_interrupt(path, 'rx_crc_err_interrupt_register', 'rx_crc_err', TYPE_MAC_LINK_ERROR, is_masked=True)


def node_mac_rx_invert_crc_err(path):
    return node_mac_lane_interrupt(
        path,
        'rx_invert_crc_err_interrupt_register',
        'rx_invert_crc_err',
        TYPE_MAC_LINK_ERROR,
        is_masked=True)


def node_mac_rx_oversize_err(path):
    return node_mac_lane_interrupt(
        path,
        'rx_oversize_err_interrupt_register',
        'rx_oversize_err',
        TYPE_MAC_LINK_ERROR,
        is_masked=True)


def node_mac_rx_undersize_err(path):
    return node_mac_lane_interrupt(
        path,
        'rx_undersize_err_interrupt_register',
        'rx_undersize_err',
        TYPE_MAC_LINK_ERROR,
        is_masked=True)


def node_mac_rx_desk_fif_ovf(path, lane_i):
    status = eval('path.rx_desk_fif_ovf_interrupt_register{0}'.format(lane_i))
    mask = eval('path.rx_desk_fif_ovf_interrupt_register{0}_mask'.format(lane_i))
    bits = {}
    for fifo_i in range(10):
        bits[fifo_i] = bit('rx_deskew_fif_ovf{0}_{1}'.format(lane_i, fifo_i), type=TYPE_MAC_LINK_DOWN, is_masked=True)
    return interrupt_node(status, mask, bits)


def node_mac_rx_pma_sig_ok_loss(path):
    return node_mac_lane_interrupt(
        path,
        'rx_pma_sig_ok_loss_interrupt_register',
        'rx_signal_ok_loss',
        TYPE_MAC_LINK_DOWN,
        is_masked=True)


def node_mac_rsf_rx_high_ser(path):
    return node_mac_lane_interrupt(path, 'rsf_rx_high_ser_interrupt_register', 'rx_high_ser', TYPE_MAC_LINK_DOWN, is_masked=True)


def node_mac_rsf_rx_degraded_ser(path):
    return node_mac_lane_interrupt(
        path,
        'rsf_rx_degraded_ser_interrupt_register',
        'rx_degraded_ser',
        TYPE_MAC_LINK_ERROR,
        is_masked=True)


def node_mac_rsf_rx_rm_degraded_ser(path):
    return node_mac_lane_interrupt(path, 'rsf_rx_rm_degraded_ser_interrupt_register',
                                   'rx_rm_degraded_ser', TYPE_MAC_LINK_ERROR, is_masked=True)


def node_mac_device_time_fif_ne(path):
    return node_mac_lane_interrupt(
        path,
        'device_time_fif_ne_interrupt_register',
        'device_time_fif_ne',
        TYPE_MAC_LINK_ERROR,
        is_masked=True)


def node_mac_device_time_override(path):
    return node_mac_lane_interrupt(
        path,
        'device_time_override_interrupt_register',
        'device_time_override',
        TYPE_MAC_LINK_ERROR,
        is_masked=True)


def node_mac_lane_interrupt(path, reg_name, bit_name_base, interrupt_type, interrupt_sw_action=SW_ACTION_NONE, is_masked=False):
    status = eval('path.' + reg_name)
    mask = eval('path.' + reg_name + '_mask')
    bits = {}
    lanes_n = 8
    for i in range(lanes_n):
        bits[i] = bit('{}{}'.format(bit_name_base, i), type=interrupt_type, sw_action=interrupt_sw_action, is_masked=is_masked)
    return interrupt_node(status, mask, bits)


def node_sms_main(path):
    status = path.sms_main.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.sms_main)]),
        1: bit('sms_cgm_error_reg_summary', [node_sms_cgm_error(path.sms_main)]),
        2: bit('sms_out_of_buffer_error_reg_summary', [node_sms_out_of_buffer_error(path.sms_main)]),
        3: bit('sms_req_fifo_ovf_reg_summary', [node_sms_req_fifo_ovf(path.sms_main)]),
        4: bit('sms_out_of_bank_write_interrupt_reg0_summary', [node_sms_out_of_bank_write(path.sms_main, 0)]),
        5: bit('sms_out_of_bank_write_interrupt_reg1_summary', [node_sms_out_of_bank_write(path.sms_main, 1)]),
        6: bit('sms_out_of_bank_write_interrupt_reg2_summary', [node_sms_out_of_bank_write(path.sms_main, 2)]),
        7: bit('sms_out_of_bank_write_interrupt_reg3_summary', [node_sms_out_of_bank_write(path.sms_main, 3)]),
        8: bit('sms_out_of_bank_write_interrupt_reg4_summary', [node_sms_out_of_bank_write(path.sms_main, 4)]),
        9: bit('sms_out_of_bank_write_interrupt_reg5_summary', [node_sms_out_of_bank_write(path.sms_main, 5)]),
        10: bit('sms_out_of_bank_write_interrupt_reg6_summary', [node_sms_out_of_bank_write(path.sms_main, 6)]),
        11: bit('sms_out_of_bank_write_interrupt_reg7_summary', [node_sms_out_of_bank_write(path.sms_main, 7)]),
        12: bit('sms_out_of_bank_write_interrupt_reg8_summary', [node_sms_out_of_bank_write(path.sms_main, 8)]),
        13: bit('sms_out_of_bank_write_interrupt_reg9_summary', [node_sms_out_of_bank_write(path.sms_main, 9)]),
        14: bit('sms_out_of_bank_write_interrupt_reg10_summary', [node_sms_out_of_bank_write(path.sms_main, 10)]),
        15: bit('sms_out_of_bank_write_interrupt_reg11_summary', [node_sms_out_of_bank_write(path.sms_main, 11)]),
        16: bit('sms_out_of_bank_write_interrupt_reg12_summary', [node_sms_out_of_bank_write(path.sms_main, 12)]),
        17: bit('sms_out_of_bank_write_interrupt_reg13_summary', [node_sms_out_of_bank_write(path.sms_main, 13)]),
        18: bit('sms_interrupt_reg_summary', [node_sms_interrupt_reg(path)]),
    }
    return master_interrupt_node(status, bits)


def node_sms_cgm_error(path):
    status = path.sms_cgm_error_reg
    mask = path.sms_cgm_error_reg_mask
    bits = {
        0: bit('sms_cgm_error', type=TYPE_THRESHOLD_CROSSED),
        1: bit('sms_cgm_dram_slice_error', type=TYPE_THRESHOLD_CROSSED),
    }
    return interrupt_node(status, mask, bits)


def node_sms_out_of_buffer_error(path):
    status = path.sms_out_of_buffer_error_reg
    mask = path.sms_out_of_buffer_error_reg_mask
    bits = {
        0: bit('sms_out_of_buffer_error', type=TYPE_LACK_OF_RESOURCES),
    }
    return interrupt_node(status, mask, bits)


def node_sms_req_fifo_ovf(path):
    status = path.sms_req_fifo_ovf_reg
    mask = path.sms_req_fifo_ovf_reg_mask
    bits = {
        0: bit('sms_req_fifo_ovf', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_sms_out_of_bank_write(path, i):
    status = path.sms_out_of_bank_write_interrupt_reg[i]
    mask = path.sms_out_of_bank_write_interrupt_reg_mask[i]
    bits = {
        0: bit('sms_out_of_bank_write_interrupt', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_sms_interrupt_reg(path):
    status = path.sms_main.sms_interrupt_reg
    mask = path.sms_main.sms_interrupt_reg_mask
    bits = {
        0: bit('sms_interrupt_quad_0', [node_sms_quad(path.sms_quad[0])]),
        1: bit('sms_interrupt_quad_1', [node_sms_quad(path.sms_quad[1])]),
        2: bit('sms_interrupt_quad_2', [node_sms_quad(path.sms_quad[2])]),
        3: bit('sms_interrupt_quad_3', [node_sms_quad(path.sms_quad[3])]),
    }
    return interrupt_node(status, mask, bits)


def node_sms_quad(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('sms2_cif_interrupt1b_ecc_error_reg0_summary', [node_sms_quad_cif_1b_ecc(path, 0)]),
        2: bit('sms2_cif_interrupt1b_ecc_error_reg1_summary', [node_sms_quad_cif_1b_ecc(path, 1)]),
        3: bit('sms2_cif_interrupt1b_ecc_error_reg2_summary', [node_sms_quad_cif_1b_ecc(path, 2)]),
        4: bit('sms2_cif_interrupt1b_ecc_error_reg3_summary', [node_sms_quad_cif_1b_ecc(path, 3)]),
        5: bit('sms2_cif_interrupt2b_ecc_error_reg0_summary', [node_sms_quad_cif_2b_ecc(path, 0)]),
        6: bit('sms2_cif_interrupt2b_ecc_error_reg1_summary', [node_sms_quad_cif_2b_ecc(path, 1)]),
        7: bit('sms2_cif_interrupt2b_ecc_error_reg2_summary', [node_sms_quad_cif_2b_ecc(path, 2)]),
        8: bit('sms2_cif_interrupt2b_ecc_error_reg3_summary', [node_sms_quad_cif_2b_ecc(path, 3)]),
        9: bit('sms2_cif_overflow_reg_summary', [node_sms_quad_cif_overflow(path)]),
    }
    return master_interrupt_node(status, bits)


def node_sms_quad_cif_1b_ecc(path, i):
    status = path.sms2_cif_interrupt1b_ecc_error_reg[i]
    mask = path.sms2_cif_interrupt1b_ecc_error_reg_mask[i]
    bits = {
        # TODO: Mask should go away when GB SMS_QUAD is properly initialized.
        0: bit('interrupt1b_ecc_error', type=TYPE_OTHER, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_sms_quad_cif_2b_ecc(path, i):
    status = path.sms2_cif_interrupt2b_ecc_error_reg[i]
    mask = path.sms2_cif_interrupt2b_ecc_error_reg_mask[i]
    bits = {
        # TODO: Mask should go away when GB SMS_QUAD is properly initialized.
        0: bit('interrupt2b_ecc_error', type=TYPE_OTHER, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_sms_quad_cif_overflow(path):
    status = path.sms2_cif_overflow_reg
    mask = path.sms2_cif_overflow_reg_mask
    bits = {
        0: bit('sms2_cif_reorder_fifo_ovf', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        1: bit('sms2_cif_fdoq_fifo_ovf', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_ts_mon(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('slice_interrupt_register0_summary', [node_ts_mon_slice(path, 0)]),
        2: bit('slice_interrupt_register1_summary', [node_ts_mon_slice(path, 1)]),
        3: bit('slice_interrupt_register2_summary', [node_ts_mon_slice(path, 2)]),
        4: bit('slice_interrupt_register3_summary', [node_ts_mon_slice(path, 3)]),
        5: bit('slice_interrupt_register4_summary', [node_ts_mon_slice(path, 4)]),
        6: bit('slice_interrupt_register5_summary', [node_ts_mon_slice(path, 5)]),
    }
    return master_interrupt_node(status, bits)


def node_ts_mon_slice(path, i):
    status = path.slice_interrupt_register[i]
    mask = path.slice_interrupt_register_mask[i]
    bits = {
        0: bit('link_down_interrupt', type=TYPE_LINK_DOWN),
        1: bit('ms_counter_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        2: bit('ms_counter_underflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_hbm_db(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('general_interrupt_register_summary', [node_hbm_db_general_interrupt(path)]),
        2: bit('channel_interrupts0_summary', [node_hbm_db_channel_interrupt(path, 0)]),
        3: bit('channel_interrupts1_summary', [node_hbm_db_channel_interrupt(path, 1)]),
        4: bit('channel_interrupts2_summary', [node_hbm_db_channel_interrupt(path, 2)]),
        5: bit('channel_interrupts3_summary', [node_hbm_db_channel_interrupt(path, 3)]),
        6: bit('channel_interrupts4_summary', [node_hbm_db_channel_interrupt(path, 4)]),
        7: bit('channel_interrupts5_summary', [node_hbm_db_channel_interrupt(path, 5)]),
        8: bit('channel_interrupts6_summary', [node_hbm_db_channel_interrupt(path, 6)]),
        9: bit('channel_interrupts7_summary', [node_hbm_db_channel_interrupt(path, 7)]),
    }
    return master_interrupt_node(status, bits)


def node_hbm_db_general_interrupt(path):
    status = path.general_interrupt_register
    mask = path.general_interrupt_register_mask
    bits = {
        0: bit('cattrip_interrupt', type=TYPE_THRESHOLD_CROSSED),
    }
    return interrupt_node(status, mask, bits)


def node_hbm_db_channel_interrupt(path, channel):
    status = path.channel_interrupts[channel]
    mask = path.channel_interrupts_mask[channel]
    bits = {
        0: bit('async_fifo_underflow', type=TYPE_OTHER),
        1: bit('async_fifo_overflow', type=TYPE_OTHER),
        2: bit('address_parity_error', type=TYPE_OTHER),
        3: bit('one_bit_ecc_error', type=TYPE_ECC_1B),
    }
    return interrupt_node(status, mask, bits)


def node_mmu(path):
    status = path.mmu.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.mmu)]),
        1: bit('general_interrupt_register_summary', [node_mmu_general_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_mmu_general_interrupt(path):
    status = path.mmu.general_interrupt_register
    mask = path.mmu.general_interrupt_register_mask
    bits = {
        0: bit('hbm_chnls01_interrupt', [node_mem_protect_only(path.hbm.chnl[0])]),
        1: bit('hbm_chnls23_interrupt', [node_mem_protect_only(path.hbm.chnl[1])]),
        2: bit('hbm_chnls45_interrupt', [node_mem_protect_only(path.hbm.chnl[2])]),
        3: bit('hbm_chnls67_interrupt', [node_mem_protect_only(path.hbm.chnl[3])]),
        4: bit('hbm_chnls89_interrupt', [node_mem_protect_only(path.hbm.chnl[4])]),
        5: bit('hbm_chnls1011_interrupt', [node_mem_protect_only(path.hbm.chnl[5])]),
        6: bit('hbm_chnls1213_interrupt', [node_mem_protect_only(path.hbm.chnl[6])]),
        7: bit('hbm_chnls1415_interrupt', [node_mem_protect_only(path.hbm.chnl[7])]),
        8: bit('mmu_has_error_buffer_interrupt', type=TYPE_OTHER),
        9: bit('lpm_has_error_buffer_interrupt', type=TYPE_OTHER),

        10: bit('sms_order_fifo_underflow', type=TYPE_OTHER),
        11: bit('sms_order_fifo_overflow', type=TYPE_OTHER),
        12: bit('sms_data_fifo_overflow', type=TYPE_OTHER),
        13: bit('sms_data_fifo_underflow', type=TYPE_OTHER),
        14: bit('sms_metadata_fifo_overflow', type=TYPE_OTHER),
        15: bit('sms_metadata_fifo_underflow', type=TYPE_OTHER),
        16: bit('data_pack_pd_fifo0_underflow', type=TYPE_OTHER),
        17: bit('data_pack_pd_fifo1_underflow', type=TYPE_OTHER),
        18: bit('data_pack_pd_fifo0_overflow', type=TYPE_OTHER),
        19: bit('data_pack_pd_fifo1_overflow', type=TYPE_OTHER),

        20: bit('lpm0_bypass_fifo_overflow', type=TYPE_OTHER),
        21: bit('lpm0_bypass_fifo_underflow', type=TYPE_OTHER),
        22: bit('lpm1_bypass_fifo_overflow', type=TYPE_OTHER),
        23: bit('lpm1_bypass_fifo_underflow', type=TYPE_OTHER),
        24: bit('lpm0_arb_fifo_overflow', type=TYPE_OTHER),
        25: bit('lpm0_arb_fifo_underflow', type=TYPE_OTHER),
        26: bit('lpm1_arb_fifo_overflow', type=TYPE_OTHER),
        27: bit('lpm1_arb_fifo_underflow', type=TYPE_OTHER),

        28: bit('mmu_buff_interrupt', [node_mem_protect_only(path.mmu_buff)]),
    }
    return interrupt_node(status, mask, bits)


def node_csms(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('csms_interrupt_reg_summary', [node_csms_csms_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_csms_csms_interrupt(path):
    status = path.csms_interrupt_reg
    mask = path.csms_interrupt_reg_mask
    bits = {
        0: bit('credit_gnt_dest_dev_unreachable', type=TYPE_OTHER),
        1: bit('msg_buffer_enq_pre_fifo_overflow0', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        2: bit('msg_buffer_enq_pre_fifo_overflow1', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        3: bit('msg_buffer_enq_pre_fifo_overflow2', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        4: bit('msg_buffer_enq_pre_fifo_overflow3', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        5: bit('msg_buffer_ddmq_overflow0', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        6: bit('msg_buffer_ddmq_overflow1', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        7: bit('msg_buffer_ddmq_overflow2', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        8: bit('msg_buffer_ddmq_overflow3', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        9: bit('msg_buffer_deq_cmd_fifo_overflow0', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        10: bit('msg_buffer_deq_cmd_fifo_overflow1', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        11: bit('msg_buffer_deq_cmd_fifo_overflow2', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        12: bit('msg_buffer_deq_cmd_fifo_overflow3', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        13: bit('msg_buffer_local_fifo_overflow0', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        14: bit('msg_buffer_local_fifo_overflow1', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        15: bit('msg_buffer_local_fifo_overflow2', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        16: bit('msg_buffer_local_fifo_overflow3', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        17: bit('msg_map_fifo_overflow4', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        18: bit('msg_map_fifo_overflow5', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        19: bit('unpack_fifo_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        20: bit('gnt_sw_target_fifo_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        21: bit('req_sw_target_fifo_overflow', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
    }
    return interrupt_node(status, mask, bits)


def node_dmc_pier(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('pier_core_interrupt_reg_summary', [node_dmc_pier_core(path)]),
    }
    return master_interrupt_node(status, bits)


def node_dmc_pier_core(path):
    status = path.pier_core_interrupt_reg
    mask = path.pier_core_interrupt_reg_mask
    bits = {
        0: bit('cscp_unreach_device', type=TYPE_LINK_DOWN),
        1: bit('inbe_multi_fifo_ovf', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        2: bit('oobe_invalid_host_type', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_dmc_frm(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('frm_interrupt_reg_summary', [node_dmc_frm_frm_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_dmc_frm_frm_interrupt(path):
    status = path.frm_interrupt_reg
    mask = path.frm_interrupt_reg_mask
    bits = {
        0: bit('link_status_down_int', type=TYPE_OTHER, is_masked=True),
        1: bit('frt_wr_fifo_overflow_int', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        2: bit('dcfm_feedback_fifo_full_int', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_dmc_fte(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('fte_interrupt_reg_summary', [node_dmc_fte_fte_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_dmc_fte_fte_interrupt(path):
    status = path.fte_interrupt_reg
    mask = path.fte_interrupt_reg_mask
    bits = {
        0: bit('lost_sync_interrupt', type=TYPE_THRESHOLD_CROSSED),
        1: bit('expected_device_time_diff_interrupt', type=TYPE_THRESHOLD_CROSSED),
    }
    return interrupt_node(status, mask, bits)


def node_npuh_fi(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('fi_engine_interrupts_summary', [node_npuh_fi_engine(path)]),
    }
    return master_interrupt_node(status, bits)


def node_npuh_fi_engine(path):
    status = path.fi_engine_interrupts
    mask = path.fi_engine_interrupts_mask
    bits = {
        0: bit('fi_ttl', type=TYPE_OTHER),
        1: bit('fi_total_offset', type=TYPE_OTHER),
        2: bit('fi_header_size', type=TYPE_OTHER),
        3: bit('fi_array_size', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_npuh_host(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('read_required_interrupt_summary', [node_npuh_host_read_required(path)]),
        2: bit('dropped_massage_summary', [node_npuh_host_dropped_maggage(path)]),
        3: bit('ene_interrupt_signals_summary', [node_npuh_host_en_interrupt_signals(path)]),
        4: bit('em_response_interrupt_summary', [node_npuh_host_em_response(path)]),
    }
    return master_interrupt_node(status, bits)


def node_npuh_host_read_required(path):
    status = path.read_required_interrupt
    mask = path.read_required_interrupt_mask
    bits = {
        0: bit('new_write_since_read', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_npuh_host_dropped_maggage(path):
    status = path.dropped_massage
    mask = path.dropped_massage_mask
    bits = {
        0: bit('interrupt', type=TYPE_LACK_OF_RESOURCES),
    }
    return interrupt_node(status, mask, bits)


def node_npuh_host_en_interrupt_signals(path):
    status = path.ene_interrupt_signals
    mask = path.ene_interrupt_signals_mask
    bits = {
        0: bit('ene_ttl_count_expired_int', type=TYPE_OTHER),
        1: bit('ene_macro_counter_wrap_around_int', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_npuh_host_em_response(path):
    status = path.em_response_interrupt
    mask = path.em_response_interrupt_mask
    bits = {
        0: bit('eth_mp_em_resp', type=TYPE_NO_ERR_NOTIFICATION),
    }
    return interrupt_node(status, mask, bits)


def node_npuh_npe(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('npe_interrupts_summary', [node_npuh_npe_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_npuh_npe_interrupt(path):
    status = path.npe_interrupts
    mask = path.npe_interrupts_mask
    bits = {
        0: bit('counters_overflow', type=TYPE_OTHER),
        1: bit('packet_timeout', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_dmc_mrb(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_npu_rxpp_term(path):
    status = path.top.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.top)]),
        1: bit('npes_interrupt_summary_reg_summary', [node_npu_rxpp_term_npes_interrupt(path)]),
        2: bit('flc_db_interrupt_summary_reg_summary', [node_npu_rxpp_term_flc_db_interrupt_summary(path)]),
        3: bit('em_response_interrupt_summary', [node_npu_rxpp_term_em_response(path.top)]),
    }
    return master_interrupt_node(status, bits)


def node_npu_rxpp_term_flc_db_interrupt_summary(path):
    status = path.top.flc_db_interrupt_summary_reg
    mask = path.top.flc_db_interrupt_summary_reg_mask
    bits = {
        0: bit('flc_db_interrupt_summary', [node_npu_rxpp_term_flc_db(path.flc_db)]),
    }
    return interrupt_node(status, mask, bits)


def node_npu_rxpp_term_flc_db(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('key_const_mis_config_interrupt_summary', [node_npu_rxpp_term_flc_db_key_const_misconfig(path)]),
        2: bit('nppd_err_indication_reg_summary', [node_npu_rxpp_term_flc_db_nppd_err_indication(path)]),
    }
    return master_interrupt_node(status, bits)


def node_npu_rxpp_term_flc_db_key_const_misconfig(path):
    status = path.key_const_mis_config_interrupt
    mask = path.key_const_mis_config_interrupt_mask
    bits = {
        0: bit('key_const_mis_config_int', type=TYPE_NO_ERR_NOTIFICATION),
    }
    return interrupt_node(status, mask, bits)


def node_npu_rxpp_term_flc_db_nppd_err_indication(path):
    status = path.nppd_err_indication_reg
    mask = path.nppd_err_indication_reg_mask
    bits = {
        0: bit('nppd_err_indication', type=TYPE_OTHER, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_npu_rxpp_term_npes_interrupt(path):
    status = path.top.npes_interrupt_summary_reg
    mask = path.top.npes_interrupt_summary_reg_mask
    bits = {
        0: bit('npe0_interrupt_summary', [node_npu_npe(path.npe[0])]),
        1: bit('npe1_interrupt_summary', [node_npu_npe(path.npe[1])]),
        2: bit('npe2_interrupt_summary', [node_npu_npe(path.npe[2])]),
    }
    return interrupt_node(status, mask, bits)


def node_npu_npe(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('npe_interrupts_summary', [node_npu_npe_interrupts(path)]),
    }
    return master_interrupt_node(status, bits)


def node_npu_npe_interrupts(path):
    status = path.npe_interrupts
    mask = path.npe_interrupts_mask
    bits = {
        0: bit('counters_overflow', type=TYPE_OTHER),
        1: bit('packet_timeout', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_npu_rxpp_term_fi_eng(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('fi_engine_interrupts_summary', [node_npu_rxpp_term_fi_eng_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_npu_rxpp_term_em_response(path):
    status = path.em_response_interrupt
    mask = path.em_response_interrupt_mask
    bits = {
        0: bit('tunnel_termination_table0_resp', type=TYPE_NO_ERR_NOTIFICATION),
        1: bit('tunnel_termination_table1_resp', type=TYPE_NO_ERR_NOTIFICATION),
    }
    return interrupt_node(status, mask, bits)


def node_npu_rxpp_term_fi_eng_interrupt(path):
    status = path.fi_engine_interrupts
    mask = path.fi_engine_interrupts_mask
    bits = {
        0: bit('fi_ttl', type=TYPE_OTHER),
        1: bit('fi_total_offset', type=TYPE_OTHER),
        2: bit('fi_header_size', type=TYPE_OTHER),
        3: bit('fi_array_size', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_npu_rxpp_term_sna(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('sna_interrupt_array_summary', [node_npu_rxpp_term_sna_interrupt_array(path)]),
    }
    return master_interrupt_node(status, bits)


def node_npu_rxpp_term_sna_interrupt_array(path):
    status = path.sna_interrupt_array
    mask = path.sna_interrupt_array_mask
    bits = {
        0: bit('program_selection_reg_tcam_miss', type=TYPE_MISCONFIGURATION),
    }
    return interrupt_node(status, mask, bits)


def node_npu_rxpp_fwd(path):
    status = path.top.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.top)]),
        1: bit('cache_interrupt_reg_summary', [node_npu_rxpp_fwd_cache_interrupt_reg(path)]),
        2: bit('npes_interrupt_summary_reg_summary', [node_npu_rxpp_fwd_npes_interrupt(path)]),
        3: bit('flow_cache_queues_interrupt_reg_summary', [node_npu_rxpp_fwd_flow_cache_queues_interrupt(path)]),
        4: bit('ifg0_flow_cache_queues_and_sna_interrupt_reg_summary',
               [node_npu_rxpp_fwd_ifg_flow_cache_queues_and_sna(path.top, 0)]),
        5: bit('ifg1_flow_cache_queues_and_sna_interrupt_reg_summary',
               [node_npu_rxpp_fwd_ifg_flow_cache_queues_and_sna(path.top, 1)]),
    }
    return master_interrupt_node(status, bits)


def node_npu_rxpp_fwd_cache_interrupt_reg(path):
    status = path.top.cache_interrupt_reg
    mask = path.top.cache_interrupt_reg_mask
    bits = {
        0: bit('cache_interrupt', [node_npu_rxpp_fwd_cdb_cache(path.cdb_cache)]),
    }
    return interrupt_node(status, mask, bits)


def node_npu_rxpp_fwd_cdb_cache(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('splitter_cache_interrupt_reg_summary', [node_npu_rxpp_fwd_cdb_cache_splitter_interrupt(path)]),
        2: bit('lpm_cache_interrupt_reg_summary', [node_npu_rxpp_fwd_cdb_cache_lpm_cache_interrupt(path)]),
    }
    return master_interrupt_node(status, bits)


def node_npu_rxpp_fwd_cdb_cache_splitter_interrupt(path):
    status = path.splitter_cache_interrupt_reg
    mask = path.splitter_cache_interrupt_reg_mask
    bits = {
        0: bit('splitter_cache_write_fail', type=TYPE_OTHER),
        1: bit('splitter_cache_write_cam', type=TYPE_OTHER),
        2: bit('splitter_cache_msb_em_duplicate_entry', type=TYPE_OTHER, is_masked=True),
        3: bit('splitter_cache_lsb_em_duplicate_entry', type=TYPE_OTHER, is_masked=True),
        4: bit('splitter_cache_msb_em_write_bin_mismatch', type=TYPE_OTHER, is_masked=True),
        5: bit('splitter_cache_lsb_em_write_bin_mismatch', type=TYPE_OTHER, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_npu_rxpp_fwd_cdb_cache_lpm_cache_interrupt(path):
    status = path.lpm_cache_interrupt_reg
    mask = path.lpm_cache_interrupt_reg_mask
    bits = {
        0: bit('lpm_cache_write_fail', type=TYPE_OTHER),
        1: bit('lpm_cache_write_cam', type=TYPE_OTHER),
        2: bit('lpm_cache_msb_em_duplicate_entry', type=TYPE_OTHER, is_masked=True),
        3: bit('lpm_cache_lsb_em_duplicate_entry', type=TYPE_OTHER, is_masked=True),
        4: bit('lpm_cache_msb_em_write_bin_mismatch', type=TYPE_OTHER, is_masked=True),
        5: bit('lpm_cache_lsb_em_write_bin_mismatch', type=TYPE_OTHER, is_masked=True),
    }
    return interrupt_node(status, mask, bits)


def node_npu_rxpp_fwd_npes_interrupt(path):
    status = path.top.npes_interrupt_summary_reg
    mask = path.top.npes_interrupt_summary_reg_mask
    bits = {
        0: bit('npe0_interrupt_summary', [node_npu_npe(path.npe[0])]),
        1: bit('npe1_interrupt_summary', [node_npu_npe(path.npe[1])]),
        2: bit('npe2_interrupt_summary', [node_npu_npe(path.npe[2])]),
    }
    return interrupt_node(status, mask, bits)


def node_npu_rxpp_fwd_flow_cache_queues_interrupt(path):
    status = path.top.flow_cache_queues_interrupt_reg
    mask = path.top.flow_cache_queues_interrupt_reg_mask
    bits = {
        0: bit('flow_cache_queues_interrupt', [node_npu_rxpp_fwd_flc_queues(path.flc_queues)]),
    }
    return interrupt_node(status, mask, bits)


def node_npu_rxpp_fwd_flc_queues(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
        1: bit('validity_check_failre_interrupt_reg_summary', [node_npu_rxpp_fwd_flc_queues_validity_check_interrupt(path)]),
        2: bit('payload_err_indication_reg_summary', [node_npu_rxpp_fwd_flc_queues_payload_err(path)]),
    }
    return master_interrupt_node(status, bits)


def node_npu_rxpp_fwd_flc_queues_validity_check_interrupt(path):
    status = path.validity_check_failre_interrupt_reg
    mask = path.validity_check_failre_interrupt_reg_mask
    bits = {
        0: bit('validity_check_failuer_interrupt', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_npu_rxpp_fwd_flc_queues_payload_err(path):
    status = path.payload_err_indication_reg
    mask = path.payload_err_indication_reg_mask
    bits = {
        0: bit('payload_err_indication', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_npu_rxpp_fwd_ifg_flow_cache_queues_and_sna(path, i):
    status = path.ifg_flow_cache_queues_and_sna_interrupt_reg[i]
    mask = path.ifg_flow_cache_queues_and_sna_interrupt_reg_mask[i]
    bits = {
        0: bit('ifg_flow_cache_queues_pop_and_sna_not_ready_interrupt', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_npu_txpp(path):
    status = path.top.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path.top)]),
        1: bit('internal_interrupt_summary', [node_npu_txpp_internal(path)]),
        2: bit('em_response_interrupt_summary', [node_npu_txpp_em_response(path.top)]),
    }
    return master_interrupt_node(status, bits)


def node_npu_txpp_internal(path):
    status = path.top.internal_interrupt
    mask = path.top.internal_interrupt_mask
    bits = {
        0: bit('ene_cluster0_interrupt', [node_npu_txpp_ene_cluster(path.ene_cluster[0])]),
        1: bit('ene_cluster1_interrupt', [node_npu_txpp_ene_cluster(path.ene_cluster[1])]),
        2: bit('npe0_interrupt', [node_npu_npe(path.npe[0])]),
        3: bit('npe1_interrupt', [node_npu_npe(path.npe[1])]),
        4: bit('eve0_packet_drop_interrupt', type=TYPE_OTHER),
        5: bit('eve1_packet_drop_interrupt', type=TYPE_OTHER),
        6: bit('ifg0_deep_term_excessive_termintaion', type=TYPE_OTHER),
        7: bit('ifg1_deep_term_excessive_termintaion', type=TYPE_OTHER),
        8: bit('ifg0_wd2_bit_ecc_err_interrupt', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        9: bit('ifg1_wd2_bit_ecc_err_interrupt', type=TYPE_OTHER, sw_action=SW_ACTION_SOFT_RESET),
        10: bit('npe_macro_id_tcam_miss_interrupt', type=TYPE_OTHER),
        11: bit('lfi_nw0_tcam_miss_interrupt', type=TYPE_OTHER),
        12: bit('lfi_nw1_tcam_miss_interrupt', type=TYPE_OTHER),
        13: bit('lfi_nw2_tcam_miss_interrupt', type=TYPE_OTHER),
        14: bit('lfi_nw3_tcam_miss_interrupt', type=TYPE_OTHER),
        15: bit('mtu_check_fail_interrupt', type=TYPE_OTHER),
        16: bit('invert_crc_asserted_before_npe0_interrupt', type=TYPE_OTHER),
        17: bit('invert_crc_asserted_before_npe1_interrupt', type=TYPE_OTHER),
        18: bit('tx_counters_cache_full_interrupt', type=TYPE_OTHER),
        19: bit('ptp_record_ifg0_pif_fifo_overflow', type=TYPE_OTHER),
        20: bit('ptp_record_ifg1_pif_fifo_overflow', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)


def node_npu_txpp_ene_cluster(path):
    status = path.interrupt_register
    bits = {
        0: bit('mem_protect_interrupt_summary', [node_mem_protect_interrupt(path)]),
    }
    for i in range(12):
        bits[i + 1] = bit('ene_interrupt_signals{}_summary'.format(i), [node_npu_txpp_ene_cluster_signals(path, i)])
    return master_interrupt_node(status, bits)


def node_npu_txpp_ene_cluster_signals(path, i):
    status = path.ene_interrupt_signals[i]
    mask = path.ene_interrupt_signals_mask[i]
    bits = {
        0: bit('ene_ttl_count_expired_int', type=TYPE_OTHER),
        1: bit('ene_macro_counter_wrap_around_int', type=TYPE_MISCONFIGURATION),
    }
    return interrupt_node(status, mask, bits)


def node_npu_txpp_em_response(path):
    status = path.em_response_interrupt
    mask = path.em_response_interrupt_mask
    bits = {
        0: bit('logical_port_profile_mapping_resp', type=TYPE_OTHER),
    }
    return interrupt_node(status, mask, bits)
