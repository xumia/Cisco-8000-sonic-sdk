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
lld-device-name := pacific

lld-design-block-uid := $(DEVICES_DIR)/pacific/design/defines/pacific_auto_unit_id_defines.v
lld-verilog-default-path :=  
lld-base-address := '0x1000000'

lld-src-lbr-rev2-path := $(DEVICES_DIR)/pacific/lbr_rev2
lld-src-block-info-path := $(DEVICES_DIR)/pacific/block_info

lld-src-lbrs-rev2 := \
		counters/data/counters_bank_group_4k_db.lbr \
		filb/data/filb_slice5.lbr \
		ifg/ifgb/data/ifgb.lbr \
		ifg/mac_pool2/data/mac_pool2.lbr \
		ifg/serdes_pool/data/serdes_pool18.lbr \
		mmu/data/hbm_chnl_4x_wide_diff_mems.lbr \
		npu/cdb/data/cdb_core_reduced.lbr \
		npu/idb/data/idb_res.lbr \
		npu/idb/data/idb_top.lbr \
		npu/sdb/data/sdb_enc.lbr \
		npu/sdb/data/sdb_mac.lbr \
		pdvoq/data/pdvoq_per_slice5_registers.lbr \
		sch/data/sch_registers_fabric.lbr \
		voq_cgm/data/hmc_cgm_registers.lbr \
		counters/data/counters_bank_group_db.lbr \
		counters/data/counters_db.lbr \
		dics/data/dics_registers.lbr \
		dmc/csms/data/csms_db.lbr \
		dmc/frm/data/frm_db.lbr \
		dmc/fte/data/fte_db.lbr \
		dmc/mrb/data/mrb_db.lbr \
		dmc/pier/data/pier_db.lbr \
		dmc/sbif/data/sbif_db.lbr \
		dvoq/data/dvoq_registers.lbr \
		fdll/data/fdll_registers.lbr \
		fdll/data/fdll_shared_mem_registers.lbr \
		filb/data/filb_slice.lbr \
		fllb/data/fllb_db.lbr \
		fllb/data/fllb_fabric_slice_db.lbr \
		fllb/data/rx_counters_db.lbr \
		hbm/data/hbm_db.lbr \
		ics/data/ics_slice_registers.lbr \
		ics/data/ics_top.lbr \
		ifg/mac_pool8/data/mac_pool8.lbr \
		mmu/data/hbm_chnl_4x_tall.lbr \
		mmu/data/mmu_buff_db.lbr \
		mmu/data/mmu_db.lbr \
		npu/cdb/data/cdb_cache.lbr \
		npu/cdb/data/cdb_core.lbr \
		npu/cdb/data/cdb_top.lbr \
		npu/format_identifier/lbr/fi.lbr \
		npu/npe/data/npe.lbr \
		npu/npu_host/data/npu_host.lbr \
		npu/rxpp/rxpp_fwd/data/rxpp_fwd.lbr \
		npu/rxpp/rxpp_term/data/fi_stage.lbr \
		npu/rxpp/rxpp_term/data/rxpp_term.lbr \
		npu/rxpp/rxpp_term/data/slice_sna.lbr \
		npu/txpp/data/ene_cluster_mem.lbr \
		npu/txpp/data/txpp_mem.lbr \
		pdoq/data/pdoq_empd_registers.lbr \
		pdoq/data/pdoq_fdoq_registers.lbr \
		pdoq/data/pdoq_registers.lbr \
		pdoq/data/pdoq_shared_mem_registers.lbr \
		pdvoq/data/pdvoq_empd.lbr \
		pdvoq/data/pdvoq_per_slice_registers.lbr \
		pdvoq/data/pdvoq_shared_mma.lbr \
		reassembly/data/reassembly_db.lbr \
		reorder/data/nw_reorder_block_db.lbr \
		reorder/data/nw_reorder_db.lbr \
		reorder/data/pp_reorder_slice_db.lbr \
		rx_cgm/data/rxcgm_db.lbr \
		rx_meter/data/rx_meter_block_db.lbr \
		rx_meter/data/rx_meter_db.lbr \
		rx_pdr/data/rx_pdr_2_slices_db.lbr \
		rx_pdr/data/rx_pdr_db.lbr \
		rx_pdr/data/rx_pdr_shared_db.lbr \
		sch/data/sch_registers.lbr \
		sch/data/sch_top_registers.lbr \
		sms/data/sms_main_db.lbr \
		sms/data/sms_quad_db.lbr \
		ts_mon/data/ts_mon_registers.lbr \
		tsms/data/tsms_registers.lbr \
		txcgm/data/txcgm_registers.lbr \
		txcgm/data/txcgm_top_registers.lbr \
		txpdr/data/txpdr_registers.lbr

lld-src-lbr-rev1-path := $(DEVICES_DIR)/pacific/lbr

lld-src-lbrs-rev1 := \
    ifgb_data/ifgb.lbr \
    npu_cdb_data/cdb_top.lbr
