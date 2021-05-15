// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
//
// This file and all technical concepts, proprietary knowledge, algorithms and
// intellectual property rights it contains (collectively the "Confidential Information"),
// are the sole propriety information of Cisco and shall remain at Cisco's ownership.
// You shall not disclose the Confidential Information to any third party and you
// shall use it solely in connection with operating and/or maintaining of Cisco's
// products and pursuant to the terms and conditions of the license agreement you
// entered into with Cisco.
//
// THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
// IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// END_LEGAL

#ifndef __PACIFIC_MAC_POOL_PORT_H__
#define __PACIFIC_MAC_POOL_PORT_H__

#include "api/system/la_mac_port.h"
#include "api/types/la_common_types.h"
#include "common/la_status.h"
#include "mac_pool_port.h"
#include <stddef.h>

namespace silicon_one
{

// The registers below are identical in MAC_POOL2 and MAC_POOL8, so it's similar code.
// We have static_assert in initialize to ensure this is still the case.
union mac_pool2_counter_timer_register;
using mac_pool_counter_timer_register = mac_pool2_counter_timer_register;

union mac_pool2_counter_timer_trigger_reg_register;
using mac_pool_counter_timer_trigger_reg_register = mac_pool2_counter_timer_trigger_reg_register;

union mac_pool2_rx_cfg0_register;
using mac_pool_rx_cfg0_register = mac_pool2_rx_cfg0_register;

union mac_pool2_tx_cfg0_register;
using mac_pool_tx_cfg0_register = mac_pool2_tx_cfg0_register;

union mac_pool2_am_cfg_register;
using mac_pool_am_cfg_register = mac_pool2_am_cfg_register;

union mac_pool2_rx_mac_cfg0_register;
using mac_pool_rx_mac_cfg0_register = mac_pool2_rx_mac_cfg0_register;

union mac_pool2_tx_mac_cfg0_register;
using mac_pool_tx_mac_cfg0_register = mac_pool2_tx_mac_cfg0_register;

union mac_pool2_rx_rsf_cfg0_register;
using mac_pool_rx_rsf_cfg0_register = mac_pool2_rx_rsf_cfg0_register;

union mac_pool2_rx_high_ser_fsm_cfg_register;
using mac_pool_rx_high_ser_fsm_cfg_register = mac_pool2_rx_high_ser_fsm_cfg_register;

union mac_pool2_port_mib_counter_register;
using mac_pool_port_mib_counter_register = mac_pool2_port_mib_counter_register;

union mac_pool2_rx_pcs_test_counter_register;
using mac_pool_rx_pcs_test_counter_register = mac_pool2_rx_pcs_test_counter_register;

union mac_pool2_rx_pma_rd_cnt_reg_register;
using mac_pool_rx_pma_rd_cnt_reg_register = mac_pool2_rx_pma_rd_cnt_reg_register;

union mac_pool2_rx_pma_test_counter_register;
using mac_pool_rx_pma_test_counter_register = mac_pool2_rx_pma_test_counter_register;

union mac_pool2_rx_errored_blocks_cnt_reg_register;
using mac_pool_rx_errored_blocks_cnt_reg_register = mac_pool2_rx_errored_blocks_cnt_reg_register;

union mac_pool2_rx_ber_cnt_reg_register;
using mac_pool_rx_ber_cnt_reg_register = mac_pool2_rx_ber_cnt_reg_register;

union mac_pool2_rx_status_register_register;
using mac_pool_rx_status_register_register = mac_pool2_rx_status_register_register;

union mac_pool2_rx_status_lane_mapping_register;
using mac_pool_rx_status_lane_mapping_register = mac_pool2_rx_status_lane_mapping_register;

union mac_pool2_rx_krf_status_register;
using mac_pool_rx_krf_status_register = mac_pool2_rx_krf_status_register;

union mac_pool2_rx_krf_cor_blocks_cnt_reg_register;
using mac_pool_rx_krf_cor_blocks_cnt_reg_register = mac_pool2_rx_krf_cor_blocks_cnt_reg_register;

union mac_pool2_rx_krf_uncor_blocks_cnt_reg_register;
using mac_pool_rx_krf_uncor_blocks_cnt_reg_register = mac_pool2_rx_krf_uncor_blocks_cnt_reg_register;

union mac_pool2_rx_cor_cw_reg_register;
using mac_pool_rx_cor_cw_reg_register = mac_pool2_rx_cor_cw_reg_register;

union mac_pool2_rx_uncor_cw_reg_register;
using mac_pool_rx_uncor_cw_reg_register = mac_pool2_rx_uncor_cw_reg_register;

union mac_pool2_rx_rsf_dbg_cntrs_reg_register;
using mac_pool_rx_rsf_dbg_cntrs_reg_register = mac_pool2_rx_rsf_dbg_cntrs_reg_register;

union mac_pool2_rx_ber_fsm_cfg_register;
using mac_pool_rx_ber_fsm_cfg_register = mac_pool2_rx_ber_fsm_cfg_register;

union mac_pool2_rsf_degraded_ser_cfg0_register;
using mac_pool_rsf_degraded_ser_cfg0_register = mac_pool2_rsf_degraded_ser_cfg0_register;

union mac_pool2_rx_high_ser_fsm_cfg_register;
using mac_pool_rx_high_ser_fsm_cfg_register = mac_pool2_rx_high_ser_fsm_cfg_register;

union mac_pool2_rx_symb_err_lane0_reg_register;
using mac_pool_rx_symb_err_lane_reg_register = mac_pool2_rx_symb_err_lane0_reg_register;

class pacific_mac_pool : public mac_pool_port
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    pacific_mac_pool(const la_device_impl_wptr& device);
    ~pacific_mac_pool();

    la_status initialize(la_slice_id_t slice_id,
                         la_ifg_id_t ifg_id,
                         la_uint_t serdes_base,
                         size_t num_of_serdes,
                         la_mac_port::port_speed_e speed,
                         la_mac_port::fc_mode_e rx_fc_mode,
                         la_mac_port::fc_mode_e tx_fc_mode,
                         la_mac_port::fec_mode_e fec_mode,
                         la_mac_port::mlp_mode_e mlp_mode,
                         la_slice_mode_e port_slice_mode) override;

    la_status read_mib_counters(bool clear, la_mac_port::mib_counters& out_mib_counters) const override;
    la_status set_fc_mode(la_mac_port::fc_direction_e fc_dir, la_mac_port::fc_mode_e fc_mode) override;
    la_status get_ipg(la_uint16_t& out_gap_len, la_uint16_t& out_gap_tx_bytes) const override;
    la_status set_ipg(la_uint16_t gap_len, la_uint16_t gap_tx_bytes) override;
    la_status get_crc_enabled(bool& out_enabled) const override;
    la_status set_crc_enabled(bool enabled) override;

    la_status reset_rs_fec_config() override;
    la_status reset_mac_config() override;
    la_status reset_general_config() override;
    la_status destroy_general_config() override;
    la_status update_general_config() override;

    la_status get_packet_sizes(la_uint_t& out_min_size, la_uint_t& out_max_size) const override;
    la_status set_packet_sizes(la_uint_t min_size, la_uint_t max_size) override;

    la_status update_rs_fec_config() override;

    la_status reset_ipg() override;
    la_status reset_xon_xoff_timers() override;

    la_status set_xoff_timer_settings(la_uint8_t tc_bitmap, la_uint_t quanta) override;
    la_status set_xon_timer_settings(la_uint8_t tc_bitmap, la_uint_t quanta) override;

    la_status set_control_tx_mac_src(la_mac_addr_t mac_addr) override;
    la_status get_control_tx_mac_src(la_mac_addr_t& out_mac_addr) const override;

    la_status configure_pcs_test_mode() override;
    la_status configure_pma_test_mode() override;

    la_status toggle_pdif_reset() override;

    la_status read_mac_status(la_mac_port::mac_status& out_mac_status) const override;
    la_status read_mac_link_down_interrupt(link_down_interrupt_info& val_out) const override;
    la_status clear_mac_link_down_interrupt() const override;
    la_status set_mac_link_down_interrupt_mask(bool enable_interrupt) const override;
    la_status clear_rx_deskew_fifo_overflow_interrupt() const override;
    la_status set_mac_link_error_interrupt_mask(bool enable_interrupt) const override;
    la_status set_delayed_mac_link_error_interrupt_mask(bool enable_interrupt) const override;
    void populate_link_error_info(const interrupt_tree::cause_bits& link_error_bits,
                                  link_error_interrupt_info& val_out) const override;
    la_status read_mac_pcs_lane_mapping(la_mac_port::mac_pcs_lane_mapping& out_mac_pcs_lane_mapping) const override;
    la_status read_rs_fec_symbol_errors_counters(la_mac_port::rs_fec_sym_err_counters& out_sym_err_counters) const override;
    la_status read_rs_fec_symbol_errors_counters(bool clear,
                                                 la_mac_port::rs_fec_sym_err_counters& out_sym_err_counters) const override;
    la_status read_rs_fec_debug_counters(la_mac_port::rs_fec_debug_counters& out_debug_counters) const override;
    la_status read_rs_fec_debug_counters(bool clear, la_mac_port::rs_fec_debug_counters& out_debug_counters) const override;
    la_status read_counter(la_mac_port::counter_e counter_type, size_t& out_counter) const override;
    la_status read_counter(bool clear, la_mac_port::counter_e counter_type, size_t& out_counter) const override;
    la_status read_counter(la_mac_port::serdes_counter_e counter_type, la_uint_t serdes_idx, size_t& out_counter) const override;
    la_status clear_counters() const override;
    la_status read_pma_test_ber(la_mac_port::mac_pma_ber& out_mac_pma_ber) const override;
    la_status configure_ber_fsm() override;
    la_status configure_degraded_ser() override;
    bool is_loopback_mode_supported(la_mac_port::loopback_mode_e mode) override;

    la_status calculate_pma_max_burst(uint32_t& pma_max_burst) override;

    // Setup counter timer
    la_status setup_counter_timer(bool enable, size_t clock_cycles) const override;

    // Wait for counter timer to elapse
    la_status wait_counter_timer() const override;

protected:
    pacific_mac_pool() = default; // Needed for cereal
    virtual void initialize_register_pointers() = 0;

private:
    la_status get_mac_config(mac_pool_rx_mac_cfg0_register* rx_mac_cfg0_register,
                             mac_pool_tx_mac_cfg0_register* tx_mac_cfg0_register) const;
    la_status set_mac_config(mac_pool_rx_mac_cfg0_register* rx_mac_cfg0_register,
                             mac_pool_tx_mac_cfg0_register* tx_mac_cfg0_register);
    la_status recalc_general_config(mac_pool_tx_cfg0_register* tx_cfg_register,
                                    mac_pool_rx_cfg0_register* rx_cfg_register,
                                    mac_pool_am_cfg_register* am_cfg_register);
    la_status get_general_config(mac_pool_tx_cfg0_register* tx_cfg_register,
                                 mac_pool_rx_cfg0_register* rx_cfg_register,
                                 mac_pool_am_cfg_register* am_cfg_register) const;
    la_status set_general_config(mac_pool_tx_cfg0_register* tx_cfg_register,
                                 mac_pool_rx_cfg0_register* rx_cfg_register,
                                 mac_pool_am_cfg_register* am_cfg_register);
    la_status recalc_rs_fec_config(mac_pool_rx_rsf_cfg0_register* rx_rsf_cfg0_register) const;
    la_status get_rs_fec_config(mac_pool_rx_rsf_cfg0_register* rx_rsf_cfg0_register) const;
    la_status set_rs_fec_config(mac_pool_rx_rsf_cfg0_register* rx_rsf_cfg0_register);
    la_status reset_rs_fec_config(mac_pool_rx_rsf_cfg0_register* rx_rsf_cfg0_register);
    la_status read_mac_status_simulated(la_mac_port::mac_status& out_mac_status) const;
    la_status read_mac_status_hw(la_mac_port::mac_status& out_mac_status) const;
    la_status read_mac_link_down_interrupt_simulated(link_down_interrupt_info& val_out) const;
    la_status read_mac_link_down_interrupt_hw(link_down_interrupt_info& val_out) const;

    // Get FEC counter register according to type
    la_status get_fec_counter_reg(la_mac_port::counter_e counter_type, lld_register_scptr& out_counter_reg) const;

protected:
    // MAC pool configuration registers
    struct _mac_pool_regs_t {
        lld_register_scptr counter_timer;
        lld_register_scptr counter_timer_trigger_reg;
        lld_register_scptr rsf_ck_cycles_per_1ms_reg;
        lld_register_array_sptr am_cfg;
        lld_register_array_sptr mac_lanes_loopback_register;
        lld_register_array_sptr pma_loopback_register;
        lld_register_array_sptr rsf_degraded_ser_cfg0;
        lld_register_array_sptr rx_ber_fsm_cfg;
        lld_register_array_sptr rx_cfg0;
        lld_register_array_sptr rx_high_ser_fsm_cfg;
        lld_register_array_sptr rx_krf_status;
        lld_register_array_sptr rx_krf_cfg;
        lld_register_array_sptr rx_mac_cfg0;
        lld_register_array_sptr rx_mac_cfg1;
        lld_register_array_sptr rx_pcs_test_cfg0;
        lld_register_array_sptr rx_pma_test_cfg0;
        lld_register_array_sptr rx_rsf_cfg0;
        lld_register_array_sptr rx_status_register;
        lld_register_array_sptr rx_status_lane_mapping;
        lld_register_array_sptr tx_cfg0;
        lld_register_array_sptr tx_mac_cfg0;
        lld_register_array_sptr tx_mac_ctrl_sa;
        lld_register_array_sptr tx_mac_cfg_ipg;
        lld_register_array_sptr tx_mac_fc_per_xoff_timer;
        lld_register_array_sptr tx_mac_fc_xoff_timer;
        lld_register_array_sptr tx_mac_fc_per_xon_timer;
        lld_register_array_sptr tx_mac_fc_xon_timer;
        lld_register_array_sptr tx_pcs_test_cfg0;
        lld_register_array_sptr tx_pma_test_cfg0;
    } m_mac_pool_regs;
    CEREAL_SUPPORT_PRIVATE_CLASS(_mac_pool_regs_t);

    // MAC pool counter registers
    struct _mac_pool_counters_t {
        lld_register_array_sptr rx_ber;
        lld_register_array_sptr rx_errored_blocks;
        lld_register_array_sptr port_mib;
        lld_register_array_sptr pcs_test;
        lld_register_array_sptr pma_read;
        lld_register_array_sptr pma_write;
        lld_register_array_sptr pma_test;
        lld_register_array_sptr krf_cor;
        lld_register_array_sptr krf_uncor;
        lld_register_array_sptr rsf_cor;
        lld_register_array_sptr rsf_uncor;
        std::array<lld_register_array_sptr, RS_FEC_LANE_PER_PORT> rx_symb_err_lane_regs;
        lld_register_scptr rsf_debug;
    } m_mac_pool_counters;
    CEREAL_SUPPORT_PRIVATE_CLASS(_mac_pool_counters_t);

    // MAC pool interrupt registers
    struct _mac_pool_interrupt_regs_t {
        // Down interrupt
        lld_register_scptr rx_link_status_down;
        lld_register_scptr rx_link_status_down_mask;
        lld_register_scptr rx_pcs_link_status_down;
        lld_register_scptr rx_pcs_link_status_down_mask;
        lld_register_scptr rx_pcs_align_status_down;
        lld_register_scptr rx_pcs_hi_ber_up;
        lld_register_scptr rx_pma_sig_ok_loss_interrupt_register;
        lld_register_scptr rsf_rx_high_ser_interrupt_register;
        std::array<lld_register_scptr, 8> rx_desk_fif_ovf_interrupt_register;

        // Error interrupt
        lld_register_scptr rx_code_err_interrupt_register;
        lld_register_scptr rx_crc_err_interrupt_register;
        lld_register_scptr rx_invert_crc_err_interrupt_register;
        lld_register_scptr rx_oob_invert_crc_err_interrupt_register;
        lld_register_scptr rx_oversize_err_interrupt_register;
        lld_register_scptr rx_undersize_err_interrupt_register;

        lld_register_scptr tx_crc_err_interrupt_register;
        lld_register_scptr tx_underrun_err_interrupt_register;
        lld_register_scptr tx_missing_eop_err_interrupt_register;

        lld_register_scptr rsf_rx_degraded_ser_interrupt_register;
        lld_register_scptr rsf_rx_rm_degraded_ser_interrupt_register;

        lld_register_scptr device_time_override_interrupt_register;

        // Error interrupt mask - TODO: remove, change to interrupt node
        lld_register_scptr rx_code_err_interrupt_register_mask;
        lld_register_scptr rx_crc_err_interrupt_register_mask;
        lld_register_scptr rx_invert_crc_err_interrupt_register_mask;
        lld_register_scptr rx_oob_invert_crc_err_interrupt_register_mask;
        lld_register_scptr rx_oversize_err_interrupt_register_mask;
        lld_register_scptr rx_undersize_err_interrupt_register_mask;

        lld_register_scptr tx_crc_err_interrupt_register_mask;
        lld_register_scptr tx_underrun_err_interrupt_register_mask;
        lld_register_scptr tx_missing_eop_err_interrupt_register_mask;

        lld_register_scptr rsf_rx_degraded_ser_interrupt_register_mask;
        lld_register_scptr rsf_rx_rm_degraded_ser_interrupt_register_mask;

        lld_register_scptr device_time_override_interrupt_register_mask;
    } m_mac_pool_interrupt_regs;
    CEREAL_SUPPORT_PRIVATE_CLASS(_mac_pool_interrupt_regs_t);
};
}

#endif // __PACIFIC_MAC_POOL_PORT_H__
