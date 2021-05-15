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

#ifndef __LA_HBM_HANDLER_IMPL_H__
#define __LA_HBM_HANDLER_IMPL_H__

#include "api/system/la_hbm_handler.h"
#include "api/types/la_notification_types.h"

#include "aapl/aapl.h"
#include "aapl/hbm.h"
#include "hld_types.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_hbm_handler_impl : public la_hbm_handler
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_hbm_handler_impl(la_device_impl_wptr device);
    ~la_hbm_handler_impl();

    la_uint_t m_device_model_id;

    la_status run_mbist(bool repair) override;
    la_status read_error_counters(size_t hbm_interface,
                                  size_t channel_id,
                                  la_hbm_handler::error_counters& out_err_counters) const override;
    la_status upload_firmware(const char* file_path) override;
    la_status get_firmware_version_id(la_uint_t& out_fw_id) override;
    la_status get_firmware_build_id(la_uint_t& out_build_id) override;

    la_status set_die_ieee1500_enabled(bool enabled) override;
    bool get_die_ieee1500_enabled() const override;
    la_status die_ieee1500_write(size_t hbm_interface,
                                 uint32_t reg_addr,
                                 uint32_t channel_addr,
                                 size_t width_bits,
                                 const bit_vector& in_bv) override;
    la_status die_ieee1500_read(size_t hbm_interface,
                                uint32_t reg_addr,
                                uint32_t channel_addr,
                                size_t width_bits,
                                bool reverse,
                                bit_vector& out_bv) override;

    la_status set_rate_limit(const la_rate_t rate_limit) override;
    void get_rate_limit(la_rate_t& out_rate_limit) const override;

    la_status start_rate_measurement(const std::chrono::seconds duration) override;
    bool is_rate_measurement_completed() const override;
    la_status read_rate(bool clear_on_read, la_rate_t& out_rate) override;
    void register_read_cb(on_done_function_t on_done_cb) override;

    la_status dram_buffer_write(const dram_buffer_cell& cell, const bit_vector& in_bv) override;
    la_status dram_buffer_read(const dram_buffer_cell& cell, bit_vector& out_bv) override;

    la_status check_dram_buffer_errors(std::vector<dram_corrupted_buffer>& out_errors);

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    la_status initialize(la_object_id_t oid);
    la_status destroy();
    la_status activate();

    la_status avago_mbist(size_t hbm);
    la_status samsung_mbist(size_t hbm, bool repair);
    la_status interface_mbist(size_t hbm);

    la_status soft_reset();

private:
    enum {
        NO_FAVOR_LPM = 0,       // Dont consider LPM fill level when moving to read
        FAVOR_LPM = 1,          // Use LPM fill level when moving to read
        FAVOR_LPM_MIN_WRITE = 2 // only move from write to read when there is LPM pending AND min of 256 cycles of write has passed
    };

    // Initialize Avago related parameters
    la_status initialize_avago(size_t hbm);

    /// @brief Program MMU/HBM parameters for Samsung.
    ///
    /// This task configures various HBM-standard related parameters of the Pacific
    ///     that should allow it to work with Samsung HBM Silicon.
    ///     -- The almost_full input is a parameter of the async FIFO between the core_clk and DFI clock, and depends on the
    ///     frequency ratio between them.
    ///     -- The PL is the parity latency, which must be programmed to the HBM PHY and to the HBM die.
    ///     -- The tRddataEn is a parameter that is expected to be constant, but will be set in the lab after finding an ideal value
    ///     for it.
    ///     -- The DfiClockPeriodNs input is required to convert various timing parameters given in the standard in terms of ns into
    ///     clock cycles, which is the unit that the Pacific uses.
    ///     -- The DbiEnable enables DBI (Data Byte Inversion) logic on the HBM interface. Depending on how devices with Mode1
    ///     repairs will be treated (see below), this will remain a parameter
    la_status initialize_mmu_hbm_samsung(int t_rd_data_en,
                                         int almost_full_level,
                                         float dfi_clock_period_ns,
                                         int dbi_enable,
                                         int relax_percent);

    /// @brief Configure MMU system-related parameters, like read-write arbitration, LPM priority, etc.
    la_status initialize_mmu_general();

    la_status configure_fw_parameters(size_t hbm, int hbm_freq_in_mhz);
    la_status configure_fw_mode_parameters(size_t hbm, float dfi_clock_period_ns, int dbi_enable, int relax_percent);

    la_status set_pll(size_t hbm, uint pll_id, bool do_reset, bool fbdiv_23, la_uint_t divider, la_uint_t pllout_divcnt);
    la_status set_hbm_pll(size_t hbm, la_uint_t divider);

    la_status get_pll_lock(size_t hbm, uint pll_id, bool& out_pll_lock);

    la_status read_device_model_id();

    la_status upload_firmware(size_t hbm, const char* file_path);
    la_status get_firmware_version_id(size_t hbm, la_uint_t& out_fw_id);
    la_status get_firmware_build_id(size_t hbm, la_uint_t& out_build_id);
    la_status verify_firmware_version_and_build(size_t hbm, la_uint_t fw_id, la_uint_t build_id);

    void avago_print_operation_result(const char* op_name, int rc, Avago_hbm_operation_results_t& op_result);

    la_status soft_reset_mmu_buff();

    la_status check_dram_buffer_error(uint32_t dram_buffer, dram_corrupted_buffer& out_error);
    la_status check_dram_buffer_cell(const dram_buffer_cell& cell, bool& out_has_error);
    la_status do_dram_buffer_read_write(bool is_read, const dram_buffer_cell& cell, bit_vector& bv);

    // Containing device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    la_device_revision_e m_device_revision;

    Aapl_t* m_aapl_handler[NUM_HBM_INTERFACES];

    la_uint_t m_hbm_rate;
    la_uint_t m_pll_div;
    int m_hbm_read_cycles;
    int m_hbm_write_cycles;
    int m_hbm_min_move_to_read;
    int m_hbm_lpm_favor_mode;
    bool m_hbm_move_to_read_on_empty;
    bool m_hbm_move_to_write_on_empty;
    int m_hbm_phy_t_rdlat_offset;

    la_rate_t m_rate_limit;

    // Rate measurement
    std::chrono::milliseconds m_duration;
    la_rate_t m_measured_rate;
    bool m_is_done;
    on_done_function_t m_on_done_cb;

    la_hbm_handler_impl() = default;
};

} // namespace silicon_one

#endif // __LA_HBM_HANDLER_IMPL_H__
