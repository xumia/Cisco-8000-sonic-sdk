// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "apb/apb_fwd.h"
#include "common/task_scheduler.h"
#include "hld_types_fwd.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"
#include "lld/lld_fwd.h"

#include <chrono>
#include <vector>

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

    la_status soft_reset();

    la_status apply_post_init_config_workaround();

private:
    // Object ID
    la_object_id_t m_oid{LA_OBJECT_ID_INVALID};

    la_device_impl_wptr m_device;
    gibraltar_tree_scptr m_gb_tree;
    apb_wptr m_apb;
    ll_device_sptr m_ll_device;

    la_device_revision_e m_device_revision;
    bool m_does_hbm_exist;

    la_status read_device_model_id();

    la_rate_t m_rate_limit;

    // Rate measurement
    la_rate_t m_measured_rate;
    bool m_is_completed;
    on_done_function_t m_on_done_cb;

    task_scheduler m_task_scheduler;
    task_scheduler::task_handle m_task_handle;
    using task_completed_cb = std::function<void()>;

    la_status start_hw_rate_measurement(const std::chrono::seconds duration); ///< Using integrated clock timer
    la_status start_sw_rate_measurement(
        const std::chrono::seconds duration); ///< Not using integrated clock timer - for long durations

    // Rate measurement helper methods
    la_status register_rate_measurement_task_completed_cb(task_completed_cb cb, std::chrono::seconds delay);
    la_status setup_counter_timer(bool enable, size_t clock_cycles) const;
    la_status read_undropped_bytes_passed_to_dram(uint64_t& out_bytes) const;

    la_status configure_clocks_and_resets();
    la_status set_use_traffic_gen(bool use_traffic_gen);
    la_status bringup_hbm(uint32_t dfi_freq_mhz, bool power_stable);
    la_status bringup_hbm_part2();
    la_status configure_samsung_timing_params(uint32_t dfi_freq_mhz);
    la_status configure_rd_wr_arbitration(bool time_only);
    la_status configure_lpm();
    la_status configure_lpm(int bank_denied_threshold, int total_denied_threshold);
    la_status take_hbm_channels_out_of_reset();
    la_status set_phy_to_mission_mode(bool set_wrstn_to_0);
    la_status set_dll_rdqs(uint64_t value);
    la_status reset_phy_fifo();
    la_status print_values(uint32_t hbm_id);
    la_status do_hbm_training(bool skip_training);
    la_status do_hbm_training_manual(bool override_vals, std::vector<uint32_t>& dll_vals);
    la_status read_hbm_training_values(std::vector<uint32_t>& dll_vals);
    la_status reset_hbm_ecosystem(bool set_clock_division);
    la_status take_mmu_out_of_reset();
    la_status configure_buffer_alloc(bool use_lpm);
    la_status configure_buffer_alloc_post_reset(bool use_lpm);
    la_status give_control_to_apb();
    la_status give_control_to_ieee();
    la_status clear_hbm_error_counters();
    la_status clear_hbm_channel_interrupts();
    la_status clear_mmu_error_counters();
    la_status clear_mmu_interrupts();
    la_status program_hbm_plls();
    la_status reset_dram();
    la_status poll_training_completion(size_t hbm_i);
    la_status apb_write(uint32_t reg, uint32_t val);
    la_status check_dram_buffer_error(uint32_t dram_buffer, dram_corrupted_buffer& out_error);
    la_status check_dram_buffer_cell(const dram_buffer_cell& cell, bool& out_has_error);
    la_status set_dram_meter(la_rate_t rate, la_rate_t eviction_rate);
    la_status get_dfi_frequency(uint32_t& out_dfi_freq_mhz);

    // For serialization purposes only
    la_hbm_handler_impl() = default;
};

} // namespace silicon_one

#endif // __LA_HBM_HANDLER_IMPL_H__
