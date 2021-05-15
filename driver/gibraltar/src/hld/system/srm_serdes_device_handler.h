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

#ifndef __SRM_SERDES_DEVICE_HANDLER_H__
#define __SRM_SERDES_DEVICE_HANDLER_H__

#include "hld_types_fwd.h"
#include "serdes_device_handler.h"
#include "system/serdes_handler.h"

#include "srm/srm_rules.h"

#include <map>

namespace silicon_one
{

class srm_serdes_device_handler : public serdes_device_handler, public std::enable_shared_from_this<srm_serdes_device_handler>
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    srm_serdes_device_handler() = default;
    //////////////////////////////
public:
    explicit srm_serdes_device_handler(const la_device_impl_wptr& device);
    ~srm_serdes_device_handler(){};

    la_status init(bool reconnect) override;

    la_status destroy() override;

    la_status create_serdes_group_handler(la_slice_id_t slice_id,
                                          la_ifg_id_t ifg_id,
                                          la_uint_t serdes_base_id,
                                          size_t serdes_count,
                                          la_mac_port::port_speed_e speed,
                                          la_mac_port::port_speed_e serdes_speed,
                                          la_slice_mode_e serdes_slice_mode,
                                          serdes_handler*& out_serdes_handler) override;

    la_status get_ifg_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl) override;

    la_status get_native_sbus_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl) override;

    la_status mbist_activate(bool repair) override;

    la_status mbist_clear() override;

    la_status mbist_read(bool report_failures, size_t& total_tested, size_t& total_pass, size_t& total_failed) override;

    la_status get_serdes_addr(la_slice_id_t slice,
                              la_ifg_id_t ifg,
                              la_uint_t serdes_idx,
                              la_serdes_direction_e direction,
                              uint32_t& out_serdes_addr) override;

    const la_device_impl* get_device() const
    {
        return m_device.get();
    }

    la_status check_all_firmware(bool& out_ready);
    la_status check_firmware(uint32_t die, bool& out_fw_ok);
    la_status get_component_health(la_component_health_vec_t& out_component_health) const override;

private:
    la_device_impl_wptr m_device;

    la_status clobber_resets();

    la_status upload_firmware();
    la_status upload_firmware_from_file(uint32_t address, uint32_t fw_crcs[2], std::string filename);
    la_status upload_firmware_from_integrated(uint32_t address, uint32_t fw_crcs[2]);
    la_status verify_firmware_upload(uint32_t broadcast_die, const uint32_t fw_crcs[2]);
    la_status init_all_firmware();
    la_status verify_new_firmware(bool& new_fw);

    la_status populate_pwrup_rules(size_t chain_idx, srm_pwrup_rules_t& pwrup_rules);
    la_status powerup_activate();
    la_status powerup_check();
    la_status powerup_check_bias();
    la_status powerup_check_eru();

    la_status rcal_fail_check();

    la_status srm_serdes_rcal_average_calc(la_slice_id_t slice, int is_eru, uint32_t& rcal_average, uint32_t& rcal_pass_cnt);
    la_status rcal_override(la_slice_id_t slice, uint32_t rcal_average, uint32_t rcal_pass_cnt);

    la_status reference_clock_propagation();

    // Die direction code is bit encoding:
    // Horizontal - 1
    // Vertical - 4
    // Horizontal and Vertical - 5
    la_status set_reference_clock(la_slice_id_t slice, la_ifg_id_t ifg, uint32_t die, uint32_t direction);

    int m_fw_version_major;
    int m_fw_version_minor;
    int m_fw_version_build;
    bool m_handler_initilized;

    la_component_health_vec_t m_die_health;

    static const size_t RCAL_THREADS = 3;
    static const size_t RCAL_SLICES_PER_THREAD = 2;

    // Get 0-127 die number from the 32 bit address
    uint32_t get_die_no(uint32_t die_addr);

    enum {
        RCAL_WRAP_AROUND_RETRY = 3,
        RCAL_FAIL_NUM_ALLOW_PER_CHAIN = 5,
        RCAL_AVERAGE_VALUE_THRES = 5,
        RCAL_AVERAGE_RANGE = 15,
        RCAL_ALL_FAIL_THRES_LO = 42,
        RCAL_ALL_FAIL_THRES_HI = 84,
        RCAL_PARTLY_FAIL_THRES = 63,
        RCAL_OVERRIDE_LO = 0,
        RCAL_OVERRIDE_HI = 127,
    };
};
}

#endif // __SRM_SERDES_DEVICE_HANDLER_H__
