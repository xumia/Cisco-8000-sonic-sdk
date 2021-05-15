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

#ifndef __MAC_POOL2_PORT_H__
#define __MAC_POOL2_PORT_H__

#include "api/system/la_mac_port.h"
#include "api/types/la_common_types.h"
#include "common/la_status.h"
#include "lld/pacific_reg_structs.h"
#include "mac_pool_port.h"
#include "pacific_mac_pool.h"
#include <stddef.h>
namespace silicon_one
{

class mac_pool2_port : public pacific_mac_pool
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    mac_pool2_port(const la_device_impl_wptr& device);
    ~mac_pool2_port();

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

    la_status get_mib_counters(la_mac_port::mib_counters& out_mib_counters) const;

    la_status set_rs_fec_debug_enabled() override;
    la_status get_rs_fec_debug_enabled(bool& out_debug_status) const override;
    la_status read_mac_soft_reset_config() const override;

protected:
    mac_pool2_port() = default; // Needed for cereal
    void initialize_register_pointers() override;
    la_status configure_lanes() override;
    la_status configure_pma(device_port_handler_base::serdes_config_data config) override;
    la_status configure_pma_max_burst(uint32_t max_burst) override;
    la_status clear_signal_ok_interrupt() override;
    la_status get_signal_ok_interrupt(bool& out_trapped) override;
    la_status set_rx_reset(la_mac_port_base::mac_reset_state_e state) override;
    la_status set_tx_reset(la_mac_port_base::mac_reset_state_e state) override;
    la_status set_reset_fabric_port_pacific_a0(la_mac_port_base::mac_reset_state_e state) override;
    la_status set_rx_pcs_sync_reset() override;
    la_status set_rx_pcs_reset() override;
    la_status reset_tx_pma(bool enable) override;
    la_status reset_rx_pma(bool enable) override;
    la_status set_mac_rx_reset(la_mac_port_base::mac_reset_state_e state) override;
    size_t get_serdes_index_in_mac_pool(size_t serdes_idx) const override;
    la_status update_rx_krf_config() override;
    la_status reset_rx_krf_config() override;
    la_status configure_loopback_mode(npl_loopback_mode_e mii_loopback_mode, npl_loopback_mode_e pma_loopback_mode) override;
    la_status set_sig_ok_overide(bool overide, bool val) override;
};
}

#endif // __MAC_POOL2_PORT_H__
