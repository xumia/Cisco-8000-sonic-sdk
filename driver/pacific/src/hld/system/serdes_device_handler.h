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

#ifndef __SERDES_DEVICE_HANDLER_H__
#define __SERDES_DEVICE_HANDLER_H__

#include "api/system/la_mac_port.h"
#include "api/types/la_common_types.h"
#include "common/la_status.h"

#include "system/serdes_handler.h"

/// @brief Environment variable name to be used for the SerDes firmware file.
static const std::string SERDES_FILE_ENVVAR = "SERDES_FIRMWARE";

namespace silicon_one
{

class serdes_device_handler
{
public:
    virtual ~serdes_device_handler(){};

    /// @brief Initialize - first time or reconnect.
    //         If not reconnect, also download Firmware to all device SerDes's and do base reset.
    virtual la_status init(bool reconnect) = 0;

    /// @brief Destroy SerDes device handler
    virtual la_status destroy() = 0;

    /// @brief Create SerDes group handler
    virtual la_status create_serdes_group_handler(la_slice_id_t slice_id,
                                                  la_ifg_id_t ifg_id,
                                                  la_uint_t serdes_base_id,
                                                  size_t serdes_count,
                                                  la_mac_port::port_speed_e speed,
                                                  la_mac_port::port_speed_e serdes_speed,
                                                  la_slice_mode_e serdes_slice_mode,
                                                  serdes_handler*& out_serdes_handler)
        = 0;

    /// @brief Get Slice IFG handler
    virtual la_status get_ifg_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl) = 0;

    /// @brief Get Slice IFG native handler
    virtual la_status get_native_sbus_aapl_handler(la_slice_id_t slice_id, la_ifg_id_t ifg_id, Aapl_t*& out_aapl) = 0;

    /// @brief Activate mbist on device SerDes's
    virtual la_status mbist_activate(bool repair) = 0;

    /// @brief Clear mbist on device SerDes's
    virtual la_status mbist_clear() = 0;

    /// @brief Read most recent activated mbist
    virtual la_status mbist_read(bool report_failures, size_t& total_tested, size_t& total_pass, size_t& total_failed) = 0;

    /// @brief Get internal SerDes address for the specified SerDes lane.
    virtual la_status get_serdes_addr(la_slice_id_t slice,
                                      la_ifg_id_t ifg,
                                      la_uint_t serdes_idx,
                                      la_serdes_direction_e direction,
                                      la_uint_t& out_serdes_addr)
        = 0;

    /// @brief Get internal SerDes address for the specified SerDes lane.
    virtual la_status get_component_health(la_component_health_vec_t& out_component_health) const = 0;
};
}

#endif // __SERDES_DEVICE_HANDLER_H__
