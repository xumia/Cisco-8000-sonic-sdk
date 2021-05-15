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

#ifndef __DEVICE_PORT_HANDLER_H__
#define __DEVICE_PORT_HANDLER_H__

#include "api/system/la_device.h"
#include "api/system/la_mac_port.h"
#include "hld_types_fwd.h"
#include "system/serdes_handler.h"
#include <unordered_map>

namespace silicon_one
{

class la_device_impl;
class mac_pool_port;
class device_port_handler_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    struct mac_port_config_data {
        la_mac_port::port_speed_e serdes_speed;
        size_t serdes_speed_gbps;
        size_t mac_lanes;
        size_t reserved_mac_lanes;
        size_t pcs_lanes_per_mac_lane;
        uint32_t alignment_marker_rx;
        uint32_t alignment_marker_tx;
        serdes_handler::an_capability_code_e an_capability;
        uint32_t an_fec_capability;
    };

    enum class fec_lane_speed_e {
        E_NONE,
        E_25G,
        E_50G,
        E_100G,
    };

    // PMA dwidth in bits
    enum class pma_data_width_e {
        E_20,
        E_32,
        E_40,
        E_64,
        E_80,
        E_128,
    };

    struct serdes_config_data {
        la_mac_port::port_speed_e serdes_speed;
        pma_data_width_e dwidth;
        uint32_t dwidth_code; // Code to be configure in the specific ASIC
        fec_lane_speed_e fec_lane_speed;
        uint32_t fec_lane_speed_code;
        bool pam4_enable;
    };

    struct fabric_data {
        uint64_t num_serdes_per_fabric_port;
        la_mac_port::port_speed_e speed;
    } m_fabric_data;

    device_port_handler_base(const la_device_impl_wptr& device);
    virtual ~device_port_handler_base();

    bool is_valid_config(la_mac_port::port_speed_e speed, size_t serdes_count, la_mac_port::fec_mode_e fec_mode);

    // This function is responsible for the bulk of the configuration job.
    // Should be called after la_devices properties were filled, and eFuse have been read, but before any port operation.
    virtual void initialize() = 0;

    // Return a MAC port config data.
    la_status get_mac_port_config(la_mac_port::port_speed_e speed,
                                  size_t serdes_count,
                                  la_mac_port::fec_mode_e fec_mode,
                                  mac_port_config_data& out_config);
    // Return a SerDes config data.
    la_status get_serdes_config(la_mac_port::port_speed_e speed, serdes_config_data& out_config);

    // Return a list of valid configurations.
    la_status get_valid_configs(la_mac_port::mac_config_vec& out_config_vec);

    // Return a list of supported port speed
    virtual const std::vector<la_mac_port::port_speed_e> get_supported_speeds() = 0;

    virtual la_status set_fabric_mode(la_device::fabric_mac_ports_mode_e fabric_mac_ports_mode) = 0;

    la_status get_fabric_data(fabric_data& out_data) const;

    virtual bool is_mlp(size_t serdes_count) const;

    virtual size_t get_mac_pool_id(size_t serdes_base_id) const;

    virtual size_t get_serdes_id_in_mac_pool(size_t serdes_base_id) const;

    virtual la_status create_mac_pool(size_t serdes_base_id, mac_pool_port_sptr& mac_pool_port) = 0;

protected:
    device_port_handler_base() = default; // for cereal
    struct mac_port_config_key {
        la_mac_port::port_speed_e speed;
        size_t serdes_count;
        la_mac_port::fec_mode_e fec_mode;

        bool operator==(const mac_port_config_key& other) const
        {
            return (speed == other.speed && serdes_count == other.serdes_count && fec_mode == other.fec_mode);
        }
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(mac_port_config_key);

    struct mac_port_config_key_hasher {
        std::size_t operator()(const mac_port_config_key& k) const
        {
            return (std::hash<size_t>()((size_t)k.speed | (k.serdes_count << 8) | ((size_t)k.fec_mode << 16)));
        }
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(mac_port_config_key_hasher);

    struct serdes_config_key {
        la_mac_port::port_speed_e speed;

        bool operator==(const serdes_config_key& other) const
        {
            return (speed == other.speed);
        }
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(serdes_config_key);

    struct serdes_config_key_hasher {
        std::size_t operator()(const serdes_config_key& k) const
        {
            return (std::hash<size_t>()((size_t)k.speed));
        }
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(serdes_config_key_hasher);

public:
    typedef std::unordered_map<mac_port_config_key, mac_port_config_data, mac_port_config_key_hasher> valid_configurations_t;
    typedef std::unordered_map<serdes_config_key, serdes_config_data, serdes_config_key_hasher> serdes_configurations_t;

protected:
    valid_configurations_t m_valid_configurations;
    serdes_configurations_t m_serdes_configurations;
    la_device_impl_wptr m_device;
};
}

#endif // __DEVICE_PORT_HANDLER_H__
